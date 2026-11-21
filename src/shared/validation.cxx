#ifdef _KERNEL_MODE
#include <ntifs.h>
#endif

#include "validation.hxx"

#include "pe.hxx"

namespace {

constexpr dump::protocol::u64 kernel_half_begin = 0xffff800000000000ull;

bool aligned(const dump::protocol::u64 value, const dump::protocol::u64 alignment) noexcept {
    return (value & (alignment - 1)) == 0;
}

bool name_character(const dump::protocol::wide_char value) noexcept {
    if ((value >= L'a' && value <= L'z') || (value >= L'A' && value <= L'Z') || (value >= L'0' && value <= L'9')) {
        return true;
    }
    return value == L'.' || value == L'_' || value == L'-' || value == L'$';
}

}

namespace dump::validation {

Status validate_header(const protocol::Header& header, const protocol::Nonce& expected_nonce, const protocol::usize actual_size) noexcept {
    if (header.magic != protocol::magic) {
        return Status::invalid_magic;
    }
    if (header.version != protocol::version) {
        return Status::version_mismatch;
    }
    if (header.size != actual_size) {
        return Status::size_mismatch;
    }
    for (protocol::usize index = 0; index < header.nonce.size(); ++index) {
        if (header.nonce[index] != expected_nonce[index]) {
            return Status::nonce_mismatch;
        }
    }
    return Status::success;
}

Status validate_range(const protocol::u64 base, const protocol::u64 size) noexcept {
    if (size == 0) {
        return Status::invalid_argument;
    }
    if (base > ~protocol::u64{0} - size) {
        return Status::range_overflow;
    }
    constexpr protocol::u64 highest_user_address = 0x00007fffffffffff;
    if (base > highest_user_address || base + size - 1 > highest_user_address) {
        return Status::noncanonical_address;
    }
    return Status::success;
}

Status validate_symbol_packet(const protocol::SymbolPacket& packet, const protocol::KernelIdentity& running) noexcept {
    if (packet.kernel_timestamp != running.timestamp || packet.kernel_image_size != running.image_size || packet.pdb_guid != running.pdb_guid || packet.pdb_age != running.pdb_age) {
        return Status::kernel_identity_mismatch;
    }
    if (packet.eprocess_size == 0 || packet.eprocess_size > 0x4000) {
        return Status::invalid_symbol_packet;
    }
    const protocol::u32 offsets[] = {packet.unique_process_id, packet.active_process_links, packet.image_file_name, packet.vad_root};
    for (const auto offset : offsets) {
        if (offset != protocol::unavailable_offset && offset >= packet.eprocess_size) {
            return Status::invalid_symbol_packet;
        }
    }
    if (packet.directory_table_base != protocol::unavailable_offset && packet.directory_table_base >= 0x1000) {
        return Status::invalid_symbol_packet;
    }
    return Status::success;
}

Status validate_sequence(const protocol::u64 incoming, const protocol::u64 last_accepted) noexcept {
    return incoming > last_accepted ? Status::success : Status::sequence_replay;
}

Status validate_kernel_pointer(const protocol::u64 address) noexcept {
    return address >= kernel_half_begin ? Status::success : Status::noncanonical_address;
}

Status validate_kernel_range(const protocol::u64 address, const protocol::u64 size) noexcept {
    if (size == 0 || size > 0x10000) {
        return Status::invalid_argument;
    }
    if (validate_kernel_pointer(address) != Status::success) {
        return Status::noncanonical_address;
    }
    if (address > ~protocol::u64{0} - size) {
        return Status::range_overflow;
    }
    return Status::success;
}

Status validate_unicode_name(const protocol::u32 length, const protocol::u32 maximum_length) noexcept {
    constexpr protocol::u32 unit = sizeof(protocol::wide_char);
    if (length < unit || (length % unit) != 0 || length > 0x200) {
        return Status::invalid_argument;
    }
    if (maximum_length < length || maximum_length > 0x400 || (maximum_length % unit) != 0) {
        return Status::invalid_argument;
    }
    return Status::success;
}

Status validate_list_links(const protocol::u64 entry, const protocol::u64 forward, const protocol::u64 backward) noexcept {
    if (!aligned(entry, 8) || !aligned(forward, 8) || !aligned(backward, 8)) {
        return Status::invalid_argument;
    }
    if (validate_kernel_pointer(entry) != Status::success || validate_kernel_pointer(forward) != Status::success || validate_kernel_pointer(backward) != Status::success) {
        return Status::noncanonical_address;
    }
    return Status::success;
}

Status validate_conceal_targets(const protocol::ConcealTargets& targets, const protocol::KernelIdentity& nt, const protocol::KernelIdentity& ci) noexcept {
    if (targets.flags == 0 || (targets.flags & ~protocol::conceal_all) != 0) {
        return Status::invalid_argument;
    }
    if (targets.nt_timestamp == 0 || targets.nt_timestamp != nt.timestamp || targets.nt_image_size == 0 || targets.nt_image_size != nt.image_size) {
        return Status::kernel_identity_mismatch;
    }
    if ((targets.flags & protocol::conceal_module_list) != 0) {
        const auto rva = targets.ps_loaded_module_list_rva;
        if (rva == protocol::unavailable_offset || rva < 0x1000 || rva >= targets.nt_image_size || !aligned(rva, 8)) {
            return Status::invalid_symbol_packet;
        }
    }
    if ((targets.flags & protocol::conceal_hash_bucket) != 0) {
        if (targets.ci_timestamp == 0 || targets.ci_timestamp != ci.timestamp || targets.ci_image_size == 0 || targets.ci_image_size != ci.image_size) {
            return Status::kernel_identity_mismatch;
        }
    }
    protocol::u32 length{};
    while (length < protocol::maximum_module_name && targets.module_name[length] != 0) {
        if (!name_character(targets.module_name[length])) {
            return Status::invalid_argument;
        }
        ++length;
    }
    if (length < 5 || length >= protocol::maximum_module_name) {
        return Status::invalid_argument;
    }
    for (protocol::u32 index = length; index < protocol::maximum_module_name; ++index) {
        if (targets.module_name[index] != 0) {
            return Status::invalid_argument;
        }
    }
    return Status::success;
}

Status validate_sections(const protocol::SectionsResponse& response) noexcept {
    if (response.image_base == 0 || response.image_size < 0x1000 || response.image_size > pe::maximum_image_size) {
        return Status::invalid_argument;
    }
    if (response.section_count == 0 || response.section_count > protocol::maximum_sections) {
        return Status::invalid_argument;
    }
    if (response.headers_size == 0 || response.headers_size > response.image_size) {
        return Status::invalid_argument;
    }
    const protocol::u64 image_size = response.image_size;
    protocol::u64 previous{};
    for (protocol::u32 index = 0; index < response.section_count; ++index) {
        const auto& section = response.sections[index];
        if (section.virtual_address < previous || section.virtual_address >= image_size) {
            return Status::invalid_argument;
        }
        previous = section.virtual_address;
        const protocol::u64 span = section.virtual_size > section.raw_size ? section.virtual_size : section.raw_size;
        if (span > image_size - section.virtual_address) {
            return Status::invalid_argument;
        }
        bool terminated{};
        for (protocol::u32 position = 0; position < protocol::section_name_size; ++position) {
            if (section.name[position] == '\0') {
                terminated = true;
                break;
            }
        }
        if (!terminated) {
            return Status::invalid_argument;
        }
    }
    return Status::success;
}

}