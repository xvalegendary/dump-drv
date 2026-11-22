#include "application.hxx"

#include "crypto.hxx"
#include "driver_client.hxx"
#include "manifest_writer.hxx"
#include "mapper.hxx"
#include "minidump_writer.hxx"
#include "net_capture.hxx"
#include "process_locator.hxx"
#include "section_dumper.hxx"
#include "symbol_resolver.hxx"
#include "generated/driver_blob.hxx"

#define NOMINMAX
#include <Windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <vector>

namespace {

using namespace dump;

struct RemoteModule {
    std::uint64_t base{};
    std::uint32_t size{};
    std::wstring name;
};

std::wstring status_text(const Status status) {
    switch (status) {
    case Status::success: return L"success";
    case Status::invalid_argument: return L"invalid argument";
    case Status::access_denied: return L"access denied";
    case Status::process_not_found: return L"process not found";
    case Status::mapper_failure: return L"mapper failure";
    case Status::driver_failure: return L"driver failure";
    case Status::validation_failure: return L"validation failure";
    case Status::invalid_symbol_packet: return L"symbol resolution failure";
    case Status::io_error: return L"I/O failure";
    case Status::partial_copy: return L"partial copy";
    default: return L"status " + std::to_wstring(static_cast<unsigned int>(status));
    }
}

bool elevated() {
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID administrators{};
    if (!AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administrators)) {
        return false;
    }
    BOOL member{};
    const auto result = CheckTokenMembership(nullptr, administrators, &member);
    FreeSid(administrators);
    return result && member;
}

bool enable_debug_privilege() {
    HANDLE token{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return false;
    LUID identifier{};
    if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &identifier)) {
        CloseHandle(token);
        return false;
    }
    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = identifier;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    const auto adjusted = AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
    const auto error = GetLastError();
    CloseHandle(token);
    return adjusted && error == ERROR_SUCCESS;
}

template <std::size_t Size>
bool copy_name(protocol::FixedArray<wchar_t, Size>& destination, const std::wstring_view source) {
    if (source.empty() || source.size() >= Size) {
        return false;
    }
    std::copy(source.begin(), source.end(), destination.begin());
    destination[source.size()] = L'\0';
    return true;
}

std::wstring suffix(const protocol::Nonce& nonce) {
    std::wostringstream value;
    value << std::hex << std::setfill(L'0');
    for (std::size_t index = 0; index < 8; ++index) {
        value << std::setw(2) << static_cast<unsigned int>(nonce[index]);
    }
    return value.str();
}

Result<std::pair<protocol::BootConfiguration, std::wstring>> boot_configuration() {
    protocol::BootConfiguration configuration{};
    configuration.header.magic = protocol::magic;
    configuration.header.version = protocol::version;
    configuration.header.size = sizeof(configuration);
    configuration.header.nonce = crypto::random_nonce();
    bool all_zero = true;
    for (const auto value : configuration.header.nonce) all_zero = all_zero && value == 0;
    if (all_zero) {
        return Status::io_error;
    }
    const auto token = suffix(configuration.header.nonce);
    const auto driver = L"\\Driver\\Dmp_" + token;
    const auto device = L"\\Device\\Dmp_" + token;
    const auto link = L"\\DosDevices\\Dmp_" + token;
    if (!copy_name(configuration.driver_name, driver) || !copy_name(configuration.device_name, device) || !copy_name(configuration.symbolic_link, link)) {
        return Status::invalid_argument;
    }
    return std::pair{configuration, L"\\\\.\\Dmp_" + token};
}

bool read_exact(DriverClient& client, const std::uint64_t address, const std::span<std::byte> output) {
    std::size_t done{};
    while (done < output.size()) {
        const auto requested = static_cast<std::uint32_t>((std::min)(output.size() - done, static_cast<std::size_t>(protocol::maximum_transfer)));
        auto chunk = client.read_memory(address + done, requested);
        if (!chunk || chunk.value().bytes.empty()) {
            return false;
        }
        std::memcpy(output.data() + done, chunk.value().bytes.data(), chunk.value().bytes.size());
        done += chunk.value().bytes.size();
        if (chunk.value().bytes.size() != requested) {
            return false;
        }
    }
    return true;
}

template <typename T>
bool read_value(DriverClient& client, const std::uint64_t address, T& value) {
    return read_exact(client, address, std::span(reinterpret_cast<std::byte*>(&value), sizeof(value)));
}

std::vector<RemoteModule> remote_modules(DriverClient& client, const protocol::AttachResponse& attached, const std::wstring_view process_name) {
    std::map<std::uint64_t, RemoteModule> modules;
    if (attached.image_base != 0) {
        modules.emplace(attached.image_base, RemoteModule{attached.image_base, 1, std::wstring(process_name)});
    }
    std::uint64_t loader{};
    if (attached.peb == 0 || !read_value(client, attached.peb + 0x18, loader) || loader == 0) {
        std::vector<RemoteModule> result;
        for (auto& [base, module] : modules) result.push_back(std::move(module));
        return result;
    }
    const auto head = loader + 0x10;
    std::uint64_t current{};
    if (!read_value(client, head, current)) {
        return {};
    }
    std::set<std::uint64_t> visited;
    for (std::size_t count = 0; count < 4096 && current != 0 && current != head && visited.insert(current).second; ++count) {
        std::array<std::byte, 0x60> entry{};
        if (!read_exact(client, current, entry)) {
            break;
        }
        std::uint64_t next{};
        std::uint64_t base{};
        std::uint32_t size{};
        std::uint16_t name_length{};
        std::uint64_t name_buffer{};
        std::memcpy(&next, entry.data(), sizeof(next));
        std::memcpy(&base, entry.data() + 0x30, sizeof(base));
        std::memcpy(&size, entry.data() + 0x40, sizeof(size));
        std::memcpy(&name_length, entry.data() + 0x48, sizeof(name_length));
        std::memcpy(&name_buffer, entry.data() + 0x50, sizeof(name_buffer));
        std::wstring name;
        if (name_length != 0 && name_length <= 32768 && (name_length % sizeof(wchar_t)) == 0 && name_buffer != 0) {
            name.resize(name_length / sizeof(wchar_t));
            if (!read_exact(client, name_buffer, std::span(reinterpret_cast<std::byte*>(name.data()), name_length))) {
                name.clear();
            }
        }
        if (base != 0 && size != 0) {
            if (name.empty()) name = L"module-" + std::to_wstring(base) + L".dll";
            modules[base] = RemoteModule{base, size, std::move(name)};
        }
        current = next;
    }
    std::vector<RemoteModule> result;
    for (auto& [base, module] : modules) result.push_back(std::move(module));
    return result;
}

ModuleRecord module_record(DriverClient& client, const RemoteModule& module) {
    ModuleRecord result{};
    result.base = module.base;
    result.size = module.size;
    result.name = module.name;
    IMAGE_DOS_HEADER dos{};
    if (!read_value(client, module.base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 || dos.e_lfanew > 0x100000) {
        return result;
    }
    IMAGE_NT_HEADERS64 nt{};
    if (!read_value(client, module.base + static_cast<std::uint32_t>(dos.e_lfanew), nt) || nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return result;
    }
    result.size = nt.OptionalHeader.SizeOfImage;
    result.checksum = nt.OptionalHeader.CheckSum;
    result.timestamp = nt.FileHeader.TimeDateStamp;
    return result;
}

SnapshotMetadata system_metadata(const std::uint32_t process_id) {
    SnapshotMetadata metadata{};
    metadata.process_id = process_id;
    SYSTEM_INFO system{};
    GetNativeSystemInfo(&system);
    metadata.processor_architecture = system.wProcessorArchitecture;
    metadata.processors = static_cast<std::uint8_t>((std::min)(system.dwNumberOfProcessors, 255ul));
    using RtlGetVersionFunction = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto version = module ? reinterpret_cast<RtlGetVersionFunction>(GetProcAddress(module, "RtlGetVersion")) : nullptr;
    RTL_OSVERSIONINFOW information{};
    information.dwOSVersionInfoSize = sizeof(information);
    if (version && version(&information) == 0) {
        metadata.major_version = information.dwMajorVersion;
        metadata.minor_version = information.dwMinorVersion;
        metadata.build_number = information.dwBuildNumber;
    }
    metadata.platform_id = VER_PLATFORM_WIN32_NT;
    metadata.comment = L"kernel snapshot";
    return metadata;
}

bool readable(const protocol::RegionDescriptor& region) {
    constexpr std::uint32_t page_noaccess = 0x01;
    constexpr std::uint32_t page_guard = 0x100;
    return region.state == protocol::RegionState::committed && (region.protect & (page_noaccess | page_guard)) == 0 && region.protect != 0;
}

std::wstring hex_value(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << value;
    return stream.str();
}

template <typename Bytes>
std::wstring hex_bytes(const Bytes& bytes) {
    std::wostringstream stream;
    stream << std::hex << std::setfill(L'0');
    for (const auto value : bytes) stream << std::setw(2) << static_cast<unsigned int>(value);
    return stream.str();
}

std::wstring section_text(const protocol::SectionDescriptor& section) {
    std::wstring name;
    for (std::size_t index = 0; index < protocol::section_name_size; ++index) {
        if (section.name[index] == '\0') break;
        name.push_back(static_cast<wchar_t>(static_cast<unsigned char>(section.name[index])));
    }
    return name.empty() ? L"unnamed" : name;
}

}

namespace dump {

Application::Application(IConsole& console) noexcept : console_(console) {}

int Application::run(const std::span<const std::wstring_view> arguments) noexcept {
    auto options = parse_options(arguments);
    if (!options) {
        console_.error(L"usage: Dumper.exe [--sections | --dmp | --sectionsanddump] [--net [--net-seconds N]] [--output path] [--keep-partial] [--no-conceal] [--module name.sys] process.exe | --pid PID");
        return 2;
    }
    if (!elevated()) {
        console_.error(L"administrator token required");
        return 3;
    }
    if (!enable_debug_privilege()) console_.progress(L"SeDebugPrivilege unavailable; continuing without kernel diagnostics");
    auto process = ProcessLocator::find(options.value().process_id, options.value().process_name);
    if (!process) {
        console_.error(status_text(process.status()));
        return 4;
    }
    if (process.value().match_count > 1) console_.progress(L"multiple process matches; selected pid=" + std::to_wstring(process.value().process_id));
    auto boot = boot_configuration();
    if (!boot) {
        console_.error(status_text(boot.status()));
        return 5;
    }
    DbgHelpSymbolProvider provider(std::filesystem::current_path() / L"symbols");
    SymbolResolver resolver(provider);
    auto symbols = resolver.resolve();
    if (!symbols) console_.progress(L"kernel symbols unavailable; continuing snapshot without offsets");
    Result<protocol::ConcealTargets> conceal_targets(Status::invalid_state);
    if (options.value().conceal) {
        conceal_targets = resolver.resolve_conceal(options.value().module_name);
        if (!conceal_targets) console_.progress(L"trace cleanup unavailable: " + status_text(conceal_targets.status()));
    }
    const bool capture_only = options.value().net && !options.value().explicit_mode;
    const bool want_sections = options.value().mode != Mode::dump && !capture_only;
    const bool want_dump = options.value().mode != Mode::sections && !capture_only;
    const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm local{};
    localtime_s(&local, &now);
    const auto stem = make_output_stem(process.value().name, local);
    const auto dump_path = options.value().output_directory / (stem + L".dmp");
    const auto manifest_path = options.value().output_directory / (stem + L".txt");
    const auto net_path = options.value().output_directory / (stem + L".net.txt");
    MiniDumpWriter writer;
    ManifestWriter manifest;
    bool writer_started{};
    bool manifest_started{};
    bool dump_finalized{};
    KdmapperBackend backend;
    MapperSession mapper(backend);
    bool mapped{};
    bool bound{};
    DriverClient client(boot.value().second, boot.value().first.header.nonce);
    const auto cleanup = [&]() {
        Status status = Status::success;
        if (bound) {
            status = mapper.shutdown(client);
            bound = false;
            mapped = false;
        } else if (mapped) {
            client.close();
            status = mapper.abort();
            mapped = false;
        }
        return status;
    };
    const auto fail = [&](const Status status, const int code) {
        console_.error(status_text(status));
        if (manifest_started) manifest.error(status_text(status));
        if (writer_started && !dump_finalized) writer.discard(options.value().keep_partial);
        if (manifest_started) manifest.discard(options.value().keep_partial);
        const auto cleanup_status = cleanup();
        if (cleanup_status != Status::success) console_.error(L"cleanup: " + status_text(cleanup_status));
        return code;
    };
    auto status = mapper.open();
    if (status != Status::success) return fail(status, 7);
    const auto image = std::span(reinterpret_cast<const std::byte*>(embedded::driver_blob), embedded::driver_blob_size);
    status = mapper.map_embedded_driver(image, boot.value().first);
    if (status != Status::success) return fail(status, 8);
    mapped = true;
    console_.success(L"driver loaded");
    status = mapper.bind(client);
    if (status != Status::success) return fail(status, 9);
    bound = true;
    auto attached = client.attach(process.value().process_id);
    if (!attached) return fail(attached.status(), 10);
    bool symbols_applied{};
    if (symbols) {
        status = client.set_symbols(symbols.value());
        symbols_applied = status == Status::success;
        if (!symbols_applied) console_.progress(L"kernel offsets rejected; continuing snapshot without offsets");
    }
    console_.success(L"attached to " + process.value().name);
    console_.success(L"pid=" + std::to_wstring(process.value().process_id) + L" eprocess=" + hex_value(attached.value().eprocess) + L" peb=" + hex_value(attached.value().peb) + L" image_base=" + hex_value(attached.value().image_base));
    status = manifest.begin(manifest_path);
    if (status != Status::success) return fail(status, 13);
    manifest_started = true;
    manifest.success(L"attached to " + process.value().name);
    manifest.success(L"pid=" + std::to_wstring(process.value().process_id));
    manifest.success(L"eprocess=" + hex_value(attached.value().eprocess) + L" peb=" + hex_value(attached.value().peb) + L" image_base=" + hex_value(attached.value().image_base));
    if (symbols_applied) {
        const auto& packet = symbols.value();
        manifest.success(L"kernel_timestamp=" + hex_value(packet.kernel_timestamp) + L" kernel_image_size=" + hex_value(packet.kernel_image_size) + L" pdb_guid=" + hex_bytes(packet.pdb_guid) + L" pdb_age=" + std::to_wstring(packet.pdb_age));
        manifest.success(L"offset UniqueProcessId=" + hex_value(packet.unique_process_id) + L" ActiveProcessLinks=" + hex_value(packet.active_process_links) + L" ImageFileName=" + hex_value(packet.image_file_name) + L" VadRoot=" + (packet.vad_root == protocol::unavailable_offset ? L"unavailable" : hex_value(packet.vad_root)) + L" DirectoryTableBase=" + hex_value(packet.directory_table_base));
        console_.success(L"validated dynamic kernel offsets");
    } else {
        manifest.progress(L"kernel offsets=unavailable path=kernel_api");
    }
    const auto metadata = system_metadata(process.value().process_id);
    manifest.success(L"os=" + std::to_wstring(metadata.major_version) + L"." + std::to_wstring(metadata.minor_version) + L" build=" + std::to_wstring(metadata.build_number));
    NetCaptureStats capture{};
    if (options.value().net) {
        NetworkCapture network(client, console_);
        auto captured = network.run(process.value().process_id, options.value().net_seconds, net_path);
        if (!captured) {
            const auto text = L"capture: " + status_text(captured.status());
            console_.error(text);
            manifest.error(text);
        } else {
            capture = captured.value();
            manifest.success(L"capture requests=" + std::to_wstring(capture.requests) + L" connections=" + std::to_wstring(capture.connections) + L" sweeps=" + std::to_wstring(capture.sweeps) + L" failures=" + std::to_wstring(capture.failures) + L" log=" + net_path.wstring());
        }
    }
    SectionDumpResult sections{};
    if (want_sections) {
        auto table = client.query_sections();
        if (!table) return fail(table.status(), 23);
        SectionDumper dumper(client);
        auto written = dumper.write(options.value().output_directory, stem, table.value());
        if (!written) return fail(written.status(), 24);
        sections = written.value();
        manifest.success(L"section image_base=" + hex_value(table.value().image_base) + L" image_size=" + hex_value(table.value().image_size) + L" headers=" + hex_value(table.value().headers_size) + L" files=" + std::to_wstring(sections.files) + L" bytes=" + std::to_wstring(sections.bytes) + L" failed=" + std::to_wstring(sections.failed));
        for (std::size_t index = 0; index < table.value().section_count; ++index) {
            const auto& section = table.value().sections[index];
            manifest.progress(L"section=" + std::to_wstring(index) + L" name=" + section_text(section) + L" rva=" + hex_value(section.virtual_address) + L" span=" + hex_value(section_extent(section, table.value().image_size)) + L" characteristics=" + hex_value(section.characteristics));
        }
        console_.success(L"sections=" + std::to_wstring(table.value().section_count) + L" files=" + std::to_wstring(sections.files) + L" bytes=" + std::to_wstring(sections.bytes));
    }
    std::size_t region_index{};
    std::uint64_t copied_total{};
    if (want_dump) {
        status = writer.begin(dump_path);
        if (status != Status::success) return fail(status, 12);
        writer_started = true;
        status = writer.add_system_info(metadata);
        if (status != Status::success) return fail(status, 14);
        auto modules = remote_modules(client, attached.value(), process.value().name);
        std::set<std::uint64_t> image_bases;
        std::uint64_t address{};
        constexpr std::uint64_t highest = 0x00007fffffffffff;
        while (address <= highest) {
            auto queried = client.query_region(address);
            if (!queried) {
                if (region_index == 0) return fail(queried.status(), 15);
                break;
            }
            const auto region = queried.value().region;
            if (region.size == 0 || region.base < address || region.base > highest || region.size - 1 > highest - region.base) {
                return fail(Status::validation_failure, 16);
            }
            status = writer.add_memory_region(MemoryRecord{region, 0});
            if (status != Status::success) return fail(status, 17);
            if (region.type == protocol::RegionType::image && region.allocation_base != 0) image_bases.insert(region.allocation_base);
            std::uint64_t copied{};
            std::int32_t native_status = queried.value().native_status;
            if (readable(region)) {
                while (copied < region.size) {
                    const auto requested = static_cast<std::uint32_t>((std::min)(region.size - copied, protocol::maximum_transfer));
                    auto chunk = client.read_memory(region.base + copied, requested);
                    if (!chunk) {
                        native_status = static_cast<std::int32_t>(chunk.status());
                        break;
                    }
                    native_status = chunk.value().native_status;
                    if (chunk.value().bytes.empty()) break;
                    status = writer.append_memory(region.base + copied, chunk.value().bytes);
                    if (status != Status::success) return fail(status, 18);
                    copied += chunk.value().bytes.size();
                    copied_total += chunk.value().bytes.size();
                    if (chunk.value().bytes.size() != requested) break;
                }
            }
            manifest.region(region_index, region, copied, native_status);
            console_.progress(L"region " + std::to_wstring(region_index) + L" base=" + hex_value(region.base) + L" copied=" + hex_value(copied));
            ++region_index;
            const auto next = region.base + region.size;
            if (next == 0 || next > highest) break;
            address = next;
        }
        for (const auto& module : modules) {
            if (image_bases.contains(module.base) || module.base == attached.value().image_base) {
                status = writer.add_module(module_record(client, module));
                if (status != Status::success) return fail(status, 19);
            }
        }
        status = writer.finalize();
        if (status != Status::success) return fail(status, 20);
        dump_finalized = true;
        manifest.success(L"regions=" + std::to_wstring(region_index) + L" copied=" + std::to_wstring(copied_total));
    }
    if (conceal_targets) {
        auto concealed = client.conceal(conceal_targets.value());
        if (!concealed) {
            const auto text = L"trace cleanup: " + status_text(concealed.status());
            console_.error(text);
            manifest.error(text);
        } else {
            const auto& response = concealed.value();
            const auto text = L"trace applied=" + hex_value(response.applied) + L" module_list=" + std::to_wstring(response.module_list_hidden) + L" unloaded=" + std::to_wstring(response.unloaded_hidden) + L" piddb=" + std::to_wstring(response.piddb_hidden) + L" hash_bucket=" + std::to_wstring(response.hash_bucket_hidden) + L" headers=" + std::to_wstring(response.headers_erased) + L" hits=" + std::to_wstring(response.name_hits);
            console_.success(text);
            manifest.success(text);
        }
    }
    status = want_dump ? manifest.finalize(dump_path) : manifest.finalize();
    if (status != Status::success) return fail(status, 21);
    manifest_started = false;
    status = cleanup();
    if (status != Status::success) {
        console_.error(L"cleanup: " + status_text(status));
        return 22;
    }
    if (want_dump) console_.success(L"dump=" + dump_path.wstring());
    console_.success(L"manifest=" + manifest_path.wstring());
    if (want_sections) console_.success(L"sections=" + std::to_wstring(sections.files) + L" files in " + options.value().output_directory.wstring());
    if (options.value().net) console_.success(L"capture log=" + net_path.wstring() + L" requests=" + std::to_wstring(capture.requests) + L" connections=" + std::to_wstring(capture.connections));
    return 0;
}

}