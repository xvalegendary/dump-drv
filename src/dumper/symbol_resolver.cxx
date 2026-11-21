#define NOMINMAX
#include "symbol_resolver.hxx"

#include "crypto.hxx"
#include "image_exports.hxx"
#include "shared/validation.hxx"

#include <Windows.h>
#include <DbgHelp.h>
#include <Psapi.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace {

struct CodeViewRecord {
    DWORD signature{};
    GUID guid{};
    DWORD age{};
};

std::filesystem::path normalize_kernel_path(std::wstring path) {
    if (path.rfind(L"\\SystemRoot\\", 0) == 0) {
        std::array<wchar_t, MAX_PATH> windows{};
        const auto length = GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
        if (length != 0 && length < windows.size()) {
            path = std::wstring(windows.data(), length) + path.substr(11);
        }
    } else if (path.rfind(L"\\??\\", 0) == 0) {
        path.erase(0, 4);
    }
    return path;
}

dump::Result<dump::KernelSymbolIdentity> read_kernel_identity() {
    std::array<LPVOID, 1024> drivers{};
    DWORD needed{};
    if (!EnumDeviceDrivers(drivers.data(), static_cast<DWORD>(drivers.size() * sizeof(LPVOID)), &needed) || needed < sizeof(LPVOID)) {
        return dump::Status::io_error;
    }
    std::array<wchar_t, 4096> path_buffer{};
    if (GetDeviceDriverFileNameW(drivers[0], path_buffer.data(), static_cast<DWORD>(path_buffer.size())) == 0) {
        return dump::Status::io_error;
    }
    dump::KernelSymbolIdentity result{};
    result.kernel_base = reinterpret_cast<std::uint64_t>(drivers[0]);
    result.image_path = normalize_kernel_path(path_buffer.data());
    std::ifstream image(result.image_path, std::ios::binary);
    if (!image) {
        return dump::Status::io_error;
    }
    IMAGE_DOS_HEADER dos{};
    image.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (!image || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return dump::Status::validation_failure;
    }
    image.seekg(dos.e_lfanew);
    IMAGE_NT_HEADERS64 nt{};
    image.read(reinterpret_cast<char*>(&nt), sizeof(nt));
    if (!image || nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return dump::Status::validation_failure;
    }
    result.identity.timestamp = nt.FileHeader.TimeDateStamp;
    result.identity.image_size = nt.OptionalHeader.SizeOfImage;
    std::vector<IMAGE_SECTION_HEADER> sections(nt.FileHeader.NumberOfSections);
    image.read(reinterpret_cast<char*>(sections.data()), static_cast<std::streamsize>(sections.size() * sizeof(IMAGE_SECTION_HEADER)));
    const auto rva_to_offset = [&](const DWORD rva) -> DWORD {
        if (rva < nt.OptionalHeader.SizeOfHeaders) {
            return rva;
        }
        for (const auto& section : sections) {
            const auto span = (std::max)(section.Misc.VirtualSize, section.SizeOfRawData);
            if (rva >= section.VirtualAddress && rva < section.VirtualAddress + span) {
                return section.PointerToRawData + rva - section.VirtualAddress;
            }
        }
        return 0;
    };
    const auto& debug_directory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    const auto debug_offset = rva_to_offset(debug_directory.VirtualAddress);
    if (debug_offset == 0 || debug_directory.Size < sizeof(IMAGE_DEBUG_DIRECTORY)) {
        return dump::Status::validation_failure;
    }
    image.seekg(debug_offset);
    const auto count = debug_directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    for (DWORD index = 0; index < count; ++index) {
        IMAGE_DEBUG_DIRECTORY entry{};
        image.read(reinterpret_cast<char*>(&entry), sizeof(entry));
        const auto next = image.tellg();
        if (entry.Type == IMAGE_DEBUG_TYPE_CODEVIEW && entry.SizeOfData >= sizeof(CodeViewRecord)) {
            image.seekg(entry.PointerToRawData);
            CodeViewRecord record{};
            image.read(reinterpret_cast<char*>(&record), sizeof(record));
            if (record.signature == 0x53445352) {
                std::memcpy(result.identity.pdb_guid.data(), &record.guid, result.identity.pdb_guid.size());
                result.identity.pdb_age = record.age;
                return result;
            }
        }
        image.seekg(next);
    }
    return dump::Status::validation_failure;
}

}

namespace dump {

DbgHelpSymbolProvider::DbgHelpSymbolProvider(std::filesystem::path cache) : cache_(std::move(cache)) {}

DbgHelpSymbolProvider::~DbgHelpSymbolProvider() {
    if (initialized_) {
        SymCleanup(GetCurrentProcess());
    }
}

Status DbgHelpSymbolProvider::initialize() noexcept {
    if (initialized_) {
        return Status::success;
    }
    if (attempted_) {
        return Status::io_error;
    }
    attempted_ = true;
    try {
        const auto live_identity = read_kernel_identity();
        if (!live_identity) {
            return live_identity.status();
        }
        identity_ = live_identity.value();
        std::filesystem::create_directories(cache_);
        const auto search = L"srv*" + cache_.wstring() + L"*https://msdl.microsoft.com/download/symbols";
        SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_AUTO_PUBLICS);
        if (!SymInitializeW(GetCurrentProcess(), search.c_str(), FALSE)) {
            return Status::io_error;
        }
        initialized_ = true;
        symbol_base_ = SymLoadModuleExW(GetCurrentProcess(), nullptr, identity_.image_path.c_str(), nullptr, identity_.kernel_base, identity_.identity.image_size, nullptr, 0);
        if (symbol_base_ == 0) {
            SymCleanup(GetCurrentProcess());
            initialized_ = false;
            return Status::io_error;
        }
        return Status::success;
    } catch (...) {
        return Status::io_error;
    }
}

Result<KernelSymbolIdentity> DbgHelpSymbolProvider::identity() {
    const auto status = initialize();
    if (status != Status::success) {
        return status;
    }
    return identity_;
}

Result<SymbolType> DbgHelpSymbolProvider::type(const std::wstring_view name) {
    const auto status = initialize();
    if (status != Status::success) {
        return status;
    }
    std::vector<std::byte> symbol_storage(sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t));
    auto* symbol = reinterpret_cast<SYMBOL_INFOW*>(symbol_storage.data());
    symbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
    symbol->MaxNameLen = MAX_SYM_NAME;
    const std::wstring owned_name(name);
    if (!SymGetTypeFromNameW(GetCurrentProcess(), symbol_base_, owned_name.c_str(), symbol)) {
        return Status::invalid_symbol_packet;
    }
    ULONG64 type_size{};
    if (!SymGetTypeInfo(GetCurrentProcess(), symbol_base_, symbol->TypeIndex, TI_GET_LENGTH, &type_size)) {
        return Status::io_error;
    }
    ULONG child_count{};
    if (!SymGetTypeInfo(GetCurrentProcess(), symbol_base_, symbol->TypeIndex, TI_GET_CHILDRENCOUNT, &child_count)) {
        return Status::io_error;
    }
    SymbolType result{};
    result.size = type_size;
    if (child_count == 0) {
        return result;
    }
    const auto bytes = sizeof(TI_FINDCHILDREN_PARAMS) + (child_count - 1) * sizeof(ULONG);
    std::vector<std::byte> child_storage(bytes);
    auto* children = reinterpret_cast<TI_FINDCHILDREN_PARAMS*>(child_storage.data());
    children->Count = child_count;
    children->Start = 0;
    if (!SymGetTypeInfo(GetCurrentProcess(), symbol_base_, symbol->TypeIndex, TI_FINDCHILDREN, children)) {
        return Status::io_error;
    }
    for (ULONG index = 0; index < child_count; ++index) {
        const auto child_id = children->ChildId[index];
        PWSTR raw_name{};
        DWORD offset{};
        ULONG type_id{};
        ULONG64 field_size{};
        if (!SymGetTypeInfo(GetCurrentProcess(), symbol_base_, child_id, TI_GET_SYMNAME, &raw_name) || raw_name == nullptr) {
            continue;
        }
        SymGetTypeInfo(GetCurrentProcess(), symbol_base_, child_id, TI_GET_OFFSET, &offset);
        SymGetTypeInfo(GetCurrentProcess(), symbol_base_, child_id, TI_GET_TYPEID, &type_id);
        SymGetTypeInfo(GetCurrentProcess(), symbol_base_, type_id, TI_GET_LENGTH, &field_size);
        PWSTR raw_type{};
        SymGetTypeInfo(GetCurrentProcess(), symbol_base_, type_id, TI_GET_SYMNAME, &raw_type);
        SymbolField field{};
        field.name = raw_name;
        field.offset = offset;
        field.size = field_size;
        if (raw_type) {
            field.type_name = raw_type;
            LocalFree(raw_type);
        }
        LocalFree(raw_name);
        result.fields.push_back(std::move(field));
    }
    return result;
}

SymbolResolver::SymbolResolver(ISymbolProvider& provider) noexcept : provider_(provider) {}

Result<std::uint32_t> SymbolResolver::field_offset(const std::wstring_view root_type, const std::wstring_view path) noexcept {
    std::wstring current_type(root_type);
    std::uint64_t total{};
    std::size_t position{};
    while (position < path.size()) {
        const auto separator = path.find(L'.', position);
        const auto component = path.substr(position, separator == std::wstring_view::npos ? path.size() - position : separator - position);
        const auto type_result = provider_.type(current_type);
        if (!type_result) {
            return type_result.status();
        }
        const auto& type = type_result.value();
        const auto found = std::find_if(type.fields.begin(), type.fields.end(), [&](const auto& field) { return field.name == component; });
        if (found == type.fields.end() || found->offset > type.size || found->size > type.size - found->offset || total > std::numeric_limits<std::uint32_t>::max() - found->offset) {
            return Status::invalid_symbol_packet;
        }
        total += found->offset;
        if (separator == std::wstring_view::npos) {
            return static_cast<std::uint32_t>(total);
        }
        if (found->type_name.empty()) {
            return Status::invalid_symbol_packet;
        }
        current_type = found->type_name;
        position = separator + 1;
    }
    return Status::invalid_symbol_packet;
}

Result<protocol::SymbolPacket> SymbolResolver::resolve() noexcept {
    try {
        const auto identity_result = provider_.identity();
        if (!identity_result) {
            return identity_result.status();
        }
        const auto eprocess_result = provider_.type(L"_EPROCESS");
        if (!eprocess_result || eprocess_result.value().size == 0 || eprocess_result.value().size > 0x4000) {
            return Status::invalid_symbol_packet;
        }
        protocol::SymbolPacket packet{};
        packet.header.magic = protocol::magic;
        packet.header.version = protocol::version;
        packet.header.size = sizeof(packet);
        packet.kernel_timestamp = identity_result.value().identity.timestamp;
        packet.kernel_image_size = identity_result.value().identity.image_size;
        packet.pdb_guid = identity_result.value().identity.pdb_guid;
        packet.pdb_age = identity_result.value().identity.pdb_age;
        packet.eprocess_size = static_cast<std::uint32_t>(eprocess_result.value().size);
        const auto unique = field_offset(L"_EPROCESS", L"UniqueProcessId");
        const auto links = field_offset(L"_EPROCESS", L"ActiveProcessLinks");
        const auto image = field_offset(L"_EPROCESS", L"ImageFileName");
        const auto directory = field_offset(L"_EPROCESS", L"Pcb.DirectoryTableBase");
        if (!unique || !links || !image || !directory) {
            return Status::invalid_symbol_packet;
        }
        packet.unique_process_id = unique.value();
        packet.active_process_links = links.value();
        packet.image_file_name = image.value();
        packet.directory_table_base = directory.value();
        const auto vad = field_offset(L"_EPROCESS", L"VadRoot");
        packet.vad_root = vad ? vad.value() : protocol::unavailable_offset;
        const protocol::KernelIdentity identity{packet.kernel_timestamp, packet.kernel_image_size, packet.pdb_guid, packet.pdb_age, 0};
        if (validation::validate_symbol_packet(packet, identity) != Status::success) {
            return Status::invalid_symbol_packet;
        }
        packet.packet_hash.fill(0);
        packet.packet_hash = crypto::sha256(std::span(reinterpret_cast<const std::byte*>(&packet), sizeof(packet)));
        return packet;
    } catch (...) {
        return Status::io_error;
    }
}

Result<protocol::ConcealTargets> SymbolResolver::resolve_conceal(const std::wstring_view module_name) noexcept {
    try {
        if (module_name.empty() || module_name.size() >= protocol::maximum_module_name) {
            return Status::invalid_argument;
        }
        const auto identity = provider_.identity();
        if (!identity) {
            return identity.status();
        }
        const auto table = read_export_table(identity.value().image_path);
        if (!table) {
            return table.status();
        }
        if (table.value().identity.timestamp != identity.value().identity.timestamp || table.value().identity.image_size != identity.value().identity.image_size) {
            return Status::kernel_identity_mismatch;
        }
        const auto list = find_export(table.value(), "PsLoadedModuleList");
        if (!list) {
            return list.status();
        }
        protocol::ConcealTargets targets{};
        targets.nt_timestamp = identity.value().identity.timestamp;
        targets.nt_image_size = identity.value().identity.image_size;
        targets.ps_loaded_module_list_rva = list.value();
        targets.flags = protocol::conceal_all;
        std::copy(module_name.begin(), module_name.end(), targets.module_name.begin());
        const auto ci = find_loaded_module(L"ci.dll");
        if (ci) {
            targets.ci_timestamp = ci.value().identity.timestamp;
            targets.ci_image_size = ci.value().identity.image_size;
        } else {
            targets.flags &= ~protocol::conceal_hash_bucket;
        }
        const protocol::KernelIdentity system_identity{targets.nt_timestamp, targets.nt_image_size, {}, 0};
        const protocol::KernelIdentity client_identity{targets.ci_timestamp, targets.ci_image_size, {}, 0};
        if (validation::validate_conceal_targets(targets, system_identity, client_identity) != Status::success) {
            return Status::invalid_symbol_packet;
        }
        return targets;
    } catch (...) {
        return Status::io_error;
    }
}

}
