#include "image_exports.hxx"

#include "shared/pe.hxx"

#define NOMINMAX
#include <Windows.h>
#include <Psapi.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <vector>

namespace {

using namespace dump;

std::uint16_t read16(const std::byte* data) noexcept {
    return static_cast<std::uint16_t>(static_cast<unsigned char>(data[0]) | (static_cast<std::uint16_t>(static_cast<unsigned char>(data[1])) << 8));
}

std::uint32_t read32(const std::byte* data) noexcept {
    return static_cast<std::uint32_t>(static_cast<unsigned char>(data[0])) | (static_cast<std::uint32_t>(static_cast<unsigned char>(data[1])) << 8) | (static_cast<std::uint32_t>(static_cast<unsigned char>(data[2])) << 16) | (static_cast<std::uint32_t>(static_cast<unsigned char>(data[3])) << 24);
}

const std::byte* rva_pointer(const std::span<const std::byte> image, const pe::Image& layout, const std::uint32_t rva, const std::size_t required) {
    if (rva < layout.headers_size && required <= image.size() && rva <= image.size() - required) {
        return image.data() + rva;
    }
    for (std::uint32_t index = 0; index < layout.section_count; ++index) {
        const auto& section = layout.sections[index];
        const auto span = section.virtual_size > section.raw_size ? section.virtual_size : section.raw_size;
        if (rva >= section.virtual_address && rva < section.virtual_address + span) {
            const auto offset = static_cast<std::size_t>(section.raw_offset) + (rva - section.virtual_address);
            if (offset <= image.size() && required <= image.size() - offset) {
                return image.data() + offset;
            }
        }
    }
    return nullptr;
}

std::wstring normalize(const std::wstring& path) {
    if (path.rfind(L"\\SystemRoot\\", 0) == 0) {
        std::array<wchar_t, 512> windows{};
        const auto length = GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
        if (length != 0 && length < windows.size()) {
            return std::wstring(windows.data(), length) + path.substr(11);
        }
    }
    if (path.rfind(L"\\??\\", 0) == 0) {
        return path.substr(4);
    }
    return path;
}

std::wstring basename(const std::wstring& path) {
    const auto slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

bool equal_insensitive(const std::wstring_view left, const std::wstring_view right) {
    return left.size() == right.size() && _wcsnicmp(left.data(), right.data(), left.size()) == 0;
}

}

namespace dump {

Result<ExportTable> parse_export_table(const std::span<const std::byte> image) noexcept {
    try {
        pe::Image layout{};
        if (pe::parse(reinterpret_cast<const unsigned char*>(image.data()), image.size(), layout) != Status::success) {
            return Status::validation_failure;
        }
        ExportTable table{};
        table.identity.timestamp = layout.timestamp;
        table.identity.image_size = layout.image_size;
        table.identity.headers_size = layout.headers_size;
        const auto* dos = image.data();
        const auto* nt = dos + read32(dos + 0x3c);
        const auto export_rva = read32(nt + 24 + 112);
        const auto export_size = read32(nt + 24 + 116);
        if (export_rva == 0 || export_size < 40) {
            return table;
        }
        const auto* directory = rva_pointer(image, layout, export_rva, 40);
        if (directory == nullptr) {
            return Status::validation_failure;
        }
        const auto number_of_names = read32(directory + 24);
        const auto address_of_functions = read32(directory + 28);
        const auto address_of_names = read32(directory + 32);
        const auto address_of_ordinals = read32(directory + 36);
        if (number_of_names == 0 || number_of_names > 0x10000) {
            return table;
        }
        const auto* names = rva_pointer(image, layout, address_of_names, static_cast<std::size_t>(number_of_names) * 4);
        const auto* ordinals = rva_pointer(image, layout, address_of_ordinals, static_cast<std::size_t>(number_of_names) * 2);
        if (names == nullptr || ordinals == nullptr) {
            return Status::validation_failure;
        }
        table.entries.reserve(number_of_names);
        for (std::uint32_t index = 0; index < number_of_names; ++index) {
            const auto name_rva = read32(names + static_cast<std::size_t>(index) * 4);
            const auto ordinal = read16(ordinals + static_cast<std::size_t>(index) * 2);
            const auto* raw = rva_pointer(image, layout, name_rva, 1);
            if (raw == nullptr) {
                continue;
            }
            const auto* text = reinterpret_cast<const char*>(raw);
            const auto maximum = static_cast<std::size_t>(image.data() + image.size() - raw);
            const auto length = strnlen_s(text, maximum);
            if (length == 0 || length == maximum) {
                continue;
            }
            const auto* functions = rva_pointer(image, layout, address_of_functions, static_cast<std::size_t>(ordinal) * 4 + 4);
            if (functions == nullptr) {
                continue;
            }
            ExportEntry entry{};
            entry.name.assign(text, length);
            entry.rva = read32(functions + static_cast<std::size_t>(ordinal) * 4);
            table.entries.push_back(std::move(entry));
        }
        return table;
    } catch (...) {
        return Status::io_error;
    }
}

Result<ExportTable> read_export_table(const std::filesystem::path& path) noexcept {
    try {
        std::ifstream input(path, std::ios::binary);
        if (!input) {
            return Status::io_error;
        }
        input.seekg(0, std::ios::end);
        const auto size = input.tellg();
        if (size <= 0 || size > 0x40000000) {
            return Status::io_error;
        }
        std::vector<std::byte> buffer(static_cast<std::size_t>(size));
        input.seekg(0, std::ios::beg);
        input.read(reinterpret_cast<char*>(buffer.data()), size);
        if (!input) {
            return Status::io_error;
        }
        return parse_export_table(buffer);
    } catch (...) {
        return Status::io_error;
    }
}

Result<std::uint32_t> find_export(const ExportTable& table, const std::string_view name) noexcept {
    for (const auto& entry : table.entries) {
        if (entry.name == name) {
            return entry.rva;
        }
    }
    return Status::invalid_symbol_packet;
}

Result<LoadedModule> find_loaded_module(const std::wstring_view name) noexcept {
    try {
        std::vector<LPVOID> drivers(1024);
        DWORD needed{};
        if (!EnumDeviceDrivers(drivers.data(), static_cast<DWORD>(drivers.size() * sizeof(LPVOID)), &needed)) {
            return Status::io_error;
        }
        const auto count = needed / sizeof(LPVOID);
        for (DWORD index = 0; index < count && index < drivers.size(); ++index) {
            std::array<wchar_t, 4096> path{};
            if (GetDeviceDriverFileNameW(drivers[index], path.data(), static_cast<DWORD>(path.size())) == 0) {
                continue;
            }
            const std::wstring candidate = normalize(path.data());
            if (!equal_insensitive(basename(candidate), name)) {
                continue;
            }
            auto table = read_export_table(candidate);
            if (!table) {
                return table.status();
            }
            LoadedModule module{};
            module.path = candidate;
            module.base = reinterpret_cast<std::uint64_t>(drivers[index]);
            module.identity = table.value().identity;
            return module;
        }
        return Status::process_not_found;
    } catch (...) {
        return Status::io_error;
    }
}

}