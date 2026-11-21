#pragma once

#include "shared/status.hxx"

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace dump {

struct ExportEntry {
    std::string name;
    std::uint32_t rva{};
};

struct ImageIdentity {
    std::uint32_t timestamp{};
    std::uint32_t image_size{};
    std::uint32_t headers_size{};
};

struct ExportTable {
    ImageIdentity identity{};
    std::vector<ExportEntry> entries;
};

struct LoadedModule {
    std::wstring path;
    std::uint64_t base{};
    ImageIdentity identity{};
};

Result<ExportTable> parse_export_table(std::span<const std::byte> image) noexcept;
Result<ExportTable> read_export_table(const std::filesystem::path& path) noexcept;
Result<std::uint32_t> find_export(const ExportTable& table, std::string_view name) noexcept;
Result<LoadedModule> find_loaded_module(std::wstring_view name) noexcept;

}