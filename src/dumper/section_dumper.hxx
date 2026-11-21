#pragma once

#include "driver_client.hxx"
#include "shared/protocol.hxx"
#include "shared/status.hxx"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace dump {

struct SectionDumpResult {
    std::uint64_t bytes{};
    std::size_t files{};
    std::size_t failed{};
};

std::wstring section_file_name(std::wstring_view stem, std::size_t index, const protocol::SectionDescriptor& section);
std::uint64_t section_extent(const protocol::SectionDescriptor& section, std::uint32_t image_size) noexcept;

class SectionDumper {
public:
    explicit SectionDumper(DriverClient& client) noexcept;

    Result<SectionDumpResult> write(const std::filesystem::path& directory, std::wstring_view stem, const protocol::SectionsResponse& table) noexcept;

private:
    DriverClient& client_;
};

}