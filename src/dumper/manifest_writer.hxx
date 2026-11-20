#pragma once

#include "shared/protocol.hxx"
#include "shared/status.hxx"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string_view>

namespace dump {

class ManifestWriter {
public:
    ManifestWriter() = default;
    ~ManifestWriter();
    ManifestWriter(const ManifestWriter&) = delete;
    ManifestWriter& operator=(const ManifestWriter&) = delete;

    Status begin(const std::filesystem::path& final_path) noexcept;
    Status success(std::wstring_view message) noexcept;
    Status progress(std::wstring_view message) noexcept;
    Status error(std::wstring_view message) noexcept;
    Status region(std::size_t index, const protocol::RegionDescriptor& descriptor, std::uint64_t copied, std::int32_t native_status) noexcept;
    Status finalize(const std::filesystem::path& dump_path) noexcept;
    void discard(bool keep_partial) noexcept;

private:
    Status write(std::string_view prefix, std::wstring_view message) noexcept;
    std::filesystem::path final_path_;
    std::filesystem::path partial_path_;
    std::ofstream stream_;
    bool finalized_{};
    bool keep_partial_{};
};

}
