#pragma once

#include "minidump_model.hxx"

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <span>
#include <vector>

namespace dump {

class MiniDumpWriter {
public:
    MiniDumpWriter() = default;
    MiniDumpWriter(const MiniDumpWriter&) = delete;
    MiniDumpWriter& operator=(const MiniDumpWriter&) = delete;
    ~MiniDumpWriter();

    Status begin(const std::filesystem::path& final_path) noexcept;
    Status add_system_info(const SnapshotMetadata& metadata) noexcept;
    Status add_module(ModuleRecord module) noexcept;
    Status add_memory_region(MemoryRecord memory) noexcept;
    Status append_memory(std::uint64_t address, std::span<const std::byte> bytes) noexcept;
    Status finalize() noexcept;
    void discard(bool keep_partial) noexcept;

    static DumpValidationResult validate_file(const std::filesystem::path& path) noexcept;

private:
    void cleanup_spool() noexcept;

    std::filesystem::path final_path_;
    std::filesystem::path partial_path_;
    std::filesystem::path spool_path_;
    std::ofstream spool_;
    SnapshotMetadata metadata_{};
    bool has_metadata_{};
    bool begun_{};
    bool finalized_{};
    bool keep_partial_{};
    std::vector<ModuleRecord> modules_;
    std::vector<MemoryRecord> memories_;
};

}
