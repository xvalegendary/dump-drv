#pragma once

#include "shared/protocol.hxx"
#include "shared/status.hxx"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dump {

struct SnapshotMetadata {
    std::uint32_t process_id{};
    std::uint16_t processor_architecture{};
    std::uint8_t processors{};
    std::uint32_t major_version{};
    std::uint32_t minor_version{};
    std::uint32_t build_number{};
    std::uint32_t platform_id{};
    std::wstring comment;
};

struct ModuleRecord {
    std::uint64_t base{};
    std::uint32_t size{};
    std::uint32_t checksum{};
    std::uint32_t timestamp{};
    std::wstring name;
};

struct MemoryRecord {
    protocol::RegionDescriptor region{};
    std::uint64_t written{};
};

struct DumpValidationResult {
    Status status{Status::validation_failure};
    bool valid{};
    std::vector<std::uint32_t> streams;
    std::size_t memory_ranges{};
    std::uint64_t memory_bytes{};
    std::uint64_t first_memory_base{};
    std::uint32_t failure_stage{};
};

}
