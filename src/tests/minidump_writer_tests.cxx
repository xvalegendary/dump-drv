#include "test.hxx"

#include "dumper/minidump_writer.hxx"

#define NOMINMAX
#include <Windows.h>
#include <DbgHelp.h>

#include <array>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

namespace {

std::filesystem::path dump_path(const wchar_t* name) {
    const auto root = std::filesystem::temp_directory_path() / L"dump-driver-minidump-tests";
    std::filesystem::create_directories(root);
    return root / name;
}

dump::SnapshotMetadata metadata() {
    dump::SnapshotMetadata value{};
    value.processor_architecture = PROCESSOR_ARCHITECTURE_AMD64;
    value.processors = 8;
    value.major_version = 10;
    value.minor_version = 0;
    value.build_number = 28000;
    value.platform_id = VER_PLATFORM_WIN32_NT;
    value.comment = L"dump-driver-test";
    return value;
}

dump::MemoryRecord memory(const std::uint64_t base, const std::uint64_t size) {
    dump::MemoryRecord value{};
    value.region.base = base;
    value.region.allocation_base = base;
    value.region.size = size;
    value.region.state = dump::protocol::RegionState::committed;
    value.region.type = dump::protocol::RegionType::private_region;
    value.region.protect = PAGE_READWRITE;
    return value;
}

}

TEST_CASE("minidump", minidump_writes_required_streams_and_signature) {
    const auto path = dump_path(L"required.dmp");
    std::filesystem::remove(path);
    std::filesystem::remove(path.wstring() + L".partial");
    dump::MiniDumpWriter writer;
    REQUIRE(writer.begin(path) == dump::Status::success);
    REQUIRE(writer.add_system_info(metadata()) == dump::Status::success);
    REQUIRE(writer.add_module(dump::ModuleRecord{0x140000000, 0x20000, 0, 0x12345678, L"тестовый-модуль.exe"}) == dump::Status::success);
    REQUIRE(writer.add_memory_region(memory(0x10000, 4)) == dump::Status::success);
    const std::array bytes{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    REQUIRE(writer.append_memory(0x10000, bytes) == dump::Status::success);
    const auto status = writer.finalize();
    if (status != dump::Status::success) {
        const auto validation = dump::MiniDumpWriter::validate_file(path.wstring() + L".partial");
        throw std::runtime_error("validation-stage=" + std::to_string(validation.failure_stage) + " status=" + std::to_string(static_cast<unsigned long>(validation.status)) + " valid=" + std::to_string(validation.valid));
    }
    const auto validation = dump::MiniDumpWriter::validate_file(path);
    REQUIRE(validation.status == dump::Status::success);
    REQUIRE(validation.valid);
    REQUIRE(validation.streams.size() == 6);
    REQUIRE(validation.memory_ranges == 1);
    REQUIRE(validation.memory_bytes == 4);
    std::ifstream input(path, std::ios::binary);
    MINIDUMP_HEADER header{};
    input.read(reinterpret_cast<char*>(&header), sizeof(header));
    REQUIRE(header.Signature == MINIDUMP_SIGNATURE);
    REQUIRE(header.Version == MINIDUMP_VERSION);
}

TEST_CASE("minidump", minidump_keeps_sorted_high_addresses_and_partial_lengths) {
    const auto path = dump_path(L"ranges.dmp");
    std::filesystem::remove(path);
    dump::MiniDumpWriter writer;
    REQUIRE(writer.begin(path) == dump::Status::success);
    REQUIRE(writer.add_system_info(metadata()) == dump::Status::success);
    REQUIRE(writer.add_memory_region(memory(0x100000000ull + 0x1000, 8)) == dump::Status::success);
    const std::array first{std::byte{0xaa}, std::byte{0xbb}, std::byte{0xcc}};
    REQUIRE(writer.append_memory(0x100001000ull, first) == dump::Status::success);
    REQUIRE(writer.add_memory_region(memory(0x200000000ull, 2)) == dump::Status::success);
    const std::array second{std::byte{0x11}, std::byte{0x22}};
    REQUIRE(writer.append_memory(0x200000000ull, second) == dump::Status::success);
    const auto status = writer.finalize();
    if (status != dump::Status::success) {
        const auto validation = dump::MiniDumpWriter::validate_file(path.wstring() + L".partial");
        throw std::runtime_error("validation-stage=" + std::to_string(validation.failure_stage) + " status=" + std::to_string(static_cast<unsigned long>(validation.status)) + " valid=" + std::to_string(validation.valid));
    }
    const auto validation = dump::MiniDumpWriter::validate_file(path);
    REQUIRE(validation.valid);
    REQUIRE(validation.memory_ranges == 2);
    REQUIRE(validation.memory_bytes == 5);
    REQUIRE(validation.first_memory_base == 0x100001000ull);
}

TEST_CASE("minidump", minidump_rejects_overlapping_descriptors) {
    const auto path = dump_path(L"overlap.dmp");
    dump::MiniDumpWriter writer;
    REQUIRE(writer.begin(path) == dump::Status::success);
    REQUIRE(writer.add_memory_region(memory(0x1000, 0x1000)) == dump::Status::success);
    REQUIRE(writer.add_memory_region(memory(0x1800, 0x1000)) == dump::Status::invalid_argument);
}

TEST_CASE("minidump", minidump_final_name_is_atomic) {
    const auto path = dump_path(L"atomic.dmp");
    const auto partial = std::filesystem::path(path.wstring() + L".partial");
    std::filesystem::remove(path);
    std::filesystem::remove(partial);
    dump::MiniDumpWriter writer;
    REQUIRE(writer.begin(path) == dump::Status::success);
    REQUIRE(!std::filesystem::exists(path));
    REQUIRE(std::filesystem::exists(partial));
    REQUIRE(writer.add_system_info(metadata()) == dump::Status::success);
    const auto status = writer.finalize();
    if (status != dump::Status::success) {
        const auto validation = dump::MiniDumpWriter::validate_file(partial);
        throw std::runtime_error("validation-stage=" + std::to_string(validation.failure_stage) + " status=" + std::to_string(static_cast<unsigned long>(validation.status)) + " valid=" + std::to_string(validation.valid));
    }
    REQUIRE(std::filesystem::exists(path));
    REQUIRE(!std::filesystem::exists(partial));
}

TEST_CASE("minidump", minidump_contains_utf16_module_name) {
    const auto path = dump_path(L"unicode.dmp");
    dump::MiniDumpWriter writer;
    REQUIRE(writer.begin(path) == dump::Status::success);
    REQUIRE(writer.add_system_info(metadata()) == dump::Status::success);
    REQUIRE(writer.add_module(dump::ModuleRecord{0x180000000, 0x1000, 0, 0, L"модуль.exe"}) == dump::Status::success);
    const auto status = writer.finalize();
    if (status != dump::Status::success) {
        const auto validation = dump::MiniDumpWriter::validate_file(path.wstring() + L".partial");
        throw std::runtime_error("validation-stage=" + std::to_string(validation.failure_stage) + " status=" + std::to_string(static_cast<unsigned long>(validation.status)) + " valid=" + std::to_string(validation.valid));
    }
    std::ifstream input(path, std::ios::binary);
    const std::string bytes((std::istreambuf_iterator<char>(input)), {});
    const std::wstring name = L"модуль.exe";
    const std::string encoded(reinterpret_cast<const char*>(name.data()), name.size() * sizeof(wchar_t));
    REQUIRE(bytes.find(encoded) != std::string::npos);
}
