#include "test.hxx"

#include "dumper/image_exports.hxx"
#include "shared/pe.hxx"

#include <cstring>
#include <vector>

namespace {

using namespace dump;

void store16(std::vector<std::byte>& data, const std::size_t offset, const std::uint16_t value) {
    data[offset] = static_cast<std::byte>(value & 0xff);
    data[offset + 1] = static_cast<std::byte>((value >> 8) & 0xff);
}

void store32(std::vector<std::byte>& data, const std::size_t offset, const std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        data[offset + index] = static_cast<std::byte>((value >> (index * 8)) & 0xff);
    }
}

constexpr std::size_t nt_offset = 0x80;
constexpr std::size_t optional_offset = nt_offset + 24;
constexpr std::size_t section_offset = optional_offset + 240;
constexpr std::size_t rdata_offset = 0x200;
constexpr std::uint32_t rdata_rva = 0x1000;

std::vector<std::byte> build_image() {
    std::vector<std::byte> data(0x600, std::byte{0});
    store16(data, 0, 0x5a4d);
    store32(data, 0x3c, static_cast<std::uint32_t>(nt_offset));
    store32(data, nt_offset, 0x00004550);
    store16(data, nt_offset + 4, 0x8664);
    store16(data, nt_offset + 6, 1);
    store32(data, nt_offset + 8, 0x11223344);
    store16(data, nt_offset + 20, 240);
    store16(data, optional_offset, 0x20b);
    store32(data, optional_offset + 32, 0x1000);
    store32(data, optional_offset + 56, 0x2000);
    store32(data, optional_offset + 60, 0x200);
    store32(data, optional_offset + 112, rdata_rva);
    store32(data, optional_offset + 116, 0x100);
    std::memcpy(data.data() + section_offset, ".rdata", 6);
    store32(data, section_offset + 8, 0x1000);
    store32(data, section_offset + 12, rdata_rva);
    store32(data, section_offset + 16, 0x400);
    store32(data, section_offset + 20, static_cast<std::uint32_t>(rdata_offset));
    store32(data, section_offset + 36, 0xc0000040);
    return data;
}

std::vector<std::byte> build_export_table() {
    auto data = build_image();
    const auto directory = rdata_offset;
    store32(data, directory + 12, 8);
    store32(data, directory + 16, 1);
    store32(data, directory + 20, 1);
    store32(data, directory + 24, 1);
    store32(data, directory + 28, rdata_rva + 0x40);
    store32(data, directory + 32, rdata_rva + 0x60);
    store32(data, directory + 36, rdata_rva + 0x80);
    store32(data, rdata_offset + 0x40, 0xc2a420);
    store32(data, rdata_offset + 0x60, rdata_rva + 0x90);
    store16(data, rdata_offset + 0x80, 0);
    std::memcpy(data.data() + rdata_offset + 0x90, "PsLoadedModuleList", 18);
    return data;
}

}

TEST_CASE("pe", pe_parses_headers_and_sections) {
    const auto data = build_image();
    pe::Image image{};
    REQUIRE(pe::parse(reinterpret_cast<const unsigned char*>(data.data()), data.size(), image) == Status::success);
    REQUIRE(image.section_count == 1);
    REQUIRE(image.image_size == 0x2000);
    REQUIRE(image.headers_size == 0x200);
    REQUIRE(image.timestamp == 0x11223344);
    REQUIRE(image.sections[0].virtual_address == rdata_rva);
    REQUIRE(pe::extent(image.sections[0], image.image_size) == 0x1000);
    REQUIRE(pe::writable(image.sections[0]));
    REQUIRE(!pe::executable(image.sections[0]));
    REQUIRE(pe::header_extent(image) == 0x200);
}

TEST_CASE("pe", pe_rejects_truncated_and_malformed_headers) {
    auto data = build_image();
    pe::Image image{};
    REQUIRE(pe::parse(reinterpret_cast<const unsigned char*>(data.data()), 0x40, image) == Status::invalid_argument);
    data = build_image();
    data[0] = std::byte{'P'};
    REQUIRE(pe::parse(reinterpret_cast<const unsigned char*>(data.data()), data.size(), image) == Status::validation_failure);
    data = build_image();
    store16(data, nt_offset + 6, static_cast<std::uint16_t>(protocol::maximum_sections + 1));
    REQUIRE(pe::parse(reinterpret_cast<const unsigned char*>(data.data()), data.size(), image) == Status::validation_failure);
}

TEST_CASE("pe", pe_rejects_section_outside_image) {
    auto data = build_image();
    store32(data, section_offset + 12, 0x9000);
    pe::Image image{};
    REQUIRE(pe::parse(reinterpret_cast<const unsigned char*>(data.data()), data.size(), image) == Status::validation_failure);
}

TEST_CASE("pe", pe_clamps_section_extent_to_image) {
    auto data = build_image();
    store32(data, section_offset + 12, 0x1800);
    store32(data, section_offset + 8, 0x1000);
    store32(data, section_offset + 16, 0x1000);
    pe::Image image{};
    REQUIRE(pe::parse(reinterpret_cast<const unsigned char*>(data.data()), data.size(), image) == Status::success);
    REQUIRE(pe::extent(image.sections[0], image.image_size) == 0x800);
}

TEST_CASE("exports", export_table_resolves_symbol_rva) {
    const auto data = build_export_table();
    const auto table = parse_export_table(data);
    REQUIRE(static_cast<bool>(table));
    REQUIRE(table.value().identity.image_size == 0x2000);
    REQUIRE(table.value().identity.timestamp == 0x11223344);
    REQUIRE(table.value().entries.size() == 1);
    const auto rva = find_export(table.value(), "PsLoadedModuleList");
    REQUIRE(static_cast<bool>(rva));
    REQUIRE(rva.value() == 0xc2a420);
    REQUIRE(!find_export(table.value(), "MmUnloadedDrivers"));
}

TEST_CASE("exports", export_table_rejects_corrupt_directory) {
    auto data = build_export_table();
    store32(data, rdata_offset + 24, 0xfffff);
    const auto table = parse_export_table(data);
    REQUIRE(static_cast<bool>(table));
    REQUIRE(table.value().entries.empty());
}