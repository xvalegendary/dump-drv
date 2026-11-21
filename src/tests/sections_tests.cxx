#include "test.hxx"

#include "dumper/section_dumper.hxx"
#include "driver/session_state.hxx"
#include "shared/validation.hxx"

#include <algorithm>
#include <array>
#include <iterator>
#include <cstdint>
#include <cstring>
#include <string>

namespace {

using namespace dump;

protocol::SectionDescriptor section(const char* name, const std::uint64_t rva, const std::uint32_t virtual_size, const std::uint32_t raw_size) {
    protocol::SectionDescriptor descriptor{};
    std::memcpy(descriptor.name.data(), name, std::strlen(name));
    descriptor.virtual_address = rva;
    descriptor.virtual_size = virtual_size;
    descriptor.raw_size = raw_size;
    return descriptor;
}

protocol::SectionsResponse response() {
    protocol::SectionsResponse value{};
    value.image_base = 0x140000000;
    value.image_size = 0x4000;
    value.headers_size = 0x400;
    value.section_count = 2;
    value.sections[0] = section(".text", 0x1000, 0x2000, 0x2000);
    value.sections[1] = section(".data", 0x3000, 0x1000, 0x800);
    return value;
}

protocol::ConcealTargets targets() {
    protocol::ConcealTargets value{};
    value.nt_timestamp = 0x1c62bee3;
    value.nt_image_size = 0x1046000;
    value.ps_loaded_module_list_rva = 0xc2a420;
    value.ci_timestamp = 0x356884b4;
    value.ci_image_size = 0xec000;
    value.flags = protocol::conceal_all;
    const wchar_t name[] = L"iqvw64e.sys";
    std::copy(std::begin(name), std::end(name), value.module_name.begin());
    return value;
}

}

TEST_CASE("sections", sections_names_and_extents_are_stable) {
    const auto table = response();
    REQUIRE(section_extent(table.sections[0], table.image_size) == 0x2000);
    REQUIRE(section_extent(table.sections[1], table.image_size) == 0x1000);
    REQUIRE(section_file_name(L"dumped-20261117-120102-notepad.exe", 1, table.sections[1]) == L"dumped-20261117-120102-notepad.exe.01-.data.bin");
    auto outside = table.sections[1];
    outside.virtual_address = 0x4000;
    REQUIRE(section_extent(outside, table.image_size) == 0);
    auto hostile = table.sections[1];
    std::memcpy(hostile.name.data(), "..\\x/y", 6);
    const auto name = section_file_name(L"stem", 2, hostile);
    REQUIRE(name == L"stem.02-.._x_y.bin");
}

TEST_CASE("sections", sections_validation_rejects_corrupt_tables) {
    auto table = response();
    REQUIRE(validation::validate_sections(table) == Status::success);
    table.section_count = 0;
    REQUIRE(validation::validate_sections(table) == Status::invalid_argument);
    table = response();
    table.sections[1].virtual_address = 0x800;
    REQUIRE(validation::validate_sections(table) == Status::invalid_argument);
    table = response();
    table.sections[1].virtual_size = 0x2000;
    REQUIRE(validation::validate_sections(table) == Status::invalid_argument);
    table = response();
    table.headers_size = 0;
    REQUIRE(validation::validate_sections(table) == Status::invalid_argument);
    table = response();
    for (auto& value : table.sections[0].name) value = 'A';
    REQUIRE(validation::validate_sections(table) == Status::invalid_argument);
}

TEST_CASE("conceal", conceal_kernel_pointer_and_range_boundaries) {
    REQUIRE(validation::validate_kernel_pointer(0xffff800000000000) == Status::success);
    REQUIRE(validation::validate_kernel_pointer(0x00007fffffffffff) == Status::noncanonical_address);
    REQUIRE(validation::validate_kernel_pointer(0) == Status::noncanonical_address);
    REQUIRE(validation::validate_kernel_range(0xfffff80612400000, 0x1000) == Status::success);
    REQUIRE(validation::validate_kernel_range(0xfffffffffffff000, 0x2000) == Status::range_overflow);
    REQUIRE(validation::validate_kernel_range(0xfffff80612400000, 0) == Status::invalid_argument);
}

TEST_CASE("conceal", conceal_unicode_names_require_alignment_and_bounds) {
    REQUIRE(validation::validate_unicode_name(0x18, 0x20) == Status::success);
    REQUIRE(validation::validate_unicode_name(0x19, 0x20) == Status::invalid_argument);
    REQUIRE(validation::validate_unicode_name(0, 0x20) == Status::invalid_argument);
    REQUIRE(validation::validate_unicode_name(0x18, 0x10) == Status::invalid_argument);
    REQUIRE(validation::validate_unicode_name(0x202, 0x400) == Status::invalid_argument);
}

TEST_CASE("conceal", conceal_list_links_require_kernel_canonical_pointers) {
    REQUIRE(validation::validate_list_links(0xfffff80600001000, 0xfffff80600002000, 0xfffff80600003000) == Status::success);
    REQUIRE(validation::validate_list_links(0x140000000, 0xfffff80600002000, 0xfffff80600003000) == Status::noncanonical_address);
    REQUIRE(validation::validate_list_links(0xfffff80600001001, 0xfffff80600002000, 0xfffff80600003000) == Status::invalid_argument);
}

TEST_CASE("conceal", conceal_targets_require_identity_match) {
    const auto value = targets();
    const protocol::KernelIdentity system{0x1c62bee3, 0x1046000, {}, 0};
    const protocol::KernelIdentity client{0x356884b4, 0xec000, {}, 0};
    REQUIRE(validation::validate_conceal_targets(value, system, client) == Status::success);
    auto mismatched = value;
    mismatched.nt_timestamp ^= 1;
    REQUIRE(validation::validate_conceal_targets(mismatched, system, client) == Status::kernel_identity_mismatch);
    mismatched = value;
    mismatched.ps_loaded_module_list_rva = protocol::unavailable_offset;
    REQUIRE(validation::validate_conceal_targets(mismatched, system, client) == Status::invalid_symbol_packet);
    mismatched = value;
    mismatched.flags = 0;
    REQUIRE(validation::validate_conceal_targets(mismatched, system, client) == Status::invalid_argument);
    mismatched = value;
    mismatched.ci_timestamp = 0;
    REQUIRE(validation::validate_conceal_targets(mismatched, system, client) == Status::kernel_identity_mismatch);
    mismatched = value;
    mismatched.module_name[3] = L'\\';
    REQUIRE(validation::validate_conceal_targets(mismatched, system, client) == Status::invalid_argument);
}

TEST_CASE("conceal", conceal_session_claim_is_single_use_and_requires_attach) {
    driver::SessionState session;
    REQUIRE(session.claim_conceal() == Status::invalid_state);
    REQUIRE(session.bind(0x1111) == Status::success);
    REQUIRE(session.claim_conceal() == Status::invalid_state);
    REQUIRE(session.attach(404, 0xabc000) == Status::success);
    REQUIRE(session.claim_conceal() == Status::success);
    REQUIRE(session.claim_conceal() == Status::invalid_state);
}