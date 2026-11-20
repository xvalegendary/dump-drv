#include "test.hxx"

#include "shared/protocol.hxx"
#include "shared/validation.hxx"

#include <array>
#include <cstdint>
#include <limits>

namespace {

dump::protocol::Header valid_header() {
    dump::protocol::Header header{};
    header.magic = dump::protocol::magic;
    header.version = dump::protocol::version;
    header.size = sizeof(header);
    header.sequence = 1;
    header.nonce.fill(0x41);
    return header;
}

}

TEST_CASE("protocol", protocol_rejects_wrong_version) {
    auto header = valid_header();
    --header.version;
    REQUIRE(dump::validation::validate_header(header, header.nonce, sizeof(header)) == dump::Status::version_mismatch);
}

TEST_CASE("protocol", protocol_rejects_wrong_nonce) {
    auto header = valid_header();
    auto expected = header.nonce;
    expected[3] ^= 0xff;
    REQUIRE(dump::validation::validate_header(header, expected, sizeof(header)) == dump::Status::nonce_mismatch);
}

TEST_CASE("protocol", range_rejects_wraparound) {
    constexpr auto base = std::numeric_limits<std::uint64_t>::max() - 7;
    REQUIRE(dump::validation::validate_range(base, 16) == dump::Status::range_overflow);
}

TEST_CASE("protocol", symbol_packet_rejects_kernel_identity_mismatch) {
    dump::protocol::SymbolPacket packet{};
    packet.header = valid_header();
    packet.kernel_timestamp = 0x12345678;
    packet.kernel_image_size = 0x100000;
    packet.unique_process_id = 0x440;
    packet.image_file_name = 0x5a8;
    dump::protocol::KernelIdentity running{0x87654321, 0x100000, {}, 1};
    REQUIRE(dump::validation::validate_symbol_packet(packet, running) == dump::Status::kernel_identity_mismatch);
}

TEST_CASE("protocol", sequence_rejects_replay) {
    REQUIRE(dump::validation::validate_sequence(8, 8) == dump::Status::sequence_replay);
    REQUIRE(dump::validation::validate_sequence(9, 8) == dump::Status::success);
}
