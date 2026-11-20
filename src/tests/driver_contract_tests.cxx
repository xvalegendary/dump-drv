#include "test.hxx"

#include "driver/session_state.hxx"

#include <algorithm>
#include <cstdint>

namespace {

dump::protocol::BootConfiguration boot() {
    dump::protocol::BootConfiguration configuration{};
    configuration.header.magic = dump::protocol::magic;
    configuration.header.version = dump::protocol::version;
    configuration.header.size = sizeof(configuration);
    configuration.header.nonce.fill(0x55);
    const wchar_t driver[] = L"\\Driver\\Dump_1234";
    const wchar_t device[] = L"\\Device\\Dump_1234";
    const wchar_t link[] = L"\\DosDevices\\Dump_1234";
    std::copy(std::begin(driver), std::end(driver), configuration.driver_name.begin());
    std::copy(std::begin(device), std::end(device), configuration.device_name.begin());
    std::copy(std::begin(link), std::end(link), configuration.symbolic_link.begin());
    return configuration;
}

}

TEST_CASE("driver-contract", driver_contract_transitions_through_full_lifecycle) {
    dump::driver::SessionState session;
    REQUIRE(session.state() == dump::protocol::SessionState::created);
    REQUIRE(session.bind(0x1111) == dump::Status::success);
    REQUIRE(session.attach(404, 0xabc000) == dump::Status::success);
    REQUIRE(session.begin_snapshot() == dump::Status::success);
    REQUIRE(session.end_snapshot() == dump::Status::success);
    REQUIRE(session.prepare_shutdown(0) == dump::Status::success);
    REQUIRE(session.stop() == dump::Status::success);
    REQUIRE(session.state() == dump::protocol::SessionState::stopped);
}

TEST_CASE("driver-contract", driver_contract_rejects_invalid_boot_configuration) {
    auto configuration = boot();
    configuration.device_name[0] = L'X';
    REQUIRE(dump::driver::validate_boot_configuration(configuration) == dump::Status::invalid_argument);
}

TEST_CASE("driver-contract", driver_contract_rejects_commands_before_bind) {
    dump::driver::SessionState session;
    REQUIRE(session.attach(1, 2) == dump::Status::invalid_state);
    REQUIRE(session.begin_snapshot() == dump::Status::invalid_state);
}

TEST_CASE("driver-contract", driver_contract_rejects_second_file_object) {
    dump::driver::SessionState session;
    REQUIRE(session.bind(0x1111) == dump::Status::success);
    REQUIRE(session.bind(0x2222) == dump::Status::access_denied);
}

TEST_CASE("driver-contract", driver_contract_detects_pid_reuse) {
    dump::driver::SessionState session;
    REQUIRE(session.bind(0x1111) == dump::Status::success);
    REQUIRE(session.attach(404, 0xabc000) == dump::Status::success);
    REQUIRE(session.validate_process(404, 0xdef000) == dump::Status::process_exited);
}

TEST_CASE("driver-contract", driver_contract_rejects_replay_and_large_read) {
    dump::driver::SessionState session;
    REQUIRE(session.accept_sequence(1) == dump::Status::success);
    REQUIRE(session.accept_sequence(1) == dump::Status::sequence_replay);
    REQUIRE(session.validate_read(dump::protocol::maximum_transfer + 1) == dump::Status::invalid_argument);
    REQUIRE(session.validate_read(dump::protocol::maximum_transfer) == dump::Status::success);
}

TEST_CASE("driver-contract", driver_contract_waits_for_rundown_before_shutdown) {
    dump::driver::SessionState session;
    REQUIRE(session.bind(0x1111) == dump::Status::success);
    REQUIRE(session.prepare_shutdown(1) == dump::Status::invalid_state);
}
