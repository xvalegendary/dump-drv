#include "test.hxx"

#include "dumper/mapper.hxx"

#include <algorithm>
#include <cstddef>
#include <span>
#include <string>
#include <vector>

namespace {

class FakeBackend final : public dump::IMapperBackend {
public:
    dump::Status load() override { calls.push_back("Load"); return load_status; }
    dump::Result<dump::MapResult> map(std::span<const std::byte>, dump::protocol::BootConfiguration&) override {
        calls.push_back("MapDriver");
        if (map_status != dump::Status::success) {
            return map_status;
        }
        return map_result;
    }
    dump::Status call_finalizer(const std::uint64_t address, const dump::protocol::Nonce&) override {
        calls.push_back("finalizer");
        finalizer_address = address;
        return finalizer_status;
    }
    dump::Status free_pool(std::uint64_t) override { calls.push_back("allocation cleanup"); return free_status; }
    dump::Status unload() override { calls.push_back("Unload"); return unload_status; }

    std::vector<std::string> calls;
    dump::Status load_status{dump::Status::success};
    dump::Status map_status{dump::Status::success};
    dump::Status finalizer_status{dump::Status::success};
    dump::Status free_status{dump::Status::success};
    dump::Status unload_status{dump::Status::success};
    dump::MapResult map_result{0xffff800000100000, 0, 0x2200};
    std::uint64_t finalizer_address{};
};

class FakeLifecycle final : public dump::IDeviceLifecycle {
public:
    explicit FakeLifecycle(std::vector<std::string>& calls) : calls_(calls) {}
    dump::Status bind() override { calls_.push_back("bind"); return bind_status; }
    dump::Status prepare_shutdown() override { calls_.push_back("shutdown"); return shutdown_status; }
    dump::Status bind_status{dump::Status::success};
    dump::Status shutdown_status{dump::Status::success};
private:
    std::vector<std::string>& calls_;
};

dump::protocol::BootConfiguration configuration() {
    dump::protocol::BootConfiguration value{};
    value.header.magic = dump::protocol::magic;
    value.header.version = dump::protocol::version;
    value.header.size = sizeof(value);
    value.header.nonce.fill(0x41);
    return value;
}

}

TEST_CASE("mapper", mapper_contract_orders_complete_lifecycle) {
    FakeBackend backend;
    FakeLifecycle lifecycle(backend.calls);
    dump::MapperSession session(backend);
    const std::byte image[]{std::byte{0x4d}, std::byte{0x5a}};
    auto boot = configuration();
    REQUIRE(session.open() == dump::Status::success);
    REQUIRE(session.map_embedded_driver(image, boot) == dump::Status::success);
    REQUIRE(session.bind(lifecycle) == dump::Status::success);
    REQUIRE(session.shutdown(lifecycle) == dump::Status::success);
    const std::vector<std::string> expected{"Load", "MapDriver", "bind", "shutdown", "finalizer", "allocation cleanup", "Unload"};
    REQUIRE(backend.calls == expected);
}

TEST_CASE("mapper", mapper_contract_unloads_immediately_after_map_failure) {
    FakeBackend backend;
    backend.map_status = dump::Status::mapper_failure;
    dump::MapperSession session(backend);
    const std::byte image[]{std::byte{0x4d}, std::byte{0x5a}};
    auto boot = configuration();
    REQUIRE(session.open() == dump::Status::success);
    REQUIRE(session.map_embedded_driver(image, boot) == dump::Status::mapper_failure);
    const std::vector<std::string> expected{"Load", "MapDriver", "Unload"};
    REQUIRE(backend.calls == expected);
}

TEST_CASE("mapper", mapper_contract_does_not_free_before_finalizer_success) {
    FakeBackend backend;
    backend.finalizer_status = dump::Status::driver_failure;
    FakeLifecycle lifecycle(backend.calls);
    dump::MapperSession session(backend);
    const std::byte image[]{std::byte{0x4d}, std::byte{0x5a}};
    auto boot = configuration();
    REQUIRE(session.open() == dump::Status::success);
    REQUIRE(session.map_embedded_driver(image, boot) == dump::Status::success);
    REQUIRE(session.bind(lifecycle) == dump::Status::success);
    REQUIRE(session.shutdown(lifecycle) == dump::Status::driver_failure);
    REQUIRE(std::find(backend.calls.begin(), backend.calls.end(), "allocation cleanup") == backend.calls.end());
    REQUIRE(backend.calls.back() == "Unload");
}

TEST_CASE("mapper", mapper_contract_preserves_entry_status_and_allocation) {
    FakeBackend backend;
    dump::MapperSession session(backend);
    const std::byte image[]{std::byte{0x4d}, std::byte{0x5a}};
    auto boot = configuration();
    REQUIRE(session.open() == dump::Status::success);
    REQUIRE(session.map_embedded_driver(image, boot) == dump::Status::success);
    REQUIRE(session.allocation_base() == 0xffff800000100000);
    REQUIRE(session.entry_status() == 0);
}

TEST_CASE("mapper", mapper_contract_aborts_unbound_mapping_in_order) {
    FakeBackend backend;
    dump::MapperSession session(backend);
    const std::byte image[]{std::byte{0x4d}, std::byte{0x5a}};
    auto boot = configuration();
    REQUIRE(session.open() == dump::Status::success);
    REQUIRE(session.map_embedded_driver(image, boot) == dump::Status::success);
    REQUIRE(session.abort() == dump::Status::success);
    const std::vector<std::string> expected{"Load", "MapDriver", "finalizer", "allocation cleanup", "Unload"};
    REQUIRE(backend.calls == expected);
}

TEST_CASE("mapper", mapper_contract_releases_failed_entry_allocation) {
    FakeBackend backend;
    backend.map_result.entry_status = static_cast<std::int32_t>(0xc0000001u);
    dump::MapperSession session(backend);
    const std::byte image[]{std::byte{0x4d}, std::byte{0x5a}};
    auto boot = configuration();
    REQUIRE(session.open() == dump::Status::success);
    REQUIRE(session.map_embedded_driver(image, boot) == dump::Status::driver_failure);
    const std::vector<std::string> expected{"Load", "MapDriver", "allocation cleanup", "Unload"};
    REQUIRE(backend.calls == expected);
}

TEST_CASE("mapper", mapper_contract_translates_rva_after_discarded_headers) {
    FakeBackend backend;
    backend.map_result.finalizer_rva = 0x1150;
    backend.map_result.discarded_header_size = 0x1000;
    dump::MapperSession session(backend);
    const std::byte image[]{std::byte{0x4d}, std::byte{0x5a}};
    auto boot = configuration();
    REQUIRE(session.open() == dump::Status::success);
    REQUIRE(session.map_embedded_driver(image, boot) == dump::Status::success);
    REQUIRE(session.abort() == dump::Status::success);
    REQUIRE(backend.finalizer_address == backend.map_result.allocation_base + 0x150);
}
