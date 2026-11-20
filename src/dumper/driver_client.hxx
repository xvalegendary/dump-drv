#pragma once

#include "mapper.hxx"
#include "shared/protocol.hxx"
#include "shared/status.hxx"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace dump {

struct ReadChunk {
    std::uint64_t address{};
    std::uint32_t requested{};
    std::int32_t native_status{};
    std::vector<std::byte> bytes;
};

class DriverClient final : public IDeviceLifecycle {
public:
    DriverClient(std::wstring path, protocol::Nonce nonce) noexcept;
    ~DriverClient();
    DriverClient(const DriverClient&) = delete;
    DriverClient& operator=(const DriverClient&) = delete;

    Status bind() override;
    Status prepare_shutdown() override;
    Result<protocol::AttachResponse> attach(std::uint32_t process_id) noexcept;
    Status set_symbols(protocol::SymbolPacket packet) noexcept;
    Result<protocol::QueryRegionResponse> query_region(std::uint64_t address) noexcept;
    Result<ReadChunk> read_memory(std::uint64_t address, std::uint32_t size) noexcept;
    Status close() noexcept;

private:
    template <typename Request>
    void prepare(Request& request, bool sequenced) noexcept {
        request.header.magic = protocol::magic;
        request.header.version = protocol::version;
        request.header.size = sizeof(Request);
        request.header.sequence = sequenced ? sequence_++ : 0;
        request.header.nonce = nonce_;
    }

    std::wstring path_;
    protocol::Nonce nonce_{};
    void* handle_{reinterpret_cast<void*>(static_cast<std::intptr_t>(-1))};
    std::uint64_t sequence_{1};
    bool bound_{};
    bool shutting_down_{};
};

}
