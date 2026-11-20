#pragma once

#include "shared/protocol.hxx"
#include "shared/status.hxx"

#include <cstddef>
#include <cstdint>
#include <span>

namespace dump {

struct MapResult {
    std::uint64_t allocation_base{};
    std::int32_t entry_status{};
    std::uint32_t finalizer_rva{};
    std::uint32_t discarded_header_size{};
};

class IMapperBackend {
public:
    virtual ~IMapperBackend() = default;
    virtual Status load() = 0;
    virtual Result<MapResult> map(std::span<const std::byte> image, protocol::BootConfiguration& configuration) = 0;
    virtual Status call_finalizer(std::uint64_t address, const protocol::Nonce& nonce) = 0;
    virtual Status free_pool(std::uint64_t allocation) = 0;
    virtual Status unload() = 0;
};

class IDeviceLifecycle {
public:
    virtual ~IDeviceLifecycle() = default;
    virtual Status bind() = 0;
    virtual Status prepare_shutdown() = 0;
};

class MapperSession {
public:
    explicit MapperSession(IMapperBackend& backend) noexcept;
    ~MapperSession();
    MapperSession(const MapperSession&) = delete;
    MapperSession& operator=(const MapperSession&) = delete;

    Status open() noexcept;
    Status map_embedded_driver(std::span<const std::byte> image, protocol::BootConfiguration& configuration) noexcept;
    Status bind(IDeviceLifecycle& lifecycle) noexcept;
    Status shutdown(IDeviceLifecycle& lifecycle) noexcept;
    Status abort() noexcept;
    [[nodiscard]] std::uint64_t allocation_base() const noexcept;
    [[nodiscard]] std::int32_t entry_status() const noexcept;

private:
    IMapperBackend& backend_;
    protocol::Nonce nonce_{};
    std::uint64_t allocation_{};
    std::uint32_t finalizer_rva_{};
    std::uint32_t discarded_header_size_{};
    std::int32_t entry_status_{};
    bool loaded_{};
    bool mapped_{};
    bool bound_{};
};

class KdmapperBackend final : public IMapperBackend {
public:
    Status load() override;
    Result<MapResult> map(std::span<const std::byte> image, protocol::BootConfiguration& configuration) override;
    Status call_finalizer(std::uint64_t address, const protocol::Nonce& nonce) override;
    Status free_pool(std::uint64_t allocation) override;
    Status unload() override;
};

}
