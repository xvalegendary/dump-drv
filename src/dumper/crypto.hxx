#pragma once

#include "shared/protocol.hxx"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace dump::crypto {

protocol::FixedArray<std::uint8_t, 32> sha256(std::span<const std::byte> bytes) noexcept;
protocol::Nonce random_nonce() noexcept;

}
