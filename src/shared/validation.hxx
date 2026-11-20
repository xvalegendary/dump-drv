#pragma once

#include "protocol.hxx"
#include "status.hxx"

namespace dump::validation {

Status validate_header(const protocol::Header& header, const protocol::Nonce& expected_nonce, protocol::usize actual_size) noexcept;
Status validate_range(protocol::u64 base, protocol::u64 size) noexcept;
Status validate_symbol_packet(const protocol::SymbolPacket& packet, const protocol::KernelIdentity& running) noexcept;
Status validate_sequence(protocol::u64 incoming, protocol::u64 last_accepted) noexcept;

}
