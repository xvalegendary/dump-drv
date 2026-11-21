#pragma once

#include "protocol.hxx"
#include "status.hxx"

namespace dump::validation {

Status validate_header(const protocol::Header& header, const protocol::Nonce& expected_nonce, protocol::usize actual_size) noexcept;
Status validate_range(protocol::u64 base, protocol::u64 size) noexcept;
Status validate_symbol_packet(const protocol::SymbolPacket& packet, const protocol::KernelIdentity& running) noexcept;
Status validate_sequence(protocol::u64 incoming, protocol::u64 last_accepted) noexcept;
Status validate_kernel_pointer(protocol::u64 address) noexcept;
Status validate_kernel_range(protocol::u64 address, protocol::u64 size) noexcept;
Status validate_unicode_name(protocol::u32 length, protocol::u32 maximum_length) noexcept;
Status validate_list_links(protocol::u64 entry, protocol::u64 forward, protocol::u64 backward) noexcept;
Status validate_conceal_targets(const protocol::ConcealTargets& targets, const protocol::KernelIdentity& nt, const protocol::KernelIdentity& ci) noexcept;
Status validate_sections(const protocol::SectionsResponse& response) noexcept;

}