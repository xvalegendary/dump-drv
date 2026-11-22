#pragma once

#include "protocol.hxx"
#include "status.hxx"

namespace dump::http {

inline constexpr protocol::u32 maximum_header_scan = 0x4000;
inline constexpr protocol::usize carry_size = 0x1000;

protocol::u32 parse(const unsigned char* data, protocol::usize size, protocol::HttpRecord* records, protocol::u32 capacity) noexcept;
bool same(const protocol::HttpRecord& left, const protocol::HttpRecord& right) noexcept;
protocol::u32 method_length(const protocol::HttpRecord& record) noexcept;

}
