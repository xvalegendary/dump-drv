#include "network_scan.hxx"

#include "shared/http.hxx"

namespace {

using dump::protocol::u32;
using dump::protocol::u64;
using dump::protocol::usize;

constexpr u32 chunk_span = 0x8000;
constexpr u32 carry_span = 0x1000;
constexpr u32 window_span = chunk_span + carry_span;
constexpr u32 default_budget = 4u * 1024u * 1024u;
constexpr u32 maximum_budget = 16u * 1024u * 1024u;
constexpr u64 highest_user_address = 0x00007fffffffffff;

alignas(16) unsigned char window[window_span];
alignas(16) dump::protocol::HttpRecord scratch[dump::protocol::maximum_http_records];

bool readable(const dump::protocol::RegionDescriptor& region) noexcept {
    constexpr u32 page_noaccess = 0x01;
    constexpr u32 page_guard = 0x100;
    return region.state == dump::protocol::RegionState::committed && region.protect != 0 && (region.protect & (page_noaccess | page_guard)) == 0;
}

}

namespace dump::driver {

NTSTATUS NetworkScan::scan(ProcessSnapshot& snapshot, const protocol::u64 start, const protocol::u32 budget, const protocol::u32 maximum_records, protocol::HttpScanResponse& response) noexcept {
    response = protocol::HttpScanResponse{};
    if (maximum_records == 0 || maximum_records > protocol::maximum_http_records) {
        response.native_status = STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }
    if (snapshot.process() == nullptr) {
        response.native_status = STATUS_INVALID_DEVICE_STATE;
        return STATUS_INVALID_DEVICE_STATE;
    }
    const auto limit = budget == 0 ? default_budget : (budget > maximum_budget ? maximum_budget : budget);
    auto address = start > highest_user_address ? protocol::u64{0} : start;
    if (start > highest_user_address) {
        response.complete = 1;
        response.native_status = STATUS_SUCCESS;
        return STATUS_SUCCESS;
    }
    u64 scanned{};
    usize tail_length{};
    while (scanned < limit) {
        protocol::RegionDescriptor region{};
        const auto query_status = snapshot.query(address, region);
        if (!NT_SUCCESS(query_status) || region.size == 0) {
            response.complete = 1;
            break;
        }
        const auto end = region.base + region.size;
        if (end <= region.base) {
            response.complete = 1;
            break;
        }
        if (!readable(region)) {
            tail_length = 0;
            address = end;
            if (address > highest_user_address) {
                response.complete = 1;
                break;
            }
            continue;
        }
        auto cursor = address < region.base ? region.base : address;
        while (cursor < end && scanned < limit && response.record_count < maximum_records) {
            const auto remaining = end - cursor;
            const auto span = static_cast<u32>(remaining < chunk_span ? remaining : chunk_span);
            SIZE_T transferred{};
            const auto read_status = snapshot.read(cursor, window + tail_length, span, transferred);
            if (!NT_SUCCESS(read_status) || transferred == 0) {
                tail_length = 0;
                cursor += span;
                continue;
            }
            const auto total = tail_length + transferred;
            const auto count = http::parse(window, total, scratch, protocol::maximum_http_records);
            for (u32 index = 0; index < count && response.record_count < maximum_records; ++index) {
                bool duplicate{};
                for (u32 existing = 0; existing < response.record_count; ++existing) {
                    if (http::same(response.records[existing], scratch[index])) {
                        duplicate = true;
                        break;
                    }
                }
                if (duplicate) {
                    continue;
                }
                response.records[response.record_count] = scratch[index];
                ++response.record_count;
            }
            tail_length = total > carry_span ? carry_span : total;
            RtlMoveMemory(window, window + total - tail_length, tail_length);
            cursor += transferred;
            scanned += transferred;
            if (transferred != span) {
                tail_length = 0;
                cursor = end;
            }
        }
        if (cursor >= end) {
            tail_length = 0;
            address = end;
        } else {
            address = cursor;
        }
        if (address > highest_user_address) {
            response.complete = 1;
            break;
        }
    }
    response.next_address = response.complete != 0 ? 0 : address;
    response.scanned = scanned;
    response.native_status = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}

}