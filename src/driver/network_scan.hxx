#pragma once

#include <ntifs.h>

#include "process_snapshot.hxx"
#include "shared/protocol.hxx"

namespace dump::driver {

class NetworkScan {
public:
    NTSTATUS scan(ProcessSnapshot& snapshot, protocol::u64 start, protocol::u32 budget, protocol::u32 maximum_records, protocol::HttpScanResponse& response) noexcept;
};

}