#pragma once

#include <ntifs.h>

#include "process_snapshot.hxx"
#include "shared/protocol.hxx"

namespace dump::driver {

class ImageSections {
public:
    NTSTATUS query(ProcessSnapshot& snapshot, protocol::SectionsResponse& response) noexcept;
};

}