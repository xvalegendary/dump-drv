#pragma once

#include <ntifs.h>

#include "shared/protocol.hxx"

namespace dump::driver {

class Conceal {
public:
    NTSTATUS apply(const protocol::ConcealTargets& targets, protocol::ConcealResponse& response) noexcept;
};

}