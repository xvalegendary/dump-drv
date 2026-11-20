#pragma once

#include <ntifs.h>

#include "shared/status.hxx"

namespace dump::driver {

NTSTATUS native_status(Status status) noexcept;
void* direct_output(PIRP irp, SIZE_T required) noexcept;
NTSTATUS complete(PIRP irp, NTSTATUS status, ULONG_PTR information = 0) noexcept;

}
