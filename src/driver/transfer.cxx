#include "transfer.hxx"

namespace dump::driver {

NTSTATUS native_status(const Status status) noexcept {
    switch (status) {
    case Status::success: return STATUS_SUCCESS;
    case Status::access_denied: return STATUS_ACCESS_DENIED;
    case Status::process_not_found: return STATUS_NOT_FOUND;
    case Status::process_exited: return STATUS_PROCESS_IS_TERMINATING;
    case Status::range_overflow: return STATUS_INTEGER_OVERFLOW;
    case Status::partial_copy: return STATUS_PARTIAL_COPY;
    case Status::invalid_state: return STATUS_INVALID_DEVICE_STATE;
    default: return STATUS_INVALID_PARAMETER;
    }
}

void* direct_output(PIRP irp, const SIZE_T required) noexcept {
    if (irp == nullptr || irp->MdlAddress == nullptr || MmGetMdlByteCount(irp->MdlAddress) < required) {
        return nullptr;
    }
    return MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);
}

NTSTATUS complete(PIRP irp, const NTSTATUS status, const ULONG_PTR information) noexcept {
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

}
