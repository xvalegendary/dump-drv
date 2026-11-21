#include "device.hxx"

#include "shared/validation.hxx"
#include "transfer.hxx"

#include <wdmsec.h>

namespace {

dump::driver::Device global_device;
constexpr GUID device_class_guid{0x2d5d80f8, 0x48ef, 0x46a8, {0x8c, 0x4a, 0xb4, 0x9e, 0x36, 0x11, 0x7c, 0xf1}};

template <typename T>
bool buffered_request(PIO_STACK_LOCATION stack, PIRP irp, T*& value) {
    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(T) || irp->AssociatedIrp.SystemBuffer == nullptr) {
        return false;
    }
    value = static_cast<T*>(irp->AssociatedIrp.SystemBuffer);
    return true;
}

}

namespace dump::driver {

Device& Device::instance() noexcept {
    return global_device;
}

NTSTATUS Device::initialize(PDRIVER_OBJECT driver_object, const protocol::BootConfiguration& configuration) noexcept {
    configuration_ = configuration;
    driver_object_ = driver_object;
    ExInitializeFastMutex(&mutex_);
    auto status = snapshot_.initialize();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    UNICODE_STRING device_name{};
    RtlInitUnicodeString(&device_name, configuration_.device_name.data());
    UNICODE_STRING sddl{};
    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    status = IoCreateDeviceSecure(driver_object_, 0, &device_name, protocol::device_type, FILE_DEVICE_SECURE_OPEN, FALSE, &sddl, &device_class_guid, &device_object_);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    device_object_->Flags |= DO_DIRECT_IO;
    device_object_->Flags &= ~DO_DEVICE_INITIALIZING;
    UNICODE_STRING link{};
    RtlInitUnicodeString(&link, configuration_.symbolic_link.data());
    status = IoCreateSymbolicLink(&link, &device_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device_object_);
        device_object_ = nullptr;
        return status;
    }
    link_created_ = true;
    for (auto& function : driver_object_->MajorFunction) {
        function = dispatch;
    }
    return STATUS_SUCCESS;
}

NTSTATUS Device::finalize(const protocol::Nonce& nonce) noexcept {
    ExAcquireFastMutex(&mutex_);
    bool nonce_matches = true;
    for (protocol::usize index = 0; index < nonce.size(); ++index) {
        nonce_matches = nonce_matches && nonce[index] == configuration_.header.nonce[index];
    }
    const auto state = session_.state();
    if (!nonce_matches || (state != protocol::SessionState::shutting_down && state != protocol::SessionState::created) || open_handles_ != 0 || active_requests_ != 0) {
        ExReleaseFastMutex(&mutex_);
        return STATUS_DEVICE_BUSY;
    }
    if (state == protocol::SessionState::shutting_down) {
        session_.stop();
    }
    snapshot_.detach();
    ExReleaseFastMutex(&mutex_);
    if (link_created_) {
        UNICODE_STRING link{};
        RtlInitUnicodeString(&link, configuration_.symbolic_link.data());
        IoDeleteSymbolicLink(&link);
        link_created_ = false;
    }
    if (device_object_) {
        IoDeleteDevice(device_object_);
        device_object_ = nullptr;
    }
    return STATUS_SUCCESS;
}

NTSTATUS Device::dispatch(PDEVICE_OBJECT, PIRP irp) noexcept {
    const auto stack = IoGetCurrentIrpStackLocation(irp);
    auto& self = instance();
    switch (stack->MajorFunction) {
    case IRP_MJ_CREATE: return self.handle_create(irp);
    case IRP_MJ_CLOSE: return self.handle_close(irp);
    case IRP_MJ_DEVICE_CONTROL: return self.handle_control(irp, stack);
    default: return complete(irp, STATUS_INVALID_DEVICE_REQUEST);
    }
}

NTSTATUS Device::handle_create(PIRP irp) noexcept {
    InterlockedIncrement(&open_handles_);
    return complete(irp, STATUS_SUCCESS);
}

NTSTATUS Device::handle_close(PIRP irp) noexcept {
    InterlockedDecrement(&open_handles_);
    return complete(irp, STATUS_SUCCESS);
}

bool Device::owned_file(PFILE_OBJECT file_object) const noexcept {
    return session_.owner() == reinterpret_cast<protocol::usize>(file_object);
}

NTSTATUS Device::handle_control(PIRP irp, PIO_STACK_LOCATION stack) noexcept {
    InterlockedIncrement(&active_requests_);
    const auto finish = [&](const NTSTATUS status, const ULONG_PTR information = 0) {
        InterlockedDecrement(&active_requests_);
        return complete(irp, status, information);
    };
    const auto code = stack->Parameters.DeviceIoControl.IoControlCode;
    ExAcquireFastMutex(&mutex_);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information{};
    if (code == protocol::ioctl_bind) {
        protocol::BindRequest* request{};
        if (buffered_request(stack, irp, request) && validation::validate_header(request->header, configuration_.header.nonce, sizeof(*request)) == Status::success) {
            status = native_status(session_.bind(reinterpret_cast<protocol::usize>(stack->FileObject)));
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
    } else if (!owned_file(stack->FileObject)) {
        status = STATUS_ACCESS_DENIED;
    } else if (code == protocol::ioctl_attach) {
        protocol::AttachRequest* request{};
        if (buffered_request(stack, irp, request) && stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(protocol::AttachResponse) && validation::validate_header(request->header, configuration_.header.nonce, sizeof(*request)) == Status::success && session_.accept_sequence(request->header.sequence) == Status::success) {
            const auto process_id = request->process_id;
            protocol::AttachResponse response{};
            status = snapshot_.attach(process_id, response);
            if (NT_SUCCESS(status)) {
                status = native_status(session_.attach(process_id, reinterpret_cast<protocol::usize>(snapshot_.process())));
                if (NT_SUCCESS(status)) {
                    RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &response, sizeof(response));
                    information = sizeof(response);
                }
            }
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
    } else if (code == protocol::ioctl_set_symbols) {
        protocol::SymbolPacket* request{};
        if (buffered_request(stack, irp, request) && validation::validate_header(request->header, configuration_.header.nonce, sizeof(*request)) == Status::success && session_.accept_sequence(request->header.sequence) == Status::success) {
            status = symbols_.set(*request, snapshot_.process());
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
    } else if (code == protocol::ioctl_query_region) {
        protocol::QueryRegionRequest* request{};
        if (buffered_request(stack, irp, request) && stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(protocol::QueryRegionResponse) && validation::validate_header(request->header, configuration_.header.nonce, sizeof(*request)) == Status::success && validation::validate_range(request->address, 1) == Status::success && session_.accept_sequence(request->header.sequence) == Status::success) {
            const auto address = request->address;
            protocol::QueryRegionResponse response{};
            status = snapshot_.query(address, response.region);
            response.native_status = status;
            RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &response, sizeof(response));
            information = sizeof(response);
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
    } else if (code == protocol::ioctl_read_memory) {
        protocol::ReadRequest* request{};
        if (buffered_request(stack, irp, request) && validation::validate_header(request->header, configuration_.header.nonce, sizeof(*request)) == Status::success && validation::validate_range(request->address, request->size) == Status::success && session_.accept_sequence(request->header.sequence) == Status::success && session_.validate_read(request->size) == Status::success) {
            const auto required = sizeof(protocol::ReadResponse) + request->size;
            auto* output = static_cast<unsigned char*>(direct_output(irp, required));
            if (output) {
                protocol::ReadResponse response{};
                response.address = request->address;
                response.requested = request->size;
                SIZE_T transferred{};
                status = snapshot_.read(request->address, output + sizeof(response), request->size, transferred);
                response.transferred = static_cast<protocol::u32>(transferred);
                response.native_status = status;
                RtlCopyMemory(output, &response, sizeof(response));
                information = sizeof(response) + transferred;
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
    } else if (code == protocol::ioctl_prepare_shutdown) {
        protocol::ShutdownRequest* request{};
        if (buffered_request(stack, irp, request) && validation::validate_header(request->header, configuration_.header.nonce, sizeof(*request)) == Status::success && session_.accept_sequence(request->header.sequence) == Status::success) {
            status = native_status(session_.prepare_shutdown(active_requests_ == 1 ? 0u : static_cast<protocol::u32>(active_requests_ - 1)));
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
    } else if (code == protocol::ioctl_query_sections) {
        protocol::SectionsRequest* request{};
        if (buffered_request(stack, irp, request) && stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(protocol::SectionsResponse) && validation::validate_header(request->header, configuration_.header.nonce, sizeof(*request)) == Status::success && session_.accept_sequence(request->header.sequence) == Status::success) {
            auto* output = static_cast<protocol::SectionsResponse*>(irp->AssociatedIrp.SystemBuffer);
            status = sections_.query(snapshot_, *output);
            if (!NT_SUCCESS(status)) {
                output->native_status = status;
            }
            information = sizeof(*output);
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
    } else if (code == protocol::ioctl_conceal) {
        protocol::ConcealRequest* request{};
        if (buffered_request(stack, irp, request) && stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(protocol::ConcealResponse) && validation::validate_header(request->header, configuration_.header.nonce, sizeof(*request)) == Status::success && session_.accept_sequence(request->header.sequence) == Status::success && session_.claim_conceal() == Status::success) {
            const protocol::ConcealTargets targets = request->targets;
            auto* output = static_cast<protocol::ConcealResponse*>(irp->AssociatedIrp.SystemBuffer);
            status = conceal_.apply(targets, *output);
            information = sizeof(*output);
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
    }
    ExReleaseFastMutex(&mutex_);
    return finish(status, information);
}

}
