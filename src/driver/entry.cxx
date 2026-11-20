#include "device.hxx"
#include "session_state.hxx"

#include <ntifs.h>

namespace {

dump::protocol::BootConfiguration boot_configuration;

NTSTATUS initialize_driver(PDRIVER_OBJECT driver_object, PUNICODE_STRING) {
    return dump::driver::Device::instance().initialize(driver_object, boot_configuration);
}

using IoCreateDriverFunction = NTSTATUS(NTAPI*)(PUNICODE_STRING, PDRIVER_INITIALIZE);

}

extern "C" NTSTATUS DriverEntry(void* parameter1, void*) {
    if (!parameter1) {
        return STATUS_INVALID_PARAMETER;
    }
    __try {
        ProbeForRead(parameter1, sizeof(boot_configuration), alignof(dump::protocol::BootConfiguration));
        RtlCopyMemory(&boot_configuration, parameter1, sizeof(boot_configuration));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    if (dump::driver::validate_boot_configuration(boot_configuration) != dump::Status::success) {
        return STATUS_INVALID_PARAMETER;
    }
    UNICODE_STRING routine_name{};
    RtlInitUnicodeString(&routine_name, L"IoCreateDriver");
    const auto create_driver = reinterpret_cast<IoCreateDriverFunction>(MmGetSystemRoutineAddress(&routine_name));
    if (!create_driver) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    UNICODE_STRING driver_name{};
    RtlInitUnicodeString(&driver_name, boot_configuration.driver_name.data());
    return create_driver(&driver_name, initialize_driver);
}

extern "C" __declspec(dllexport) NTSTATUS FinalizeDriver(void* parameter1, void*) {
    if (!parameter1) {
        return STATUS_INVALID_PARAMETER;
    }
    dump::protocol::Nonce nonce{};
    __try {
        ProbeForRead(parameter1, nonce.size(), 1);
        RtlCopyMemory(nonce.data(), parameter1, nonce.size());
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return dump::driver::Device::instance().finalize(nonce);
}
