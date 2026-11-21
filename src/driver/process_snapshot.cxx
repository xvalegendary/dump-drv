#include "process_snapshot.hxx"

namespace {

template <typename Function>
Function resolve(const wchar_t* name) {
    UNICODE_STRING value{};
    RtlInitUnicodeString(&value, name);
    return reinterpret_cast<Function>(MmGetSystemRoutineAddress(&value));
}

}

namespace dump::driver {

NTSTATUS ProcessSnapshot::initialize() noexcept {
    get_process_peb_ = resolve<GetProcessPeb>(L"PsGetProcessPeb");
    get_section_base_ = resolve<GetProcessSectionBaseAddress>(L"PsGetProcessSectionBaseAddress");
    get_image_name_ = resolve<GetProcessImageFileName>(L"PsGetProcessImageFileName");
    return STATUS_SUCCESS;
}

NTSTATUS ProcessSnapshot::attach(const protocol::u64 process_id, protocol::AttachResponse& response) noexcept {
    detach();
    PEPROCESS process{};
    auto status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(process_id), &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    HANDLE handle{};
    status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, nullptr, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &handle);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        return status;
    }
    process_ = process;
    process_handle_ = handle;
    process_id_ = process_id;
    response.process_id = process_id;
    response.eprocess = reinterpret_cast<protocol::u64>(process);
    response.peb = get_process_peb_ ? reinterpret_cast<protocol::u64>(get_process_peb_(process)) : 0;
    response.image_base = get_section_base_ ? reinterpret_cast<protocol::u64>(get_section_base_(process)) : 0;
    image_base_ = response.image_base;
    if (get_image_name_) {
        const auto* name = get_image_name_(process);
        if (name) {
            SIZE_T length{};
            while (name[length] != '\0' && length + 1 < response.image_name.size()) {
                ++length;
            }
            RtlCopyMemory(response.image_name.data(), name, length);
        }
    }
    return STATUS_SUCCESS;
}

void ProcessSnapshot::detach() noexcept {
    if (process_handle_) {
        ZwClose(process_handle_);
        process_handle_ = nullptr;
    }
    if (process_) {
        ObDereferenceObject(process_);
        process_ = nullptr;
    }
    process_id_ = 0;
    image_base_ = 0;
}

NTSTATUS ProcessSnapshot::query(const protocol::u64 address, protocol::RegionDescriptor& region) noexcept {
    if (!process_handle_) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    MEMORY_BASIC_INFORMATION information{};
    SIZE_T returned{};
    const auto status = ZwQueryVirtualMemory(process_handle_, reinterpret_cast<PVOID>(address), MemoryBasicInformation, &information, sizeof(information), &returned);
    if (NT_SUCCESS(status)) {
        region.base = reinterpret_cast<protocol::u64>(information.BaseAddress);
        region.allocation_base = reinterpret_cast<protocol::u64>(information.AllocationBase);
        region.size = information.RegionSize;
        region.allocation_protect = information.AllocationProtect;
        region.protect = information.Protect;
        region.state = static_cast<protocol::RegionState>(information.State);
        region.type = static_cast<protocol::RegionType>(information.Type);
    }
    return status;
}

NTSTATUS ProcessSnapshot::read(const protocol::u64 address, void* destination, const SIZE_T size, SIZE_T& transferred) noexcept {
    transferred = 0;
    if (!process_ || !destination || size == 0 || size > protocol::maximum_transfer) {
        return STATUS_INVALID_PARAMETER;
    }

    KAPC_STATE state{};
    KeStackAttachProcess(process_, &state);
    MM_COPY_ADDRESS source{};
    source.VirtualAddress = reinterpret_cast<PVOID>(address);
    SIZE_T copied{};
    const auto status = MmCopyMemory(destination, source, size, MM_COPY_MEMORY_VIRTUAL, &copied);
    KeUnstackDetachProcess(&state);
    transferred = copied;
    return status;
}

PEPROCESS ProcessSnapshot::process() const noexcept {
    return process_;
}

protocol::u64 ProcessSnapshot::process_id() const noexcept {
    return process_id_;
}

protocol::u64 ProcessSnapshot::image_base() const noexcept {
    return image_base_;
}

}
