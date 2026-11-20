#pragma once

#include <ntifs.h>

#include "shared/protocol.hxx"

namespace dump::driver {

class ProcessSnapshot {
public:
    NTSTATUS initialize() noexcept;
    NTSTATUS attach(protocol::u64 process_id, protocol::AttachResponse& response) noexcept;
    void detach() noexcept;
    NTSTATUS query(protocol::u64 address, protocol::RegionDescriptor& region) noexcept;
    NTSTATUS read(protocol::u64 address, void* destination, SIZE_T size, SIZE_T& transferred) noexcept;
    [[nodiscard]] PEPROCESS process() const noexcept;
    [[nodiscard]] protocol::u64 process_id() const noexcept;

private:
    using GetProcessPeb = PVOID(NTAPI*)(PEPROCESS);
    using GetProcessSectionBaseAddress = PVOID(NTAPI*)(PEPROCESS);
    using GetProcessImageFileName = const char*(NTAPI*)(PEPROCESS);

    PEPROCESS process_{};
    HANDLE process_handle_{};
    protocol::u64 process_id_{};
    GetProcessPeb get_process_peb_{};
    GetProcessSectionBaseAddress get_section_base_{};
    GetProcessImageFileName get_image_name_{};
};

}
