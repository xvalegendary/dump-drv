#pragma once

#include <ntifs.h>

#include "conceal.hxx"
#include "image_sections.hxx"
#include "process_snapshot.hxx"
#include "session_state.hxx"
#include "symbol_table.hxx"

namespace dump::driver {

class Device {
public:
    NTSTATUS initialize(PDRIVER_OBJECT driver_object, const protocol::BootConfiguration& configuration) noexcept;
    NTSTATUS finalize(const protocol::Nonce& nonce) noexcept;
    static NTSTATUS dispatch(PDEVICE_OBJECT device_object, PIRP irp) noexcept;
    static Device& instance() noexcept;

private:
    NTSTATUS handle_create(PIRP irp) noexcept;
    NTSTATUS handle_close(PIRP irp) noexcept;
    NTSTATUS handle_control(PIRP irp, PIO_STACK_LOCATION stack) noexcept;
    bool owned_file(PFILE_OBJECT file_object) const noexcept;

    PDRIVER_OBJECT driver_object_{};
    PDEVICE_OBJECT device_object_{};
    protocol::BootConfiguration configuration_{};
    SessionState session_{};
    ProcessSnapshot snapshot_{};
    SymbolTable symbols_{};
    ImageSections sections_{};
    Conceal conceal_{};
    FAST_MUTEX mutex_{};
    volatile LONG open_handles_{};
    volatile LONG active_requests_{};
    bool link_created_{};
};

}