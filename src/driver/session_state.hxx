#pragma once

#ifdef _KERNEL_MODE
#include <ntifs.h>
#endif

#include "shared/protocol.hxx"
#include "shared/status.hxx"

namespace dump::driver {

Status validate_boot_configuration(const protocol::BootConfiguration& configuration) noexcept;

class SessionState {
public:
    [[nodiscard]] protocol::SessionState state() const noexcept;
    Status bind(protocol::usize file_object) noexcept;
    Status attach(protocol::u64 process_id, protocol::usize process_object) noexcept;
    Status begin_snapshot() noexcept;
    Status end_snapshot() noexcept;
    Status prepare_shutdown(protocol::u32 active_rundown) noexcept;
    Status claim_conceal() noexcept;
    Status stop() noexcept;
    Status validate_process(protocol::u64 process_id, protocol::usize process_object) const noexcept;
    Status accept_sequence(protocol::u64 sequence) noexcept;
    Status validate_read(protocol::u64 size) const noexcept;
    [[nodiscard]] protocol::usize owner() const noexcept;
    [[nodiscard]] protocol::u64 process_id() const noexcept;
    [[nodiscard]] protocol::usize process_object() const noexcept;

private:
    protocol::SessionState state_{protocol::SessionState::created};
    protocol::usize owner_{};
    protocol::u64 process_id_{};
    protocol::usize process_object_{};
    protocol::u64 last_sequence_{};
    bool concealed_{};
};

}
