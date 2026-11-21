#include "session_state.hxx"

#include "shared/validation.hxx"

namespace {

template <dump::protocol::usize Size, dump::protocol::usize PrefixSize>
bool valid_name(const dump::protocol::FixedArray<dump::protocol::wide_char, Size>& value, const dump::protocol::wide_char (&prefix)[PrefixSize]) {
    dump::protocol::usize length{};
    while (length < Size && value[length] != 0) {
        ++length;
    }
    if (length == Size || length <= PrefixSize - 1) {
        return false;
    }
    for (dump::protocol::usize index = 0; index < PrefixSize - 1; ++index) {
        if (value[index] != prefix[index]) {
            return false;
        }
    }
    return true;
}

}

namespace dump::driver {

Status validate_boot_configuration(const protocol::BootConfiguration& configuration) noexcept {
    if (configuration.header.magic != protocol::magic || configuration.header.version != protocol::version || configuration.header.size != sizeof(configuration)) {
        return Status::invalid_argument;
    }
    bool all_zero = true;
    for (const auto value : configuration.header.nonce) {
        all_zero = all_zero && value == 0;
    }
    if (all_zero) {
        return Status::invalid_argument;
    }
    if (!valid_name(configuration.driver_name, L"\\Driver\\") || !valid_name(configuration.device_name, L"\\Device\\") || !valid_name(configuration.symbolic_link, L"\\DosDevices\\")) {
        return Status::invalid_argument;
    }
    return Status::success;
}

protocol::SessionState SessionState::state() const noexcept {
    return state_;
}

Status SessionState::bind(const protocol::usize file_object) noexcept {
    if (state_ == protocol::SessionState::created && file_object != 0) {
        owner_ = file_object;
        state_ = protocol::SessionState::bound;
        return Status::success;
    }
    return owner_ == file_object ? Status::success : Status::access_denied;
}

Status SessionState::attach(const protocol::u64 process_id, const protocol::usize process_object) noexcept {
    if (state_ != protocol::SessionState::bound || process_id == 0 || process_object == 0) {
        return Status::invalid_state;
    }
    process_id_ = process_id;
    process_object_ = process_object;
    state_ = protocol::SessionState::attached;
    return Status::success;
}

Status SessionState::begin_snapshot() noexcept {
    if (state_ != protocol::SessionState::attached) {
        return Status::invalid_state;
    }
    state_ = protocol::SessionState::snapshotting;
    return Status::success;
}

Status SessionState::end_snapshot() noexcept {
    if (state_ != protocol::SessionState::snapshotting) {
        return Status::invalid_state;
    }
    state_ = protocol::SessionState::attached;
    return Status::success;
}

Status SessionState::prepare_shutdown(const protocol::u32 active_rundown) noexcept {
    if (state_ == protocol::SessionState::snapshotting || state_ == protocol::SessionState::shutting_down || state_ == protocol::SessionState::stopped || active_rundown != 0) {
        return Status::invalid_state;
    }
    state_ = protocol::SessionState::shutting_down;
    return Status::success;
}

Status SessionState::claim_conceal() noexcept {
    if (state_ != protocol::SessionState::attached || concealed_) {
        return Status::invalid_state;
    }
    concealed_ = true;
    return Status::success;
}

Status SessionState::stop() noexcept {
    if (state_ != protocol::SessionState::shutting_down) {
        return Status::invalid_state;
    }
    state_ = protocol::SessionState::stopped;
    return Status::success;
}

Status SessionState::validate_process(const protocol::u64 process_id, const protocol::usize process_object) const noexcept {
    return process_id == process_id_ && process_object == process_object_ ? Status::success : Status::process_exited;
}

Status SessionState::accept_sequence(const protocol::u64 sequence) noexcept {
    const auto status = validation::validate_sequence(sequence, last_sequence_);
    if (status == Status::success) {
        last_sequence_ = sequence;
    }
    return status;
}

Status SessionState::validate_read(const protocol::u64 size) const noexcept {
    return size != 0 && size <= protocol::maximum_transfer ? Status::success : Status::invalid_argument;
}

protocol::usize SessionState::owner() const noexcept {
    return owner_;
}

protocol::u64 SessionState::process_id() const noexcept {
    return process_id_;
}

protocol::usize SessionState::process_object() const noexcept {
    return process_object_;
}

}
