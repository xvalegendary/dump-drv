#include "driver_client.hxx"

#include "shared/validation.hxx"

#define NOMINMAX
#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <limits>

namespace {

dump::Status last_error_status() {
    switch (GetLastError()) {
    case ERROR_ACCESS_DENIED: return dump::Status::access_denied;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND: return dump::Status::driver_failure;
    case ERROR_PARTIAL_COPY: return dump::Status::partial_copy;
    default: return dump::Status::io_error;
    }
}

HANDLE native_handle(void* value) {
    return static_cast<HANDLE>(value);
}

}

namespace dump {

DriverClient::DriverClient(std::wstring path, const protocol::Nonce nonce) noexcept : path_(std::move(path)), nonce_(nonce) {}

DriverClient::~DriverClient() {
    close();
}

Status DriverClient::bind() {
    if (bound_ || native_handle(handle_) != INVALID_HANDLE_VALUE) {
        return Status::invalid_state;
    }
    handle_ = CreateFileW(path_.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (native_handle(handle_) == INVALID_HANDLE_VALUE) {
        return last_error_status();
    }
    protocol::BindRequest request{};
    prepare(request, false);
    request.client_process_id = GetCurrentProcessId();
    DWORD returned{};
    if (!DeviceIoControl(native_handle(handle_), protocol::ioctl_bind, &request, sizeof(request), nullptr, 0, &returned, nullptr)) {
        const auto status = last_error_status();
        close();
        return status;
    }
    bound_ = true;
    return Status::success;
}

Result<protocol::AttachResponse> DriverClient::attach(const std::uint32_t process_id) noexcept {
    if (!bound_ || shutting_down_ || process_id == 0) {
        return Status::invalid_state;
    }
    protocol::AttachRequest request{};
    prepare(request, true);
    request.process_id = process_id;
    protocol::AttachResponse response{};
    DWORD returned{};
    if (!DeviceIoControl(native_handle(handle_), protocol::ioctl_attach, &request, sizeof(request), &response, sizeof(response), &returned, nullptr) || returned != sizeof(response)) {
        return last_error_status();
    }
    return response;
}

Status DriverClient::set_symbols(protocol::SymbolPacket packet) noexcept {
    if (!bound_ || shutting_down_) {
        return Status::invalid_state;
    }
    prepare(packet, true);
    DWORD returned{};
    if (!DeviceIoControl(native_handle(handle_), protocol::ioctl_set_symbols, &packet, sizeof(packet), nullptr, 0, &returned, nullptr)) {
        return last_error_status();
    }
    return Status::success;
}

Result<protocol::QueryRegionResponse> DriverClient::query_region(const std::uint64_t address) noexcept {
    if (!bound_ || shutting_down_) {
        return Status::invalid_state;
    }
    protocol::QueryRegionRequest request{};
    prepare(request, true);
    request.address = address;
    protocol::QueryRegionResponse response{};
    DWORD returned{};
    const auto success = DeviceIoControl(native_handle(handle_), protocol::ioctl_query_region, &request, sizeof(request), &response, sizeof(response), &returned, nullptr);
    if (!success && returned != sizeof(response)) {
        return last_error_status();
    }
    if (returned != sizeof(response) || response.region.size == 0) {
        return Status::io_error;
    }
    return response;
}

Result<ReadChunk> DriverClient::read_memory(const std::uint64_t address, const std::uint32_t size) noexcept {
    if (!bound_ || shutting_down_ || size == 0 || size > protocol::maximum_transfer || address > std::numeric_limits<std::uint64_t>::max() - size) {
        return Status::invalid_argument;
    }
    protocol::ReadRequest request{};
    prepare(request, true);
    request.address = address;
    request.size = size;
    std::vector<std::byte> output(sizeof(protocol::ReadResponse) + size);
    DWORD returned{};
    const auto success = DeviceIoControl(native_handle(handle_), protocol::ioctl_read_memory, &request, sizeof(request), output.data(), static_cast<DWORD>(output.size()), &returned, nullptr);
    if (!success && returned < sizeof(protocol::ReadResponse)) {
        return last_error_status();
    }
    if (returned < sizeof(protocol::ReadResponse)) {
        return Status::io_error;
    }
    protocol::ReadResponse response{};
    std::memcpy(&response, output.data(), sizeof(response));
    if (response.address != address || response.requested != size || response.transferred > size || returned != sizeof(response) + response.transferred) {
        return Status::validation_failure;
    }
    ReadChunk result{};
    result.address = address;
    result.requested = size;
    result.native_status = response.native_status;
    result.bytes.assign(output.begin() + sizeof(response), output.begin() + returned);
    return result;
}

Result<protocol::SectionsResponse> DriverClient::query_sections() noexcept {
    if (!bound_ || shutting_down_) {
        return Status::invalid_state;
    }
    protocol::SectionsRequest request{};
    prepare(request, true);
    protocol::SectionsResponse response{};
    DWORD returned{};
    if (!DeviceIoControl(native_handle(handle_), protocol::ioctl_query_sections, &request, sizeof(request), &response, sizeof(response), &returned, nullptr)) {
        return last_error_status();
    }
    if (returned < sizeof(response)) {
        return Status::validation_failure;
    }
    if (validation::validate_sections(response) != Status::success) {
        return Status::validation_failure;
    }
    return response;
}

Result<protocol::ConcealResponse> DriverClient::conceal(const protocol::ConcealTargets& targets) noexcept {
    if (!bound_ || shutting_down_) {
        return Status::invalid_state;
    }
    protocol::ConcealRequest request{};
    prepare(request, true);
    request.targets = targets;
    protocol::ConcealResponse response{};
    DWORD returned{};
    if (!DeviceIoControl(native_handle(handle_), protocol::ioctl_conceal, &request, sizeof(request), &response, sizeof(response), &returned, nullptr)) {
        return last_error_status();
    }
    if (returned < sizeof(response)) {
        return Status::validation_failure;
    }
    return response;
}

Status DriverClient::prepare_shutdown() {
    if (!bound_ || shutting_down_) {
        return Status::invalid_state;
    }
    protocol::ShutdownRequest request{};
    prepare(request, true);
    DWORD returned{};
    if (!DeviceIoControl(native_handle(handle_), protocol::ioctl_prepare_shutdown, &request, sizeof(request), nullptr, 0, &returned, nullptr)) {
        return last_error_status();
    }
    shutting_down_ = true;
    bound_ = false;
    return close();
}

Status DriverClient::close() noexcept {
    if (native_handle(handle_) == INVALID_HANDLE_VALUE) {
        return Status::success;
    }
    const auto success = CloseHandle(native_handle(handle_));
    handle_ = INVALID_HANDLE_VALUE;
    bound_ = false;
    return success ? Status::success : Status::io_error;
}

}
