#include "net_capture.hxx"

#define NOMINMAX
#include <WinSock2.h>
#include <Windows.h>
#include <iphlpapi.h>

#include <algorithm>
#include <cstddef>
#include <array>
#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>

namespace {

using namespace dump;

constexpr std::uint32_t sweep_budget = 4u * 1024u * 1024u;
constexpr std::uint32_t sweep_limit = 4096;
constexpr std::uint32_t poll_interval_ms = 500;

std::string escape_body(const char* data, const std::uint32_t length) {
    std::string result;
    result.reserve(length * 4);
    constexpr char digits[] = "0123456789abcdef";
    for (std::uint32_t index = 0; index < length; ++index) {
        const auto value = static_cast<unsigned char>(data[index]);
        if (value >= 0x20 && value <= 0x7e && value != '"' && value != '\\') {
            result.push_back(static_cast<char>(value));
            continue;
        }
        result.append("\\x");
        result.push_back(digits[(value >> 4) & 0xf]);
        result.push_back(digits[value & 0xf]);
    }
    return result;
}

std::string ascii(const std::wstring& text) {
    std::string result;
    result.reserve(text.size());
    for (const auto value : text) {
        result.push_back(static_cast<char>(value & 0xff));
    }
    return result;
}

std::string narrow(const char* data, const std::size_t maximum) {
    std::string result;
    for (std::size_t index = 0; index < maximum && data[index] != '\0'; ++index) {
        result.push_back(data[index]);
    }
    return result;
}

std::wstring widen(const std::string& text) {
    std::wstring result;
    result.reserve(text.size());
    for (const auto value : text) {
        result.push_back(static_cast<wchar_t>(static_cast<unsigned char>(value)));
    }
    return result;
}

std::string request_key(const protocol::HttpRecord& record) {
    std::string key = narrow(record.method.data(), protocol::http_method_size);
    key.push_back(' ');
    key.append(narrow(record.host.data(), protocol::http_host_size));
    key.append(narrow(record.target.data(), protocol::http_target_size));
    key.append(escape_body(record.body.data(), record.body_length));
    return key;
}

std::string endpoint_key(const std::uint32_t address, const std::uint32_t port) {
    char buffer[32]{};
    const auto* bytes = reinterpret_cast<const unsigned char*>(&address);
    std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u:%u", bytes[0], bytes[1], bytes[2], bytes[3], port);
    return buffer;
}

}

namespace dump {

std::wstring http_line(const protocol::HttpRecord& record) {
    std::string line = narrow(record.method.data(), protocol::http_method_size);
    const auto host = narrow(record.host.data(), protocol::http_host_size);
    const auto target = narrow(record.target.data(), protocol::http_target_size);
    const auto agent = narrow(record.agent.data(), protocol::http_agent_size);
    line.append(" host=");
    line.append(host.empty() ? "-" : host);
    line.append(" target=");
    line.append(target);
    if (!agent.empty()) {
        line.append(" agent=");
        line.append(agent);
    }
    line.append(" headers=");
    line.append(std::to_string(record.headers));
    if (record.body_length != 0) {
        line.append(" body=\"");
        line.append(escape_body(record.body.data(), record.body_length));
        line.push_back('"');
    }
    return widen(line);
}

std::wstring endpoint_line(const std::uint32_t remote_address, const std::uint32_t remote_port, const std::uint32_t state) {
    return widen(endpoint_key(remote_address, remote_port) + " state=" + std::to_string(state));
}

NetworkCapture::NetworkCapture(DriverClient& client, IConsole& console) noexcept : client_(client), console_(console) {}

NetworkCapture::~NetworkCapture() {
    if (log_.is_open()) {
        log_.close();
    }
}

Status NetworkCapture::sweep(const std::uint32_t process_id, NetCaptureStats& stats) noexcept {
    (void)process_id;
    std::uint64_t start{};
    for (std::uint32_t iteration = 0; iteration < sweep_limit; ++iteration) {
        auto response = client_.http_scan(start, sweep_budget, protocol::maximum_http_records);
        if (!response) {
            ++stats.failures;
            return response.status();
        }
        for (std::uint32_t index = 0; index < response.value().record_count; ++index) {
            const auto& record = response.value().records[index];
            if (!seen_.insert(request_key(record)).second) {
                continue;
            }
            const auto line = L"http " + http_line(record);
            console_.success(line);
            if (log_.is_open()) {
                log_ << "[+] " << ascii(line) << '\n';
            }
            ++stats.requests;
        }
        if (response.value().complete != 0) {
            break;
        }
        if (response.value().next_address <= start) {
            break;
        }
        start = response.value().next_address;
    }
    ++stats.sweeps;
    return Status::success;
}

Status NetworkCapture::endpoints(const std::uint32_t process_id, NetCaptureStats& stats) noexcept {
    DWORD size{};
    auto status = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (status != ERROR_INSUFFICIENT_BUFFER) {
        return Status::io_error;
    }
    std::vector<std::byte> buffer(size);
    status = GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (status != NO_ERROR) {
        return Status::io_error;
    }
    const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
    for (DWORD index = 0; index < table->dwNumEntries; ++index) {
        const auto& row = table->table[index];
        if (row.dwOwningPid != process_id || row.dwRemoteAddr == 0) {
            continue;
        }
        const auto key = endpoint_key(row.dwRemoteAddr, static_cast<std::uint32_t>(ntohs(static_cast<u_short>(row.dwRemotePort))));
        if (!seen_.insert("tcp " + key).second) {
            continue;
        }
        const auto line = L"tcp " + endpoint_line(row.dwRemoteAddr, static_cast<std::uint32_t>(ntohs(static_cast<u_short>(row.dwRemotePort))), row.dwState);
        console_.success(line);
        if (log_.is_open()) {
            log_ << "[+] " << ascii(line) << '\n';
        }
        ++stats.connections;
    }
    return Status::success;
}

Result<NetCaptureStats> NetworkCapture::run(const std::uint32_t process_id, const std::uint32_t seconds, const std::filesystem::path& log_path) noexcept {
    try {
        std::error_code ignored;
        std::filesystem::create_directories(log_path.parent_path(), ignored);
        log_.open(log_path, std::ios::binary | std::ios::trunc);
        if (!log_) {
            return Status::io_error;
        }
        const unsigned char bom[]{0xef, 0xbb, 0xbf};
        log_.write(reinterpret_cast<const char*>(bom), sizeof(bom));
        NetCaptureStats stats{};
        const auto duration = seconds == 0 ? 30u : seconds;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(duration);
        while (std::chrono::steady_clock::now() < deadline) {
            const auto sweep_status = sweep(process_id, stats);
            const auto endpoint_status = endpoints(process_id, stats);
            if (log_.is_open()) {
                log_ << "[~] sweep=" << stats.sweeps << " requests=" << stats.requests << " connections=" << stats.connections << " failures=" << stats.failures << '\n';
                log_.flush();
            }
            if (sweep_status != Status::success && endpoint_status != Status::success) {
                return stats;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(poll_interval_ms));
        }
        console_.success(L"capture requests=" + std::to_wstring(stats.requests) + L" connections=" + std::to_wstring(stats.connections) + L" sweeps=" + std::to_wstring(stats.sweeps));
        return stats;
    } catch (...) {
        return Status::io_error;
    }
}

}