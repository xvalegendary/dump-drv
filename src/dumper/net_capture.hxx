#pragma once

#include "console.hxx"
#include "driver_client.hxx"
#include "shared/protocol.hxx"
#include "shared/status.hxx"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>

namespace dump {

struct NetCaptureStats {
    std::uint32_t sweeps{};
    std::uint32_t requests{};
    std::uint32_t connections{};
    std::uint32_t failures{};
};

std::wstring http_line(const protocol::HttpRecord& record);
std::wstring endpoint_line(std::uint32_t remote_address, std::uint32_t remote_port, std::uint32_t state);

class NetworkCapture {
public:
    NetworkCapture(DriverClient& client, IConsole& console) noexcept;
    ~NetworkCapture();

    Result<NetCaptureStats> run(std::uint32_t process_id, std::uint32_t seconds, const std::filesystem::path& log_path) noexcept;

private:
    Status sweep(std::uint32_t process_id, NetCaptureStats& stats) noexcept;
    Status endpoints(std::uint32_t process_id, NetCaptureStats& stats) noexcept;

    DriverClient& client_;
    IConsole& console_;
    std::ofstream log_;
    std::set<std::string> seen_;
};

}