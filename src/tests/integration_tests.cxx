#include "test.hxx"

#define NOMINMAX
#include <Windows.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace {

std::wstring exe_path(const wchar_t* name) {
    std::array<wchar_t, 32768> module_path{};
    const auto length = GetModuleFileNameW(nullptr, module_path.data(), static_cast<DWORD>(module_path.size()));
    REQUIRE(length != 0 && length < module_path.size());
    const auto directory = std::filesystem::path(std::wstring(module_path.data(), length)).parent_path();
    return (directory / name).wstring();
}

std::string file_text(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(input)), {});
}

bool hex_digit(const char value) {
    return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F');
}

std::string hex_after(const std::string& text, const std::string& key) {
    const auto position = text.find(key);
    if (position == std::string::npos) return {};
    std::string value;
    for (std::size_t index = position + key.size(); index < text.size() && hex_digit(text[index]); ++index) {
        value.push_back(text[index]);
    }
    return value;
}

struct ProcessGuard {
    ~ProcessGuard() {
        if (event) SetEvent(event);
        if (handle) {
            WaitForSingleObject(handle, 15000);
            CloseHandle(handle);
        }
        if (event) CloseHandle(event);
        if (write_end) CloseHandle(write_end);
        if (read_end) CloseHandle(read_end);
    }
    void* handle{};
    void* event{};
    void* read_end{};
    void* write_end{};
    DWORD process_id{};
    std::string fixture_text{};
};

void* open_output(const std::filesystem::path& path) {
    SECURITY_ATTRIBUTES inherit{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    return CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &inherit, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
}

bool launch(const std::wstring& exe, const std::wstring& arguments, void* output_handle, ProcessGuard& process) {
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = output_handle;
    startup.hStdError = output_handle;
    std::wstring command = L"\"" + exe + L"\"" + arguments;
    PROCESS_INFORMATION information{};
    if (!CreateProcessW(nullptr, command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &information)) {
        return false;
    }
    CloseHandle(information.hThread);
    process.handle = information.hProcess;
    process.process_id = information.dwProcessId;
    return true;
}

void capture_fixture(ProcessGuard& process) {
    std::string text;
    char chunk[4096]{};
    DWORD received{};
    while (ReadFile(process.read_end, chunk, sizeof(chunk), &received, nullptr) && received != 0) {
        text.append(chunk, received);
        if (text.find("[+] event=") != std::string::npos) {
            break;
        }
    }
    REQUIRE(text.find("[+] pid=") != std::string::npos);
    const auto pid = hex_after(text, "[+] pid=");
    REQUIRE(!pid.empty());
    process.process_id = static_cast<DWORD>(std::strtoul(pid.c_str(), nullptr, 10));
    const auto event_name = L"Local\\DumpDriverFixture-" + std::to_wstring(process.process_id);
    process.event = OpenEventW(EVENT_MODIFY_STATE, FALSE, event_name.c_str());
    REQUIRE(process.event != nullptr);
    REQUIRE(text.find("[+] image=0x") != std::string::npos);
    REQUIRE(text.find("[+] mapped=0x") != std::string::npos);
    REQUIRE(text.find("[+] private_one=0x") != std::string::npos);
    REQUIRE(text.find("[+] private_two=0x") != std::string::npos);
    REQUIRE(text.find("[+] guard=0x") != std::string::npos);
    REQUIRE(text.find("[+] noaccess=0x") != std::string::npos);
    REQUIRE(text.find("PRIVATE_READABLE_MARKER_ONE_01") != std::string::npos);
    REQUIRE(text.find("PRIVATE_READABLE_MARKER_TWO_02") != std::string::npos);
    REQUIRE(text.find("MAPPED_READABLE_MARKER_VALUE_03") != std::string::npos);
    process.fixture_text = text;
}

}

TEST_CASE("integration", integration_fixture_exposes_required_region_matrix) {
    const auto fixture = exe_path(L"Fixture.exe");
    REQUIRE(std::filesystem::exists(fixture));
    const auto output = std::filesystem::temp_directory_path() / L"dump-driver-fixture-probe.txt";
    const auto handle = open_output(output);
    REQUIRE(handle != INVALID_HANDLE_VALUE);
    {
        ProcessGuard process;
        REQUIRE(launch(fixture, L" --probe", handle, process));
        REQUIRE(WaitForSingleObject(process.handle, 30000) == WAIT_OBJECT_0);
    }
    CloseHandle(handle);
    const std::string text = file_text(output);
    REQUIRE(text.find("[+] image=0x") != std::string::npos);
    REQUIRE(text.find("[+] mapped=0x") != std::string::npos);
    REQUIRE(text.find("[+] private_one=0x") != std::string::npos);
    REQUIRE(text.find("[+] private_two=0x") != std::string::npos);
    REQUIRE(text.find("[+] guard=0x") != std::string::npos);
    REQUIRE(text.find("[+] noaccess=0x") != std::string::npos);
    REQUIRE(text.find("PRIVATE_READABLE_MARKER_ONE_01") != std::string::npos);
    REQUIRE(text.find("PRIVATE_READABLE_MARKER_TWO_02") != std::string::npos);
    REQUIRE(text.find("MAPPED_READABLE_MARKER_VALUE_03") != std::string::npos);
    std::filesystem::remove(output);
}

TEST_CASE("integration", integration_dumper_captures_fixture_markers) {
    const auto fixture = exe_path(L"Fixture.exe");
    const auto dumper = exe_path(L"Dumper.exe");
    REQUIRE(std::filesystem::exists(fixture));
    REQUIRE(std::filesystem::exists(dumper));
    const auto output_directory = std::filesystem::temp_directory_path() / L"dump-driver-integration";
    std::error_code ignored;
    std::filesystem::remove_all(output_directory, ignored);
    std::filesystem::create_directories(output_directory);
    const auto report = output_directory / L"dumper-run.txt";
    {
        ProcessGuard fixture_process;
        {
            SECURITY_ATTRIBUTES inherit{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
            REQUIRE(CreatePipe(&fixture_process.read_end, &fixture_process.write_end, &inherit, 0) != FALSE);
            REQUIRE(SetHandleInformation(fixture_process.read_end, HANDLE_FLAG_INHERIT, 0) != FALSE);
        }
        REQUIRE(launch(fixture, L"", fixture_process.write_end, fixture_process));
        capture_fixture(fixture_process);
        const auto report_handle = open_output(report);
        REQUIRE(report_handle != INVALID_HANDLE_VALUE);
        ProcessGuard dumper_process;
        const auto launched = launch(dumper, L" --no-pause --pid " + std::to_wstring(fixture_process.process_id) + L" --output \"" + output_directory.wstring() + L"\"", report_handle, dumper_process);
        CloseHandle(report_handle);
        if (!launched) {
            REQUIRE(GetLastError() == ERROR_ELEVATION_REQUIRED);
            std::filesystem::remove_all(output_directory, ignored);
            return;
        }
        REQUIRE(WaitForSingleObject(dumper_process.handle, 120000) == WAIT_OBJECT_0);
        DWORD exit_code{};
        REQUIRE(GetExitCodeProcess(dumper_process.handle, &exit_code) != FALSE);
        REQUIRE(exit_code == 0 || exit_code == 3);
        if (exit_code == 3) {
            const std::string output = file_text(report);
            REQUIRE(output.find("administrator token required") != std::string::npos);
            std::filesystem::remove_all(output_directory, ignored);
            return;
        }
        const std::string output = file_text(report);
        REQUIRE(output.find("[+] driver loaded") != std::string::npos);
        std::vector<std::filesystem::path> dumps;
        std::vector<std::filesystem::path> manifests;
        for (const auto& entry : std::filesystem::directory_iterator(output_directory)) {
            if (entry.path().extension() == L".dmp") dumps.push_back(entry.path());
            if (entry.path().extension() == L".txt") manifests.push_back(entry.path());
        }
        REQUIRE(dumps.size() == 1);
        REQUIRE(manifests.size() == 1);
        const std::string dump = file_text(dumps.front());
        REQUIRE(dump.find("PRIVATE_READABLE_MARKER_ONE_01") != std::string::npos);
        REQUIRE(dump.find("PRIVATE_READABLE_MARKER_TWO_02") != std::string::npos);
        REQUIRE(dump.find("MAPPED_READABLE_MARKER_VALUE_03") != std::string::npos);
        const std::string manifest = file_text(manifests.front());
        REQUIRE(manifest.find("eprocess=0x") != std::string::npos);
        REQUIRE(manifest.find("sha256=") != std::string::npos);
        REQUIRE(manifest.find("type=0x1000000") != std::string::npos);
        REQUIRE(manifest.find("type=0x40000") != std::string::npos);
        for (const auto& key : {"[+] image=0x", "[+] mapped=0x", "[+] private_one=0x", "[+] private_two=0x", "[+] guard=0x", "[+] noaccess=0x"}) {
            const auto address = hex_after(fixture_process.fixture_text, key);
            REQUIRE(!address.empty());
            REQUIRE(manifest.find("base=0x" + address) != std::string::npos);
        }
        REQUIRE(manifest.find("protect=0x1 copied=0x0") != std::string::npos);
        REQUIRE(manifest.find("protect=0x104 copied=0x0") != std::string::npos);
    }
    std::filesystem::remove_all(output_directory, ignored);
}
