#include "process_locator.hxx"

#define NOMINMAX
#include <Windows.h>
#include <TlHelp32.h>

#include <algorithm>
#include <cwctype>

namespace {

bool equal_insensitive(const std::wstring_view left, const std::wstring_view right) {
    return left.size() == right.size() && std::equal(left.begin(), left.end(), right.begin(), [](const wchar_t a, const wchar_t b) { return std::towlower(a) == std::towlower(b); });
}

}

namespace dump {

Result<std::vector<ProcessInfo>> ProcessLocator::enumerate() noexcept {
    const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return Status::io_error;
    }
    std::vector<ProcessInfo> processes;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            processes.push_back(ProcessInfo{entry.th32ProcessID, entry.szExeFile});
        } while (Process32NextW(snapshot, &entry));
    }
    const auto error = GetLastError();
    CloseHandle(snapshot);
    if (processes.empty() && error != ERROR_NO_MORE_FILES) {
        return Status::io_error;
    }
    return processes;
}

Result<ProcessInfo> ProcessLocator::select(const std::span<const ProcessInfo> processes, const std::optional<std::uint32_t> process_id, const std::wstring_view name) noexcept {
    if (process_id) {
        const auto found = std::find_if(processes.begin(), processes.end(), [&](const auto& process) { return process.process_id == *process_id; });
        return found == processes.end() ? Result<ProcessInfo>(Status::process_not_found) : Result<ProcessInfo>(*found);
    }
    if (name.empty()) {
        return Status::invalid_argument;
    }
    std::optional<ProcessInfo> selected;
    std::size_t matches{};
    for (const auto& process : processes) {
        if (!equal_insensitive(process.name, name)) {
            continue;
        }
        ++matches;
        if (!selected || process.process_id > selected->process_id) selected = process;
    }
    if (selected) selected->match_count = matches;
    return selected ? Result<ProcessInfo>(*selected) : Result<ProcessInfo>(Status::process_not_found);
}

Result<ProcessInfo> ProcessLocator::find(const std::optional<std::uint32_t> process_id, const std::wstring_view name) noexcept {
    auto processes = enumerate();
    if (!processes) {
        return processes.status();
    }
    return select(processes.value(), process_id, name);
}

}
