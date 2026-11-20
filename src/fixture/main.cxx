#define NOMINMAX
#include <Windows.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>

namespace {

constexpr std::array<char, 32> private_marker_one{"PRIVATE_READABLE_MARKER_ONE_01"};
constexpr std::array<char, 32> private_marker_two{"PRIVATE_READABLE_MARKER_TWO_02"};
constexpr std::array<char, 32> mapped_marker{"MAPPED_READABLE_MARKER_VALUE_03"};

struct Regions {
    void* private_one{};
    void* private_two{};
    void* mapped{};
    void* guard{};
    void* noaccess{};
    HANDLE section{};
};

bool allocate(Regions& regions) {
    regions.private_one = VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    regions.private_two = VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    regions.section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 0x10000, nullptr);
    regions.mapped = regions.section ? MapViewOfFile(regions.section, FILE_MAP_ALL_ACCESS, 0, 0, 0x10000) : nullptr;
    regions.guard = VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    regions.noaccess = VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    if (!regions.private_one || !regions.private_two || !regions.section || !regions.mapped || !regions.guard || !regions.noaccess) return false;
    std::memcpy(regions.private_one, private_marker_one.data(), private_marker_one.size());
    std::memcpy(regions.private_two, private_marker_two.data(), private_marker_two.size());
    std::memcpy(regions.mapped, mapped_marker.data(), mapped_marker.size());
    DWORD previous{};
    return VirtualProtect(regions.guard, 0x10000, PAGE_READWRITE | PAGE_GUARD, &previous) != FALSE;
}

void release(Regions& regions) {
    if (regions.mapped) UnmapViewOfFile(regions.mapped);
    if (regions.section) CloseHandle(regions.section);
    if (regions.private_one) VirtualFree(regions.private_one, 0, MEM_RELEASE);
    if (regions.private_two) VirtualFree(regions.private_two, 0, MEM_RELEASE);
    if (regions.guard) VirtualFree(regions.guard, 0, MEM_RELEASE);
    if (regions.noaccess) VirtualFree(regions.noaccess, 0, MEM_RELEASE);
}

bool validate(void* address, const DWORD type, const DWORD protection) {
    MEMORY_BASIC_INFORMATION information{};
    return VirtualQuery(address, &information, sizeof(information)) == sizeof(information) && information.State == MEM_COMMIT && information.Type == type && (information.Protect & protection) == protection;
}

void print_address(const wchar_t* name, const void* value) {
    std::wcout << L"[+] " << name << L"=0x" << std::hex << reinterpret_cast<std::uintptr_t>(value) << std::dec << L'\n';
}

}

int wmain(const int argc, wchar_t** argv) {
    if (argc == 3 && std::wstring_view(argv[1]) == L"--release") {
        const auto name = L"Local\\DumpDriverFixture-" + std::wstring(argv[2]);
        const auto event = OpenEventW(EVENT_MODIFY_STATE, FALSE, name.c_str());
        if (!event) return 2;
        const auto result = SetEvent(event);
        CloseHandle(event);
        return result ? 0 : 3;
    }
    Regions regions{};
    if (!allocate(regions)) {
        release(regions);
        std::wcerr << L"[-] allocation failed\n";
        return 1;
    }
    const auto valid = validate(regions.private_one, MEM_PRIVATE, PAGE_READWRITE) &&
        validate(regions.private_two, MEM_PRIVATE, PAGE_READWRITE) &&
        validate(regions.mapped, MEM_MAPPED, PAGE_READWRITE) &&
        validate(regions.guard, MEM_PRIVATE, PAGE_GUARD) &&
        validate(regions.noaccess, MEM_PRIVATE, PAGE_NOACCESS);
    if (!valid) {
        release(regions);
        std::wcerr << L"[-] layout validation failed\n";
        return 2;
    }
    const auto process_id = GetCurrentProcessId();
    const auto event_name = L"Local\\DumpDriverFixture-" + std::to_wstring(process_id);
    const auto event = CreateEventW(nullptr, TRUE, FALSE, event_name.c_str());
    if (!event) {
        release(regions);
        return 3;
    }
    std::wcout << L"[+] pid=" << process_id << L'\n';
    print_address(L"image", GetModuleHandleW(nullptr));
    print_address(L"mapped", regions.mapped);
    print_address(L"private_one", regions.private_one);
    print_address(L"private_two", regions.private_two);
    print_address(L"guard", regions.guard);
    print_address(L"noaccess", regions.noaccess);
    std::wcout << L"[+] marker_one=" << private_marker_one.data() << L'\n';
    std::wcout << L"[+] marker_two=" << private_marker_two.data() << L'\n';
    std::wcout << L"[+] mapped_marker=" << mapped_marker.data() << L'\n';
    std::wcout << L"[+] event=" << event_name << L'\n' << std::flush;
    if (argc != 2 || std::wstring_view(argv[1]) != L"--probe") WaitForSingleObject(event, INFINITE);
    CloseHandle(event);
    release(regions);
    return 0;
}
