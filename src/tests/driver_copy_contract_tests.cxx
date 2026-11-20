#include "test.hxx"

#define NOMINMAX
#include <Windows.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

namespace {

std::filesystem::path repository_root() {
    std::array<wchar_t, 32768> module_path{};
    const auto length = GetModuleFileNameW(nullptr, module_path.data(), static_cast<DWORD>(module_path.size()));
    REQUIRE(length != 0 && length < module_path.size());
    return std::filesystem::path(std::wstring(module_path.data(), length)).parent_path().parent_path().parent_path();
}

std::string source_text(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    REQUIRE(input.good());
    return std::string((std::istreambuf_iterator<char>(input)), {});
}

}

TEST_CASE("driver-contract", driver_copy_uses_fault_contained_documented_path) {
    const auto implementation = source_text(repository_root() / L"src" / L"driver" / L"process_snapshot.cxx");
    const auto declaration = source_text(repository_root() / L"src" / L"driver" / L"process_snapshot.hxx");

    REQUIRE(implementation.find("KeStackAttachProcess") != std::string::npos);
    REQUIRE(implementation.find("MmCopyMemory") != std::string::npos);
    REQUIRE(implementation.find("KeUnstackDetachProcess") != std::string::npos);
    REQUIRE(implementation.find("MmCopyVirtualMemory") == std::string::npos);
    REQUIRE(declaration.find("CopyVirtualMemory") == std::string::npos);
    REQUIRE(declaration.find("copy_virtual_memory_") == std::string::npos);
}

