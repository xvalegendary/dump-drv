#include "mapper.hxx"

#include <algorithm>
#include <cstring>
#include <limits>

#ifndef DUMP_MAPPER_CONTRACT_ONLY
#define NOMINMAX
#include <Windows.h>
#include <intel_driver.hpp>
#include <kdmapper.hpp>
#endif

namespace {

#ifndef DUMP_MAPPER_CONTRACT_ONLY
const std::byte* rva_pointer(const std::span<const std::byte> image, const IMAGE_NT_HEADERS64& nt, const std::uint32_t rva, const std::size_t required) {
    if (rva < nt.OptionalHeader.SizeOfHeaders && rva <= image.size() && required <= image.size() - rva) {
        return image.data() + rva;
    }
    const auto* section = IMAGE_FIRST_SECTION(&nt);
    for (std::uint16_t index = 0; index < nt.FileHeader.NumberOfSections; ++index) {
        const auto span = (std::max)(section[index].Misc.VirtualSize, section[index].SizeOfRawData);
        if (rva >= section[index].VirtualAddress && rva < section[index].VirtualAddress + span) {
            const auto offset = static_cast<std::size_t>(section[index].PointerToRawData) + rva - section[index].VirtualAddress;
            if (offset <= image.size() && required <= image.size() - offset) {
                return image.data() + offset;
            }
        }
    }
    return nullptr;
}

std::uint32_t export_rva(const std::span<const std::byte> image, const char* name) {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) {
        return 0;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 || static_cast<std::size_t>(dos->e_lfanew) > image.size() - sizeof(IMAGE_NT_HEADERS64)) {
        return 0;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return 0;
    }
    const auto directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    const auto* raw_exports = rva_pointer(image, *nt, directory.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY));
    if (!raw_exports) {
        return 0;
    }
    const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(raw_exports);
    const auto* raw_names = rva_pointer(image, *nt, exports->AddressOfNames, exports->NumberOfNames * sizeof(std::uint32_t));
    const auto* raw_ordinals = rva_pointer(image, *nt, exports->AddressOfNameOrdinals, exports->NumberOfNames * sizeof(std::uint16_t));
    const auto* raw_functions = rva_pointer(image, *nt, exports->AddressOfFunctions, exports->NumberOfFunctions * sizeof(std::uint32_t));
    if (!raw_names || !raw_ordinals || !raw_functions) {
        return 0;
    }
    const auto* names = reinterpret_cast<const std::uint32_t*>(raw_names);
    const auto* ordinals = reinterpret_cast<const std::uint16_t*>(raw_ordinals);
    const auto* functions = reinterpret_cast<const std::uint32_t*>(raw_functions);
    for (std::uint32_t index = 0; index < exports->NumberOfNames; ++index) {
        const auto* raw_name = rva_pointer(image, *nt, names[index], 1);
        if (!raw_name) {
            continue;
        }
        const auto* current = reinterpret_cast<const char*>(raw_name);
        const auto maximum = static_cast<std::size_t>(image.data() + image.size() - raw_name);
        const auto length = strnlen_s(current, maximum);
        if (length != maximum && std::strcmp(current, name) == 0 && ordinals[index] < exports->NumberOfFunctions) {
            return functions[ordinals[index]];
        }
    }
    return 0;
}

std::uint32_t first_section_rva(const std::span<const std::byte> image) {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) {
        return 0;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        static_cast<std::size_t>(dos->e_lfanew) > image.size() - sizeof(IMAGE_NT_HEADERS64)) {
        return 0;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt->FileHeader.NumberOfSections == 0) {
        return 0;
    }
    const auto* section = IMAGE_FIRST_SECTION(nt);
    const auto section_offset = reinterpret_cast<const std::byte*>(section) - image.data();
    if (section_offset < 0 || static_cast<std::size_t>(section_offset) > image.size() - sizeof(IMAGE_SECTION_HEADER)) {
        return 0;
    }
    return section->VirtualAddress;
}
#endif

}

namespace dump {

MapperSession::MapperSession(IMapperBackend& backend) noexcept : backend_(backend) {}

MapperSession::~MapperSession() {
    if (loaded_) {
        backend_.unload();
    }
}

Status MapperSession::open() noexcept {
    if (loaded_) {
        return Status::invalid_state;
    }
    const auto status = backend_.load();
    loaded_ = status == Status::success;
    return status;
}

Status MapperSession::map_embedded_driver(const std::span<const std::byte> image, protocol::BootConfiguration& configuration) noexcept {
    if (!loaded_ || mapped_ || image.empty()) {
        return Status::invalid_state;
    }
    nonce_ = configuration.header.nonce;
    auto result = backend_.map(image, configuration);
    if (!result) {
        backend_.unload();
        loaded_ = false;
        return result.status();
    }
    allocation_ = result.value().allocation_base;
    entry_status_ = result.value().entry_status;
    finalizer_rva_ = result.value().finalizer_rva;
    discarded_header_size_ = result.value().discarded_header_size;
    if (entry_status_ < 0) {
        if (allocation_ != 0) {
            backend_.free_pool(allocation_);
        }
        backend_.unload();
        loaded_ = false;
        allocation_ = 0;
        finalizer_rva_ = 0;
        discarded_header_size_ = 0;
        return Status::driver_failure;
    }
    mapped_ = allocation_ != 0 && finalizer_rva_ > discarded_header_size_ &&
        finalizer_rva_ - discarded_header_size_ <= std::numeric_limits<std::uint64_t>::max() - allocation_;
    if (!mapped_) {
        if (allocation_ != 0) {
            backend_.free_pool(allocation_);
        }
        backend_.unload();
        loaded_ = false;
        allocation_ = 0;
        finalizer_rva_ = 0;
        discarded_header_size_ = 0;
        return Status::mapper_failure;
    }
    return Status::success;
}

Status MapperSession::bind(IDeviceLifecycle& lifecycle) noexcept {
    if (!mapped_ || bound_) {
        return Status::invalid_state;
    }
    const auto status = lifecycle.bind();
    bound_ = status == Status::success;
    return status;
}

Status MapperSession::shutdown(IDeviceLifecycle& lifecycle) noexcept {
    if (!loaded_ || !mapped_ || !bound_) {
        return Status::invalid_state;
    }
    auto result = lifecycle.prepare_shutdown();
    if (result == Status::success) {
        result = backend_.call_finalizer(allocation_ + finalizer_rva_ - discarded_header_size_, nonce_);
        if (result == Status::success) {
            result = backend_.free_pool(allocation_);
        }
    }
    const auto unload_status = backend_.unload();
    loaded_ = false;
    mapped_ = false;
    bound_ = false;
    allocation_ = 0;
    finalizer_rva_ = 0;
    discarded_header_size_ = 0;
    return result != Status::success ? result : unload_status;
}

Status MapperSession::abort() noexcept {
    if (!loaded_ || !mapped_ || bound_) {
        return Status::invalid_state;
    }
    auto result = backend_.call_finalizer(allocation_ + finalizer_rva_ - discarded_header_size_, nonce_);
    if (result == Status::success) {
        result = backend_.free_pool(allocation_);
    }
    const auto unload_status = backend_.unload();
    loaded_ = false;
    mapped_ = false;
    allocation_ = 0;
    finalizer_rva_ = 0;
    discarded_header_size_ = 0;
    return result != Status::success ? result : unload_status;
}

std::uint64_t MapperSession::allocation_base() const noexcept {
    return allocation_;
}

std::int32_t MapperSession::entry_status() const noexcept {
    return entry_status_;
}

#ifndef DUMP_MAPPER_CONTRACT_ONLY
Status KdmapperBackend::load() {
    const auto status = intel_driver::Load();
    return NT_SUCCESS(status) && intel_driver::hDevice != INVALID_HANDLE_VALUE ? Status::success : Status::mapper_failure;
}

Result<MapResult> KdmapperBackend::map(const std::span<const std::byte> image, protocol::BootConfiguration& configuration) {
    const auto finalizer = export_rva(image, "FinalizeDriver");
    const auto discarded_header_size = first_section_rva(image);
    if (discarded_header_size == 0 || finalizer <= discarded_header_size || image.size() > std::numeric_limits<ULONG>::max()) {
        return Status::validation_failure;
    }
    NTSTATUS entry_status{};
    const auto allocation = kdmapper::MapDriver(reinterpret_cast<BYTE*>(const_cast<std::byte*>(image.data())), reinterpret_cast<ULONG64>(&configuration), 0, false, true, kdmapper::AllocationMode::AllocatePool, false, nullptr, &entry_status);
    if (allocation == 0) {
        return Status::mapper_failure;
    }
    return MapResult{allocation, static_cast<std::int32_t>(entry_status), finalizer, discarded_header_size};
}

Status KdmapperBackend::call_finalizer(const std::uint64_t address, const protocol::Nonce& nonce) {
    NTSTATUS result{};
    const auto invoked = intel_driver::CallKernelFunction<NTSTATUS>(&result, address, reinterpret_cast<ULONG64>(&nonce), 0ull);
    return invoked && NT_SUCCESS(result) ? Status::success : Status::driver_failure;
}

Status KdmapperBackend::free_pool(const std::uint64_t allocation) {
    return intel_driver::FreePool(allocation) ? Status::success : Status::mapper_failure;
}

Status KdmapperBackend::unload() {
    return NT_SUCCESS(intel_driver::Unload()) ? Status::success : Status::mapper_failure;
}
#else
Status KdmapperBackend::load() { return Status::mapper_failure; }
Result<MapResult> KdmapperBackend::map(std::span<const std::byte>, protocol::BootConfiguration&) { return Status::mapper_failure; }
Status KdmapperBackend::call_finalizer(std::uint64_t, const protocol::Nonce&) { return Status::mapper_failure; }
Status KdmapperBackend::free_pool(std::uint64_t) { return Status::mapper_failure; }
Status KdmapperBackend::unload() { return Status::mapper_failure; }
#endif

}
