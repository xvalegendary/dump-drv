#pragma once

namespace dump::protocol {

using u8 = unsigned char;
using u16 = unsigned short;
using u32 = unsigned int;
using u64 = unsigned long long;
using i32 = int;
using usize = decltype(sizeof(0));
#ifdef _KERNEL_MODE
using wide_char = WCHAR;
#else
using wide_char = wchar_t;
#endif

template <typename T, usize Size>
struct FixedArray {
    T values[Size]{};
    constexpr T* data() noexcept { return values; }
    constexpr const T* data() const noexcept { return values; }
    constexpr usize size() const noexcept { return Size; }
    constexpr T* begin() noexcept { return values; }
    constexpr const T* begin() const noexcept { return values; }
    constexpr T* end() noexcept { return values + Size; }
    constexpr const T* end() const noexcept { return values + Size; }
    constexpr T& operator[](usize index) noexcept { return values[index]; }
    constexpr const T& operator[](usize index) const noexcept { return values[index]; }
    constexpr void fill(const T& value) noexcept {
        for (usize index = 0; index < Size; ++index) {
            values[index] = value;
        }
    }
    constexpr bool operator==(const FixedArray& other) const noexcept {
        for (usize index = 0; index < Size; ++index) {
            if (!(values[index] == other.values[index])) {
                return false;
            }
        }
        return true;
    }
};

inline constexpr u32 magic = 0x504d5544;
inline constexpr u16 version = 1;
inline constexpr u64 maximum_transfer = 1024ull * 1024ull;
inline constexpr u32 unavailable_offset = 0xffffffffu;
inline constexpr u32 device_type = 0x8000;
inline constexpr u32 method_buffered = 0;
inline constexpr u32 method_out_direct = 2;
inline constexpr u32 special_access = 3;
constexpr u32 control_code(const u32 function, const u32 method) noexcept {
    return (device_type << 16) | (special_access << 14) | (function << 2) | method;
}
inline constexpr u32 ioctl_bind = control_code(0x800, method_buffered);
inline constexpr u32 ioctl_attach = control_code(0x801, method_buffered);
inline constexpr u32 ioctl_set_symbols = control_code(0x802, method_buffered);
inline constexpr u32 ioctl_query_region = control_code(0x803, method_buffered);
inline constexpr u32 ioctl_read_memory = control_code(0x804, method_out_direct);
inline constexpr u32 ioctl_prepare_shutdown = control_code(0x805, method_buffered);

using Nonce = FixedArray<u8, 32>;

enum class Command : u32 {
    bind = 1,
    attach,
    set_symbols,
    query_region,
    read_memory,
    prepare_shutdown
};

enum class SessionState : u32 {
    created,
    bound,
    attached,
    snapshotting,
    shutting_down,
    stopped
};

enum class RegionState : u32 {
    free_region = 0x10000,
    reserved = 0x2000,
    committed = 0x1000
};

enum class RegionType : u32 {
    none = 0,
    image = 0x1000000,
    mapped = 0x40000,
    private_region = 0x20000
};

struct alignas(8) Header {
    u32 magic{};
    u16 version{};
    u16 size{};
    u64 sequence{};
    Nonce nonce{};
};

struct alignas(8) KernelIdentity {
    u32 timestamp{};
    u32 image_size{};
    FixedArray<u8, 16> pdb_guid{};
    u32 pdb_age{};
    u32 reserved{};
};

struct alignas(8) BootConfiguration {
    Header header{};
    FixedArray<wide_char, 96> driver_name{};
    FixedArray<wide_char, 96> device_name{};
    FixedArray<wide_char, 96> symbolic_link{};
};

struct alignas(8) BindRequest {
    Header header{};
    u64 client_process_id{};
};

struct alignas(8) AttachRequest {
    Header header{};
    u64 process_id{};
};

struct alignas(8) AttachResponse {
    u64 process_id{};
    u64 eprocess{};
    u64 peb{};
    u64 image_base{};
    FixedArray<char, 16> image_name{};
};

struct alignas(8) SymbolPacket {
    Header header{};
    u32 kernel_timestamp{};
    u32 kernel_image_size{};
    FixedArray<u8, 16> pdb_guid{};
    u32 pdb_age{};
    u32 eprocess_size{};
    u32 unique_process_id{unavailable_offset};
    u32 active_process_links{unavailable_offset};
    u32 image_file_name{unavailable_offset};
    u32 vad_root{unavailable_offset};
    u32 directory_table_base{unavailable_offset};
    u32 reserved{};
    FixedArray<u8, 32> packet_hash{};
};

struct alignas(8) QueryRegionRequest {
    Header header{};
    u64 address{};
};

struct alignas(8) RegionDescriptor {
    u64 base{};
    u64 allocation_base{};
    u64 size{};
    u32 allocation_protect{};
    u32 protect{};
    RegionState state{};
    RegionType type{};
};

struct alignas(8) QueryRegionResponse {
    RegionDescriptor region{};
    i32 native_status{};
};

struct alignas(8) ReadRequest {
    Header header{};
    u64 address{};
    u32 size{};
    u32 reserved{};
};

struct alignas(8) ReadResponse {
    u64 address{};
    u32 requested{};
    u32 transferred{};
    i32 native_status{};
    u32 reserved{};
};

struct alignas(8) ShutdownRequest {
    Header header{};
};

static_assert(sizeof(Header) == 48);
static_assert(sizeof(Nonce) == 32);

}
