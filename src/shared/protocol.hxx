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
inline constexpr u16 version = 3;
inline constexpr u64 maximum_transfer = 1024ull * 1024ull;
inline constexpr u32 unavailable_offset = 0xffffffffu;
inline constexpr u32 device_type = 0x8000;
inline constexpr u32 method_buffered = 0;
inline constexpr u32 method_out_direct = 2;
inline constexpr u32 special_access = 3;
inline constexpr u32 maximum_sections = 128;
inline constexpr u32 section_name_size = 8;
inline constexpr u32 maximum_http_records = 8;
inline constexpr u32 http_method_size = 8;
inline constexpr u32 http_target_size = 384;
inline constexpr u32 http_host_size = 192;
inline constexpr u32 http_agent_size = 96;
inline constexpr u32 http_body_size = 192;
inline constexpr u32 maximum_module_name = 64;
inline constexpr u32 maximum_scan_hits = 32;
inline constexpr u32 conceal_module_list = 0x1;
inline constexpr u32 conceal_unloaded = 0x2;
inline constexpr u32 conceal_piddb = 0x4;
inline constexpr u32 conceal_hash_bucket = 0x8;
inline constexpr u32 conceal_headers = 0x10;
inline constexpr u32 conceal_all = conceal_module_list | conceal_unloaded | conceal_piddb | conceal_hash_bucket | conceal_headers;

constexpr u32 control_code(const u32 function, const u32 method) noexcept {
    return (device_type << 16) | (special_access << 14) | (function << 2) | method;
}
inline constexpr u32 ioctl_bind = control_code(0x800, method_buffered);
inline constexpr u32 ioctl_attach = control_code(0x801, method_buffered);
inline constexpr u32 ioctl_set_symbols = control_code(0x802, method_buffered);
inline constexpr u32 ioctl_query_region = control_code(0x803, method_buffered);
inline constexpr u32 ioctl_read_memory = control_code(0x804, method_out_direct);
inline constexpr u32 ioctl_prepare_shutdown = control_code(0x805, method_buffered);
inline constexpr u32 ioctl_query_sections = control_code(0x806, method_buffered);
inline constexpr u32 ioctl_conceal = control_code(0x807, method_buffered);
inline constexpr u32 ioctl_http_scan = control_code(0x808, method_buffered);

using Nonce = FixedArray<u8, 32>;

enum class Command : u32 {
    bind = 1,
    attach,
    set_symbols,
    query_region,
    read_memory,
    prepare_shutdown,
    query_sections,
    conceal
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

struct alignas(8) SectionDescriptor {
    FixedArray<char, section_name_size> name{};
    u64 virtual_address{};
    u32 virtual_size{};
    u32 raw_offset{};
    u32 raw_size{};
    u32 characteristics{};
};

struct alignas(8) SectionsRequest {
    Header header{};
};

struct alignas(8) SectionsResponse {
    u64 image_base{};
    u32 image_size{};
    u32 headers_size{};
    u32 section_count{};
    i32 native_status{};
    u32 reserved{};
    FixedArray<SectionDescriptor, maximum_sections> sections{};
};

struct ConcealTargets {
    u32 nt_timestamp{};
    u32 nt_image_size{};
    u32 ps_loaded_module_list_rva{unavailable_offset};
    u32 ci_timestamp{};
    u32 ci_image_size{};
    u32 flags{conceal_all};
    u32 reserved{};
    u32 reserved2{};
    FixedArray<wide_char, maximum_module_name> module_name{};
};

struct alignas(8) ConcealRequest {
    Header header{};
    ConcealTargets targets{};
};

struct alignas(8) ConcealResponse {
    u32 applied{};
    u32 module_list_hidden{};
    u32 unloaded_hidden{};
    u32 piddb_hidden{};
    u32 hash_bucket_hidden{};
    u32 headers_erased{};
    u32 name_hits{};
    u32 reserved{};
    i32 native_status{};
    u32 reserved2{};
};

struct alignas(8) HttpRecord {
    FixedArray<char, http_method_size> method{};
    FixedArray<char, http_target_size> target{};
    FixedArray<char, http_host_size> host{};
    FixedArray<char, http_agent_size> agent{};
    FixedArray<char, http_body_size> body{};
    u32 body_length{};
    u32 request_length{};
    u32 headers{};
    u32 reserved{};
};

struct alignas(8) HttpScanRequest {
    Header header{};
    u64 start_address{};
    u32 budget{};
    u32 maximum_records{};
};

struct alignas(8) HttpScanResponse {
    u64 next_address{};
    u64 scanned{};
    u32 record_count{};
    u32 complete{};
    i32 native_status{};
    u32 reserved{};
    FixedArray<HttpRecord, maximum_http_records> records{};
};

static_assert(sizeof(Header) == 48);
static_assert(sizeof(Nonce) == 32);
static_assert(sizeof(ConcealTargets) % 8 == 0);
static_assert(sizeof(SectionDescriptor) == 32);

}