#pragma once

#include "protocol.hxx"
#include "status.hxx"

namespace dump::pe {

inline constexpr protocol::u16 dos_magic = 0x5a4d;
inline constexpr protocol::u32 nt_magic = 0x00004550;
inline constexpr protocol::u16 optional_magic_64 = 0x20b;
inline constexpr protocol::u16 machine_amd64 = 0x8664;
inline constexpr protocol::u32 flag_execute = 0x20000000;
inline constexpr protocol::u32 flag_write = 0x80000000;
inline constexpr protocol::u32 minimum_headers = 0x200;
inline constexpr protocol::u32 maximum_image_size = 0x40000000;
inline constexpr protocol::u32 maximum_section_alignment = 0x10000;
inline constexpr protocol::u32 dos_header_size = 0x40;
inline constexpr protocol::usize section_header_size = 40;
inline constexpr protocol::usize optional_header_size = 240;

struct Section {
    protocol::FixedArray<char, protocol::section_name_size> name{};
    protocol::u32 virtual_address{};
    protocol::u32 virtual_size{};
    protocol::u32 raw_offset{};
    protocol::u32 raw_size{};
    protocol::u32 characteristics{};
};

struct Image {
    protocol::u32 timestamp{};
    protocol::u32 image_size{};
    protocol::u32 headers_size{};
    protocol::u32 section_alignment{};
    protocol::u32 machine{};
    protocol::u32 section_count{};
    Section sections[protocol::maximum_sections]{};
};

namespace detail {

inline bool available(const protocol::usize size, const protocol::usize offset, const protocol::usize required) noexcept {
    return offset <= size && required <= size - offset;
}

inline protocol::u16 read16(const unsigned char* data) noexcept {
    return static_cast<protocol::u16>(data[0] | (static_cast<protocol::u16>(data[1]) << 8));
}

inline protocol::u32 read32(const unsigned char* data) noexcept {
    return static_cast<protocol::u32>(data[0]) | (static_cast<protocol::u32>(data[1]) << 8) | (static_cast<protocol::u32>(data[2]) << 16) | (static_cast<protocol::u32>(data[3]) << 24);
}

}

inline protocol::u32 extent(const Section& section, const protocol::u32 image_size) noexcept {
    if (section.virtual_address >= image_size) {
        return 0;
    }
    const auto span = section.virtual_size > section.raw_size ? section.virtual_size : section.raw_size;
    const auto remaining = image_size - section.virtual_address;
    return span < remaining ? span : remaining;
}

inline bool writable(const Section& section) noexcept {
    return (section.characteristics & flag_write) != 0;
}

inline bool executable(const Section& section) noexcept {
    return (section.characteristics & flag_execute) != 0;
}

inline protocol::u32 section_name_length(const Section& section) noexcept {
    protocol::u32 length{};
    while (length < protocol::section_name_size && section.name[length] != '\0') {
        ++length;
    }
    return length;
}

inline Status parse(const unsigned char* data, const protocol::usize size, Image& image) noexcept {
    image = Image{};
    if (data == nullptr || size < dos_header_size + sizeof(protocol::u32)) {
        return Status::invalid_argument;
    }
    if (detail::read16(data) != dos_magic) {
        return Status::validation_failure;
    }
    const auto nt_offset = detail::read32(data + 0x3c);
    if (nt_offset < dos_header_size || nt_offset > 0x10000 || !detail::available(size, nt_offset, 4 + 20 + optional_header_size)) {
        return Status::validation_failure;
    }
    const auto* nt = data + nt_offset;
    if (detail::read32(nt) != nt_magic) {
        return Status::validation_failure;
    }
    image.machine = detail::read16(nt + 4);
    const auto section_count = detail::read16(nt + 6);
    const auto optional_size = detail::read16(nt + 20);
    if (image.machine != machine_amd64 || section_count == 0 || section_count > protocol::maximum_sections || optional_size < optional_header_size) {
        return Status::validation_failure;
    }
    const auto* optional = nt + 24;
    if (detail::read16(optional) != optional_magic_64) {
        return Status::validation_failure;
    }
    image.section_alignment = detail::read32(optional + 32);
    image.image_size = detail::read32(optional + 56);
    image.headers_size = detail::read32(optional + 60);
    if (image.image_size < 0x1000 || image.image_size > maximum_image_size) {
        return Status::validation_failure;
    }
    if (image.section_alignment == 0 || image.section_alignment > maximum_section_alignment || (image.section_alignment & (image.section_alignment - 1)) != 0) {
        return Status::validation_failure;
    }
    if (image.headers_size < minimum_headers || image.headers_size > image.image_size) {
        return Status::validation_failure;
    }
    const auto table_offset = static_cast<protocol::usize>(nt_offset) + 24 + optional_size;
    if (!detail::available(size, table_offset, section_header_size * section_count)) {
        return Status::validation_failure;
    }
    image.timestamp = detail::read32(nt + 8);
    image.section_count = section_count;
    protocol::u32 previous{};
    for (protocol::u32 index = 0; index < section_count; ++index) {
        const auto* raw = data + table_offset + section_header_size * index;
        auto& section = image.sections[index];
        for (protocol::usize position = 0; position < protocol::section_name_size; ++position) {
            section.name[position] = static_cast<char>(raw[position]);
        }
        section.name[protocol::section_name_size - 1] = '\0';
        section.virtual_size = detail::read32(raw + 8);
        section.virtual_address = detail::read32(raw + 12);
        section.raw_size = detail::read32(raw + 16);
        section.raw_offset = detail::read32(raw + 20);
        section.characteristics = detail::read32(raw + 36);
        if (section.virtual_address < previous || section.virtual_address >= image.image_size) {
            return Status::validation_failure;
        }
        previous = section.virtual_address;
    }
    return Status::success;
}

inline protocol::u32 first_section_offset(const Image& image) noexcept {
    if (image.section_count == 0) {
        return 0;
    }
    return image.sections[0].virtual_address;
}

inline protocol::u32 header_extent(const Image& image) noexcept {
    const auto first = first_section_offset(image);
    if (first == 0) {
        return 0;
    }
    const auto limit = image.headers_size < first ? image.headers_size : first;
    return limit > 0x10000 ? 0x10000 : limit;
}

}