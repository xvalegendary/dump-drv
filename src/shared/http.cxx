#ifdef _KERNEL_MODE
#include <ntifs.h>
#endif

#include "http.hxx"

namespace {

using dump::protocol::u32;
using dump::protocol::usize;

const char* const methods[] = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE"};
constexpr u32 method_count = sizeof(methods) / sizeof(methods[0]);

bool printable(const unsigned char value) noexcept {
    return value >= 0x20 && value <= 0x7e;
}

bool alphanumeric(const unsigned char value) noexcept {
    return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9');
}

template <typename T>
T minimum(const T left, const T right) noexcept {
    return left < right ? left : right;
}

u32 text_length(const char* text) noexcept {
    u32 length{};
    while (text[length] != '\0') {
        ++length;
    }
    return length;
}

unsigned char lowered(const unsigned char value) noexcept {
    return value >= 'A' && value <= 'Z' ? static_cast<unsigned char>(value - 'A' + 'a') : value;
}

bool equals_insensitive(const unsigned char* data, const char* text, const u32 length) noexcept {
    for (u32 index = 0; index < length; ++index) {
        if (lowered(data[index]) != lowered(static_cast<unsigned char>(text[index]))) {
            return false;
        }
    }
    return true;
}

template <u32 Size>
void copy_bounded(dump::protocol::FixedArray<char, Size>& destination, const unsigned char* source, const u32 length) noexcept {
    const auto count = length < Size - 1 ? length : Size - 1;
    for (u32 index = 0; index < count; ++index) {
        destination[index] = static_cast<char>(source[index]);
    }
    destination[count] = '\0';
}

bool header_matches(const unsigned char* data, const u32 available, const char* name) noexcept {
    const auto length = text_length(name);
    return available >= length + 1 && equals_insensitive(data, name, length) && data[length] == ':';
}

u32 header_value_offset(const unsigned char* data, const u32 available, const char* name) noexcept {
    const auto length = text_length(name) + 1;
    auto offset = length;
    while (offset < available && (data[offset] == ' ' || data[offset] == '\t')) {
        ++offset;
    }
    return offset;
}

bool absolute_target(const unsigned char* text, const u32 span) noexcept {
    if (span > 7 && equals_insensitive(text, "http://", 7)) {
        return true;
    }
    return span > 8 && equals_insensitive(text, "https://", 8);
}

u32 parse_content_length(const unsigned char* data, const u32 available) noexcept {
    u32 value{};
    for (u32 index = 0; index < available && index < 10; ++index) {
        const auto byte = data[index];
        if (byte < '0' || byte > '9') {
            break;
        }
        if (value > 0xffffffffu / 10) {
            return 0;
        }
        value = value * 10 + static_cast<u32>(byte - '0');
    }
    return value;
}

}

namespace dump::http {

bool same(const protocol::HttpRecord& left, const protocol::HttpRecord& right) noexcept {
    if (left.body_length != right.body_length) {
        return false;
    }
    for (u32 index = 0; index < protocol::http_method_size; ++index) {
        if (left.method[index] != right.method[index]) {
            return false;
        }
    }
    for (u32 index = 0; index < protocol::http_target_size; ++index) {
        if (left.target[index] != right.target[index]) {
            return false;
        }
    }
    for (u32 index = 0; index < protocol::http_host_size; ++index) {
        if (left.host[index] != right.host[index]) {
            return false;
        }
    }
    for (u32 index = 0; index < protocol::http_body_size; ++index) {
        if (left.body[index] != right.body[index]) {
            return false;
        }
    }
    return true;
}

u32 method_length(const protocol::HttpRecord& record) noexcept {
    u32 length{};
    while (length < protocol::http_method_size && record.method[length] != '\0') {
        ++length;
    }
    return length;
}

u32 parse(const unsigned char* data, const usize size, protocol::HttpRecord* records, const u32 capacity) noexcept {
    if (data == nullptr || records == nullptr || capacity == 0 || size < 24) {
        return 0;
    }
    u32 count{};
    for (usize index = 0; index + 24 < size && count < capacity; ++index) {
        if (index != 0 && alphanumeric(data[index - 1])) {
            continue;
        }
        const auto* line = data + index;
        const usize remaining = size - index;
        u32 method_size{};
        for (u32 candidate = 0; candidate < method_count; ++candidate) {
            const auto length = text_length(methods[candidate]);
            if (remaining > length && equals_insensitive(line, methods[candidate], length) && line[length] == ' ') {
                method_size = length;
                break;
            }
        }
        if (method_size == 0) {
            continue;
        }
        const u32 target_begin = method_size + 1;
        u32 target_end = target_begin;
        while (target_end < remaining && target_end - target_begin < protocol::http_target_size - 1 && printable(line[target_end]) && line[target_end] != ' ') {
            ++target_end;
        }
        if (target_end == target_begin || target_end >= remaining || line[target_end] != ' ') {
            continue;
        }
        const auto target_span = target_end - target_begin;
        if (line[target_begin] != '/' && !absolute_target(line + target_begin, target_span)) {
            continue;
        }
        const auto version_begin = target_end + 1;
        if (version_begin + 9 > remaining || !equals_insensitive(line + version_begin, "HTTP/1.", 7)) {
            continue;
        }
        const auto digit = line[version_begin + 7];
        if (digit < '0' || digit > '9') {
            continue;
        }
        u32 cursor = static_cast<u32>(version_begin) + 8;
        if (static_cast<usize>(cursor) + 2 > remaining || line[cursor] != '\r' || line[cursor + 1] != '\n') {
            continue;
        }
        cursor += 2;
        protocol::HttpRecord record{};
        copy_bounded(record.method, line, method_size);
        copy_bounded(record.target, line + target_begin, target_span);
        const auto header_limit = minimum(remaining, static_cast<usize>(cursor) + maximum_header_scan);
        u32 headers{};
        u32 content_length{};
        bool has_content{};
        bool terminated{};
        while (static_cast<usize>(cursor) + 2 <= header_limit) {
            if (line[cursor] == '\r' && line[cursor + 1] == '\n') {
                cursor += 2;
                terminated = true;
                break;
            }
            u32 end = cursor;
            while (static_cast<usize>(end) + 1 < header_limit && !(line[end] == '\r' && line[end + 1] == '\n')) {
                ++end;
            }
            if (static_cast<usize>(end) + 1 >= header_limit) {
                break;
            }
            const auto value_begin = end - cursor;
            if (header_matches(line + cursor, value_begin, "Host")) {
                const auto offset = header_value_offset(line + cursor, value_begin, "Host");
                if (offset < value_begin) {
                    copy_bounded(record.host, line + cursor + offset, value_begin - offset);
                }
            } else if (header_matches(line + cursor, value_begin, "User-Agent")) {
                const auto offset = header_value_offset(line + cursor, value_begin, "User-Agent");
                if (offset < value_begin) {
                    copy_bounded(record.agent, line + cursor + offset, value_begin - offset);
                }
            } else if (header_matches(line + cursor, value_begin, "Content-Length")) {
                const auto offset = header_value_offset(line + cursor, value_begin, "Content-Length");
                if (offset < value_begin) {
                    content_length = parse_content_length(line + cursor + offset, value_begin - offset);
                    has_content = content_length != 0;
                }
            }
            ++headers;
            cursor = end + 2;
        }
        record.headers = headers;
        if (!terminated) {
            continue;
        }
        const auto header_end = cursor;
        u32 body_length{};
        if (has_content && static_cast<usize>(cursor) < remaining) {
            const auto available = remaining - cursor;
            const auto limit = minimum(static_cast<usize>(content_length), minimum(available, static_cast<usize>(protocol::http_body_size - 1)));
            for (usize position = 0; position < limit; ++position) {
                record.body[position] = static_cast<char>(line[cursor + position]);
            }
            record.body[limit] = '\0';
            body_length = static_cast<u32>(limit);
        }
        record.body_length = body_length;
        record.request_length = body_length != 0 ? header_end + body_length : header_end;
        bool duplicate{};
        for (u32 existing = 0; existing < count; ++existing) {
            if (same(records[existing], record)) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            continue;
        }
        records[count] = record;
        ++count;
        index += record.request_length > 0 ? record.request_length - 1 : 0;
    }
    return count;
}

}