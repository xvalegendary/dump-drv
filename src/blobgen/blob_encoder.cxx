#include "blob_encoder.hxx"

#include <Windows.h>

#include <array>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <system_error>
#include <vector>

namespace dump::blob {

std::string encode(const std::span<const std::byte> bytes) {
    std::ostringstream stream;
    stream << "#pragma once\n\n";
    stream << "#include <cstddef>\n\n";
    stream << "namespace dump::embedded {\n\n";
    stream << "inline constexpr unsigned char driver_blob[] = {\n";
    stream << std::hex << std::setfill('0');
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index % 16 == 0) {
            stream << "    ";
        }
        stream << "0x" << std::setw(2) << std::to_integer<unsigned int>(bytes[index]);
        if (index + 1 != bytes.size()) {
            stream << ", ";
        }
        if (index % 16 == 15 || index + 1 == bytes.size()) {
            stream << '\n';
        }
    }
    stream << "};\n";
    stream << std::dec << "inline constexpr std::size_t driver_blob_size = " << bytes.size() << ";\n\n";
    stream << "}\n";
    return stream.str();
}

Status write_if_changed(const std::filesystem::path& input, const std::filesystem::path& output) noexcept {
    try {
        std::ifstream source(input, std::ios::binary);
        if (!source) {
            return Status::io_error;
        }
        std::vector<char> raw((std::istreambuf_iterator<char>(source)), {});
        if (raw.empty()) {
            return Status::invalid_argument;
        }
        const auto bytes = std::span(reinterpret_cast<const std::byte*>(raw.data()), raw.size());
        const auto generated = encode(bytes);
        {
            std::ifstream existing(output, std::ios::binary);
            if (existing) {
                const std::string current((std::istreambuf_iterator<char>(existing)), {});
                if (current == generated) {
                    return Status::success;
                }
            }
        }
        std::filesystem::create_directories(output.parent_path());
        auto temporary = output;
        temporary += L".tmp";
        {
            std::ofstream destination(temporary, std::ios::binary | std::ios::trunc);
            if (!destination) {
                return Status::io_error;
            }
            destination.write(generated.data(), static_cast<std::streamsize>(generated.size()));
            destination.flush();
            if (!destination) {
                return Status::io_error;
            }
        }
        if (!MoveFileExW(temporary.c_str(), output.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            std::error_code ignored;
            std::filesystem::remove(temporary, ignored);
            return Status::io_error;
        }
        return Status::success;
    } catch (...) {
        return Status::io_error;
    }
}

Status verify(const std::filesystem::path& input, const std::filesystem::path& header) noexcept {
    try {
        std::ifstream source(input, std::ios::binary);
        std::ifstream generated(header, std::ios::binary);
        if (!source || !generated) {
            return Status::io_error;
        }
        const std::vector<char> raw((std::istreambuf_iterator<char>(source)), {});
        const std::string text((std::istreambuf_iterator<char>(generated)), {});
        if (raw.empty()) {
            return Status::invalid_argument;
        }
        std::vector<unsigned char> reconstructed;
        const auto begin = text.find("driver_blob[] = {");
        const auto end = begin == std::string::npos ? std::string::npos : text.find("};", begin);
        if (begin == std::string::npos || end == std::string::npos) {
            return Status::validation_failure;
        }
        auto cursor = begin;
        while ((cursor = text.find("0x", cursor)) != std::string::npos && cursor < end) {
            if (cursor + 4 > end) {
                return Status::validation_failure;
            }
            const auto digit = [](const char value) -> int {
                if (value >= '0' && value <= '9') return value - '0';
                if (value >= 'a' && value <= 'f') return value - 'a' + 10;
                if (value >= 'A' && value <= 'F') return value - 'A' + 10;
                return -1;
            };
            const auto high = digit(text[cursor + 2]);
            const auto low = digit(text[cursor + 3]);
            if (high < 0 || low < 0) {
                return Status::validation_failure;
            }
            reconstructed.push_back(static_cast<unsigned char>((high << 4) | low));
            cursor += 4;
        }
        if (reconstructed.size() != raw.size()) {
            return Status::validation_failure;
        }
        for (std::size_t index = 0; index < raw.size(); ++index) {
            if (reconstructed[index] != static_cast<unsigned char>(raw[index])) {
                return Status::validation_failure;
            }
        }
        return Status::success;
    } catch (...) {
        return Status::io_error;
    }
}

}
