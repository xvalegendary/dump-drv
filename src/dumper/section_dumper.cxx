#include "section_dumper.hxx"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <vector>

namespace {

bool safe_character(const char value) {
    if ((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9')) {
        return true;
    }
    return value == '.' || value == '_' || value == '$' || value == '-';
}

std::wstring section_label(const dump::protocol::SectionDescriptor& section) {
    std::wstring label;
    for (std::size_t index = 0; index < dump::protocol::section_name_size; ++index) {
        const auto value = section.name[index];
        if (value == '\0') {
            break;
        }
        label.push_back(safe_character(value) ? static_cast<wchar_t>(value) : L'_');
    }
    if (label.empty()) {
        label = L"unnamed";
    }
    return label;
}

dump::Status append_range(dump::DriverClient& client, const std::uint64_t address, const std::uint64_t size, std::ofstream& output, std::uint64_t& written) {
    std::uint64_t done{};
    while (done < size) {
        const auto remaining = static_cast<std::size_t>(std::min<std::uint64_t>(size - done, dump::protocol::maximum_transfer));
        const auto chunk = client.read_memory(address + done, static_cast<std::uint32_t>(remaining));
        if (!chunk) {
            return chunk.status();
        }
        if (chunk.value().bytes.empty()) {
            return dump::Status::partial_copy;
        }
        output.write(reinterpret_cast<const char*>(chunk.value().bytes.data()), static_cast<std::streamsize>(chunk.value().bytes.size()));
        if (!output) {
            return dump::Status::io_error;
        }
        done += chunk.value().bytes.size();
        written += chunk.value().bytes.size();
        if (chunk.value().bytes.size() != remaining) {
            return dump::Status::partial_copy;
        }
    }
    return dump::Status::success;
}

}

namespace dump {

std::uint64_t section_extent(const protocol::SectionDescriptor& section, const std::uint32_t image_size) noexcept {
    if (section.virtual_address >= image_size) {
        return 0;
    }
    const auto span = section.virtual_size > section.raw_size ? section.virtual_size : section.raw_size;
    const auto remaining = static_cast<std::uint64_t>(image_size) - section.virtual_address;
    return span < remaining ? span : remaining;
}

std::wstring section_file_name(const std::wstring_view stem, const std::size_t index, const protocol::SectionDescriptor& section) {
    std::wstring name(stem);
    name.push_back(L'.');
    wchar_t digits[3]{};
    swprintf_s(digits, L"%02zu", index);
    name.append(digits);
    name.push_back(L'-');
    name.append(section_label(section));
    name.append(L".bin");
    return name;
}

SectionDumper::SectionDumper(DriverClient& client) noexcept : client_(client) {}

Result<SectionDumpResult> SectionDumper::write(const std::filesystem::path& directory, const std::wstring_view stem, const protocol::SectionsResponse& table) noexcept {
    try {
        SectionDumpResult result{};
        std::error_code ignored;
        std::filesystem::create_directories(directory, ignored);
        const auto header_path = directory / (std::wstring(stem) + L".headers.bin");
        {
            std::ofstream header(header_path, std::ios::binary | std::ios::trunc);
            if (!header) {
                return Status::io_error;
            }
            std::uint64_t written{};
            const auto status = append_range(client_, table.image_base, table.headers_size, header, written);
            if (status != Status::success) {
                header.close();
                std::filesystem::remove(header_path, ignored);
                ++result.failed;
            } else {
                result.bytes += written;
                ++result.files;
            }
        }
        for (std::size_t index = 0; index < table.section_count; ++index) {
            const auto& section = table.sections[index];
            const auto extent = section_extent(section, table.image_size);
            if (extent == 0) {
                continue;
            }
            const auto path = directory / section_file_name(stem, index, section);
            std::ofstream output(path, std::ios::binary | std::ios::trunc);
            if (!output) {
                return Status::io_error;
            }
            std::uint64_t written{};
            const auto status = append_range(client_, table.image_base + section.virtual_address, extent, output, written);
            output.close();
            if (status != Status::success) {
                std::filesystem::remove(path, ignored);
                ++result.failed;
                continue;
            }
            result.bytes += written;
            ++result.files;
        }
        return result;
    } catch (...) {
        return Status::io_error;
    }
}

}