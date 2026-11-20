#include "minidump_writer.hxx"

#define NOMINMAX
#include <Windows.h>
#include <DbgHelp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <string>
#include <system_error>
#include <utility>

namespace {

using ByteVector = std::vector<std::byte>;

struct StreamBlob {
    MINIDUMP_STREAM_TYPE type{};
    ByteVector data;
    RVA rva{};
};

std::size_t aligned4(const std::size_t value) {
    return (value + 3u) & ~std::size_t{3u};
}

template <typename T>
void append_value(ByteVector& bytes, const T& value) {
    const auto* first = reinterpret_cast<const std::byte*>(&value);
    bytes.insert(bytes.end(), first, first + sizeof(T));
}

void append_bytes(ByteVector& bytes, const void* data, const std::size_t size) {
    const auto* first = reinterpret_cast<const std::byte*>(data);
    bytes.insert(bytes.end(), first, first + size);
}

void pad4(ByteVector& bytes) {
    bytes.resize(aligned4(bytes.size()));
}

StreamBlob make_system_stream(const dump::SnapshotMetadata& metadata) {
    MINIDUMP_SYSTEM_INFO info{};
    info.ProcessorArchitecture = metadata.processor_architecture;
    info.NumberOfProcessors = metadata.processors;
    info.MajorVersion = metadata.major_version;
    info.MinorVersion = metadata.minor_version;
    info.BuildNumber = metadata.build_number;
    info.PlatformId = metadata.platform_id;
    StreamBlob stream{SystemInfoStream};
    append_value(stream.data, info);
    return stream;
}

std::size_t module_stream_size(const std::vector<dump::ModuleRecord>& modules) {
    std::size_t size = sizeof(ULONG32) + modules.size() * sizeof(MINIDUMP_MODULE);
    for (const auto& module : modules) {
        size += sizeof(ULONG32) + (module.name.size() + 1) * sizeof(wchar_t);
    }
    return aligned4(size);
}

StreamBlob make_module_stream(const std::vector<dump::ModuleRecord>& modules, const RVA stream_rva) {
    StreamBlob stream{ModuleListStream};
    stream.rva = stream_rva;
    const auto count = static_cast<ULONG32>(modules.size());
    append_value(stream.data, count);
    const auto table_start = stream.data.size();
    stream.data.resize(table_start + modules.size() * sizeof(MINIDUMP_MODULE));
    auto string_offset = stream.data.size();
    for (std::size_t index = 0; index < modules.size(); ++index) {
        const auto& source = modules[index];
        MINIDUMP_MODULE module{};
        module.BaseOfImage = source.base;
        module.SizeOfImage = source.size;
        module.CheckSum = source.checksum;
        module.TimeDateStamp = source.timestamp;
        module.ModuleNameRva = stream_rva + static_cast<RVA>(string_offset);
        std::memcpy(stream.data.data() + table_start + index * sizeof(MINIDUMP_MODULE), &module, sizeof(module));
        const auto byte_length = static_cast<ULONG32>(source.name.size() * sizeof(wchar_t));
        append_value(stream.data, byte_length);
        append_bytes(stream.data, source.name.data(), byte_length);
        const wchar_t terminator{};
        append_value(stream.data, terminator);
        string_offset = stream.data.size();
    }
    pad4(stream.data);
    return stream;
}

StreamBlob make_memory64_stream(const std::vector<dump::MemoryRecord>& memories, const ULONG64 payload_rva) {
    StreamBlob stream{Memory64ListStream};
    ULONG64 count{};
    for (const auto& memory : memories) {
        if (memory.written != 0) {
            ++count;
        }
    }
    append_value(stream.data, count);
    append_value(stream.data, payload_rva);
    for (const auto& memory : memories) {
        if (memory.written == 0) {
            continue;
        }
        MINIDUMP_MEMORY_DESCRIPTOR64 descriptor{};
        descriptor.StartOfMemoryRange = memory.region.base;
        descriptor.DataSize = memory.written;
        append_value(stream.data, descriptor);
    }
    return stream;
}

StreamBlob make_memory_info_stream(const std::vector<dump::MemoryRecord>& memories) {
    StreamBlob stream{MemoryInfoListStream};
    MINIDUMP_MEMORY_INFO_LIST header{};
    header.SizeOfHeader = sizeof(header);
    header.SizeOfEntry = sizeof(MINIDUMP_MEMORY_INFO);
    header.NumberOfEntries = memories.size();
    append_value(stream.data, header);
    for (const auto& memory : memories) {
        MINIDUMP_MEMORY_INFO info{};
        info.BaseAddress = memory.region.base;
        info.AllocationBase = memory.region.allocation_base;
        info.AllocationProtect = memory.region.allocation_protect;
        info.RegionSize = memory.region.size;
        info.State = static_cast<ULONG32>(memory.region.state);
        info.Protect = memory.region.protect;
        info.Type = static_cast<ULONG32>(memory.region.type);
        append_value(stream.data, info);
    }
    return stream;
}

StreamBlob make_misc_stream(const dump::SnapshotMetadata& metadata) {
    StreamBlob stream{MiscInfoStream};
    MINIDUMP_MISC_INFO info{};
    info.SizeOfInfo = sizeof(info);
    info.Flags1 = MINIDUMP_MISC1_PROCESS_ID;
    info.ProcessId = metadata.process_id;
    append_value(stream.data, info);
    return stream;
}

StreamBlob make_comment_stream(const std::wstring& comment) {
    StreamBlob stream{CommentStreamW};
    append_bytes(stream.data, comment.data(), comment.size() * sizeof(wchar_t));
    const wchar_t terminator{};
    append_value(stream.data, terminator);
    return stream;
}

bool read_exact(std::ifstream& input, void* destination, const std::size_t size) {
    input.read(static_cast<char*>(destination), static_cast<std::streamsize>(size));
    return input.good();
}

}

namespace dump {

MiniDumpWriter::~MiniDumpWriter() {
    if (spool_.is_open()) {
        spool_.close();
    }
    if (!finalized_) {
        cleanup_spool();
        if (!keep_partial_) {
            std::error_code ignored;
            std::filesystem::remove(partial_path_, ignored);
        }
    }
}

Status MiniDumpWriter::begin(const std::filesystem::path& final_path) noexcept {
    try {
        if (begun_ || final_path.empty()) {
            return Status::invalid_state;
        }
        final_path_ = final_path;
        partial_path_ = final_path_.wstring() + L".partial";
        spool_path_ = final_path_.wstring() + L".memory";
        std::filesystem::create_directories(final_path_.parent_path());
        std::ofstream(partial_path_, std::ios::binary | std::ios::trunc).close();
        spool_.open(spool_path_, std::ios::binary | std::ios::trunc);
        if (!spool_) {
            return Status::io_error;
        }
        begun_ = true;
        return Status::success;
    } catch (...) {
        return Status::io_error;
    }
}

Status MiniDumpWriter::add_system_info(const SnapshotMetadata& metadata) noexcept {
    if (!begun_ || finalized_) {
        return Status::invalid_state;
    }
    metadata_ = metadata;
    has_metadata_ = true;
    return Status::success;
}

Status MiniDumpWriter::add_module(ModuleRecord module) noexcept {
    if (!begun_ || finalized_ || module.name.empty() || module.size == 0) {
        return Status::invalid_argument;
    }
    modules_.push_back(std::move(module));
    return Status::success;
}

Status MiniDumpWriter::add_memory_region(MemoryRecord memory) noexcept {
    if (!begun_ || finalized_ || memory.region.size == 0) {
        return Status::invalid_argument;
    }
    if (!memories_.empty()) {
        const auto& previous = memories_.back().region;
        if (previous.base > std::numeric_limits<std::uint64_t>::max() - previous.size || memory.region.base < previous.base + previous.size) {
            return Status::invalid_argument;
        }
    }
    memory.written = 0;
    memories_.push_back(memory);
    return Status::success;
}

Status MiniDumpWriter::append_memory(const std::uint64_t address, const std::span<const std::byte> bytes) noexcept {
    if (!begun_ || finalized_ || memories_.empty() || bytes.empty()) {
        return Status::invalid_argument;
    }
    auto& memory = memories_.back();
    if (memory.region.base > std::numeric_limits<std::uint64_t>::max() - memory.written || address != memory.region.base + memory.written || bytes.size() > memory.region.size - memory.written) {
        return Status::invalid_argument;
    }
    spool_.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!spool_) {
        return Status::io_error;
    }
    memory.written += bytes.size();
    return Status::success;
}

Status MiniDumpWriter::finalize() noexcept {
    try {
        if (!begun_ || finalized_ || !has_metadata_) {
            return Status::invalid_state;
        }
        spool_.flush();
        spool_.close();
        std::sort(modules_.begin(), modules_.end(), [](const auto& left, const auto& right) { return left.base < right.base; });
        constexpr ULONG32 stream_count = 6;
        const auto directory_bytes = static_cast<std::size_t>(stream_count) * sizeof(MINIDUMP_DIRECTORY);
        std::size_t cursor = aligned4(sizeof(MINIDUMP_HEADER) + directory_bytes);
        const auto system_size = aligned4(sizeof(MINIDUMP_SYSTEM_INFO));
        const auto modules_size = module_stream_size(modules_);
        std::size_t copied_count{};
        for (const auto& memory : memories_) {
            copied_count += memory.written != 0 ? 1u : 0u;
        }
        const auto memory64_size = aligned4(sizeof(ULONG64) * 2 + copied_count * sizeof(MINIDUMP_MEMORY_DESCRIPTOR64));
        const auto memory_info_size = aligned4(sizeof(MINIDUMP_MEMORY_INFO_LIST) + memories_.size() * sizeof(MINIDUMP_MEMORY_INFO));
        const auto misc_size = aligned4(sizeof(MINIDUMP_MISC_INFO));
        const auto comment_size = aligned4((metadata_.comment.size() + 1) * sizeof(wchar_t));
        const auto payload_rva = cursor + system_size + modules_size + memory64_size + memory_info_size + misc_size + comment_size;
        if (payload_rva > std::numeric_limits<RVA>::max()) {
            return Status::range_overflow;
        }
        std::vector<StreamBlob> streams;
        auto system = make_system_stream(metadata_);
        system.rva = static_cast<RVA>(cursor);
        streams.push_back(std::move(system));
        cursor += system_size;
        streams.push_back(make_module_stream(modules_, static_cast<RVA>(cursor)));
        cursor += modules_size;
        auto memory64 = make_memory64_stream(memories_, payload_rva);
        memory64.rva = static_cast<RVA>(cursor);
        streams.push_back(std::move(memory64));
        cursor += memory64_size;
        auto memory_info = make_memory_info_stream(memories_);
        memory_info.rva = static_cast<RVA>(cursor);
        streams.push_back(std::move(memory_info));
        cursor += memory_info_size;
        auto misc = make_misc_stream(metadata_);
        misc.rva = static_cast<RVA>(cursor);
        streams.push_back(std::move(misc));
        cursor += misc_size;
        auto comment = make_comment_stream(metadata_.comment);
        comment.rva = static_cast<RVA>(cursor);
        streams.push_back(std::move(comment));

        MINIDUMP_HEADER header{};
        header.Signature = MINIDUMP_SIGNATURE;
        header.Version = MINIDUMP_VERSION;
        header.NumberOfStreams = stream_count;
        header.StreamDirectoryRva = sizeof(MINIDUMP_HEADER);
        header.TimeDateStamp = static_cast<ULONG32>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
        header.Flags = MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo;
        {
        std::ofstream output(partial_path_, std::ios::binary | std::ios::trunc);
        output.write(reinterpret_cast<const char*>(&header), sizeof(header));
        for (const auto& stream : streams) {
            MINIDUMP_DIRECTORY directory{};
            directory.StreamType = stream.type;
            directory.Location.DataSize = static_cast<ULONG32>(stream.data.size());
            directory.Location.Rva = stream.rva;
            output.write(reinterpret_cast<const char*>(&directory), sizeof(directory));
        }
        const auto header_end = static_cast<std::size_t>(output.tellp());
        const std::array<char, 4> zeros{};
        if (header_end < aligned4(header_end)) {
            output.write(zeros.data(), static_cast<std::streamsize>(aligned4(header_end) - header_end));
        }
        for (const auto& stream : streams) {
            output.seekp(stream.rva);
            output.write(reinterpret_cast<const char*>(stream.data.data()), static_cast<std::streamsize>(stream.data.size()));
        }
        output.seekp(static_cast<std::streamoff>(payload_rva - 1));
        output.put('\0');
        output.seekp(static_cast<std::streamoff>(payload_rva));
        std::ifstream spool(spool_path_, std::ios::binary);
        if (spool.peek() != std::char_traits<char>::eof()) {
            output << spool.rdbuf();
        }
        output.flush();
        if (!output) {
            return Status::io_error;
        }
        }
        const auto validation = validate_file(partial_path_);
        if (!validation.valid) {
            return validation.status;
        }
        if (!MoveFileExW(partial_path_.c_str(), final_path_.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            return Status::io_error;
        }
        finalized_ = true;
        cleanup_spool();
        return Status::success;
    } catch (...) {
        return Status::io_error;
    }
}

void MiniDumpWriter::discard(const bool keep_partial) noexcept {
    keep_partial_ = keep_partial;
    if (spool_.is_open()) {
        spool_.close();
    }
    cleanup_spool();
    if (!keep_partial_) {
        std::error_code ignored;
        std::filesystem::remove(partial_path_, ignored);
    }
}

DumpValidationResult MiniDumpWriter::validate_file(const std::filesystem::path& path) noexcept {
    DumpValidationResult result{};
    try {
        std::ifstream input(path, std::ios::binary);
        if (!input) {
            result.status = Status::io_error;
            return result;
        }
        input.seekg(0, std::ios::end);
        const auto file_size = static_cast<std::uint64_t>(input.tellg());
        input.seekg(0);
        MINIDUMP_HEADER header{};
        if (!read_exact(input, &header, sizeof(header)) || header.Signature != MINIDUMP_SIGNATURE || header.Version != MINIDUMP_VERSION || header.NumberOfStreams != 6) {
            result.failure_stage = 1;
            result.status = Status::validation_failure;
            return result;
        }
        if (header.StreamDirectoryRva > file_size || header.NumberOfStreams > (file_size - header.StreamDirectoryRva) / sizeof(MINIDUMP_DIRECTORY)) {
            result.failure_stage = 2;
            result.status = Status::validation_failure;
            return result;
        }
        input.seekg(header.StreamDirectoryRva);
        std::vector<MINIDUMP_DIRECTORY> directories(header.NumberOfStreams);
        if (!read_exact(input, directories.data(), directories.size() * sizeof(MINIDUMP_DIRECTORY))) {
            result.failure_stage = 3;
            result.status = Status::validation_failure;
            return result;
        }
        bool found_memory64{};
        for (const auto& directory : directories) {
            if (directory.Location.Rva > file_size || directory.Location.DataSize > file_size - directory.Location.Rva) {
                result.failure_stage = 4;
                result.status = Status::validation_failure;
                return result;
            }
            result.streams.push_back(directory.StreamType);
            if (directory.StreamType != Memory64ListStream) {
                continue;
            }
            found_memory64 = true;
            input.seekg(directory.Location.Rva);
            ULONG64 count{};
            RVA64 payload{};
            if (!read_exact(input, &count, sizeof(count)) || !read_exact(input, &payload, sizeof(payload)) || count > (file_size / sizeof(MINIDUMP_MEMORY_DESCRIPTOR64))) {
                result.failure_stage = 5;
                result.status = Status::validation_failure;
                return result;
            }
            std::uint64_t previous_end{};
            for (ULONG64 index = 0; index < count; ++index) {
                MINIDUMP_MEMORY_DESCRIPTOR64 descriptor{};
                if (!read_exact(input, &descriptor, sizeof(descriptor)) || descriptor.StartOfMemoryRange < previous_end || descriptor.StartOfMemoryRange > std::numeric_limits<std::uint64_t>::max() - descriptor.DataSize) {
                    result.failure_stage = 6;
                    result.status = Status::validation_failure;
                    return result;
                }
                if (index == 0) {
                    result.first_memory_base = descriptor.StartOfMemoryRange;
                }
                previous_end = descriptor.StartOfMemoryRange + descriptor.DataSize;
                result.memory_bytes += descriptor.DataSize;
                ++result.memory_ranges;
            }
            if (payload > file_size || result.memory_bytes > file_size - payload) {
                result.failure_stage = 7;
                result.status = Status::validation_failure;
                return result;
            }
        }
        result.valid = found_memory64;
        result.status = result.valid ? Status::success : Status::validation_failure;
        return result;
    } catch (...) {
        result.status = Status::io_error;
        return result;
    }
}

void MiniDumpWriter::cleanup_spool() noexcept {
    std::error_code ignored;
    std::filesystem::remove(spool_path_, ignored);
}

}
