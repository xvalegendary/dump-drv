#include "manifest_writer.hxx"

#define NOMINMAX
#include <Windows.h>
#include <bcrypt.h>

#include <array>
#include <iomanip>
#include <sstream>
#include <system_error>
#include <vector>

namespace {

std::string utf8(const std::wstring_view value) {
    if (value.empty()) {
        return {};
    }
    const auto required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return {};
    }
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), required, nullptr, nullptr) != required) {
        return {};
    }
    return result;
}

dump::Result<std::array<unsigned char, 32>> file_digest(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return dump::Status::io_error;
    }
    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_HASH_HANDLE hash{};
    DWORD object_size{};
    DWORD received{};
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) ||
        !BCRYPT_SUCCESS(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &received, 0))) {
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
        return dump::Status::io_error;
    }
    std::vector<unsigned char> object(object_size);
    if (!BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, object.data(), object_size, nullptr, 0, 0))) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return dump::Status::io_error;
    }
    std::vector<unsigned char> buffer(1024 * 1024);
    while (input) {
        input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count > 0 && !BCRYPT_SUCCESS(BCryptHashData(hash, buffer.data(), static_cast<ULONG>(count), 0))) {
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(algorithm, 0);
            return dump::Status::io_error;
        }
    }
    std::array<unsigned char, 32> digest{};
    const auto success = BCRYPT_SUCCESS(BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0));
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return success ? dump::Result<std::array<unsigned char, 32>>(digest) : dump::Result<std::array<unsigned char, 32>>(dump::Status::io_error);
}

}

namespace dump {

ManifestWriter::~ManifestWriter() {
    if (stream_.is_open()) {
        stream_.close();
    }
    if (!finalized_ && !keep_partial_) {
        std::error_code ignored;
        std::filesystem::remove(partial_path_, ignored);
    }
}

Status ManifestWriter::begin(const std::filesystem::path& final_path) noexcept {
    try {
        if (stream_.is_open() || final_path.empty()) {
            return Status::invalid_state;
        }
        final_path_ = final_path;
        partial_path_ = final_path_.wstring() + L".partial";
        std::filesystem::create_directories(final_path_.parent_path());
        stream_.open(partial_path_, std::ios::binary | std::ios::trunc);
        if (!stream_) {
            return Status::io_error;
        }
        const unsigned char bom[]{0xef, 0xbb, 0xbf};
        stream_.write(reinterpret_cast<const char*>(bom), sizeof(bom));
        return stream_ ? Status::success : Status::io_error;
    } catch (...) {
        return Status::io_error;
    }
}

Status ManifestWriter::write(const std::string_view prefix, const std::wstring_view message) noexcept {
    if (!stream_.is_open() || finalized_) {
        return Status::invalid_state;
    }
    const auto encoded = utf8(message);
    if (!message.empty() && encoded.empty()) {
        return Status::io_error;
    }
    stream_.write(prefix.data(), static_cast<std::streamsize>(prefix.size()));
    stream_.write(encoded.data(), static_cast<std::streamsize>(encoded.size()));
    stream_.put('\n');
    return stream_ ? Status::success : Status::io_error;
}

Status ManifestWriter::success(const std::wstring_view message) noexcept { return write("[+] ", message); }
Status ManifestWriter::progress(const std::wstring_view message) noexcept { return write("[~] ", message); }
Status ManifestWriter::error(const std::wstring_view message) noexcept { return write("[-] ", message); }

Status ManifestWriter::region(const std::size_t index, const protocol::RegionDescriptor& descriptor, const std::uint64_t copied, const std::int32_t native_status) noexcept {
    std::wostringstream line;
    line << L"region=" << index << L" base=0x" << std::hex << descriptor.base << L" size=0x" << descriptor.size << L" state=0x" << static_cast<std::uint32_t>(descriptor.state) << L" type=0x" << static_cast<std::uint32_t>(descriptor.type) << L" protect=0x" << descriptor.protect << L" copied=0x" << copied << L" status=0x" << static_cast<std::uint32_t>(native_status);
    return progress(line.str());
}

Status ManifestWriter::finalize(const std::filesystem::path& dump_path) noexcept {
    try {
        if (!stream_.is_open() || finalized_) {
            return Status::invalid_state;
        }
        const auto digest = file_digest(dump_path);
        if (!digest) {
            return digest.status();
        }
        std::wostringstream line;
        line << L"sha256=" << std::hex << std::setfill(L'0');
        for (const auto value : digest.value()) {
            line << std::setw(2) << static_cast<unsigned int>(value);
        }
        const auto status = success(line.str());
        if (status != Status::success) {
            return status;
        }
        return finalize();
    } catch (...) {
        return Status::io_error;
    }
}

Status ManifestWriter::finalize() noexcept {
    try {
        if (!stream_.is_open() || finalized_) {
            return Status::invalid_state;
        }
        stream_.flush();
        stream_.close();
        if (!MoveFileExW(partial_path_.c_str(), final_path_.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            return Status::io_error;
        }
        finalized_ = true;
        return Status::success;
    } catch (...) {
        return Status::io_error;
    }
}

void ManifestWriter::discard(const bool keep_partial) noexcept {
    keep_partial_ = keep_partial;
    if (stream_.is_open()) {
        stream_.close();
    }
    if (!keep_partial_) {
        std::error_code ignored;
        std::filesystem::remove(partial_path_, ignored);
    }
}

}
