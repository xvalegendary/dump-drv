#include "test.hxx"

#include "blobgen/blob_encoder.hxx"

#include <array>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>

TEST_CASE("blob", blob_encodes_exact_bytes_and_size) {
    const std::array bytes{std::byte{0x00}, std::byte{0x7f}, std::byte{0x80}, std::byte{0xff}};
    const auto text = dump::blob::encode(bytes);
    REQUIRE(text.find("0x00, 0x7f, 0x80, 0xff") != std::string::npos);
    REQUIRE(text.find("driver_blob_size = 4;") != std::string::npos);
    REQUIRE(text.find("namespace dump::embedded") != std::string::npos);
    REQUIRE(text.find("\r") == std::string::npos);
    REQUIRE(text.back() == '\n');
}

TEST_CASE("blob", blob_output_is_stable) {
    const std::array bytes{std::byte{0x13}, std::byte{0x37}};
    REQUIRE(dump::blob::encode(bytes) == dump::blob::encode(bytes));
}

TEST_CASE("blob", blob_rejects_empty_input) {
    const auto root = std::filesystem::temp_directory_path() / L"dump-driver-blob-empty";
    std::filesystem::create_directories(root);
    const auto input = root / L"empty.sys";
    const auto output = root / L"driver_blob.hxx";
    std::ofstream(input, std::ios::binary).close();
    REQUIRE(dump::blob::write_if_changed(input, output) == dump::Status::invalid_argument);
    std::filesystem::remove_all(root);
}

TEST_CASE("blob", blob_second_write_is_identical) {
    const auto root = std::filesystem::temp_directory_path() / L"dump-driver-blob-stable";
    std::filesystem::create_directories(root);
    const auto input = root / L"driver.sys";
    const auto output = root / L"driver_blob.hxx";
    const std::array bytes{std::byte{0x00}, std::byte{0x7f}, std::byte{0x80}, std::byte{0xff}};
    {
        std::ofstream stream(input, std::ios::binary);
        stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    REQUIRE(dump::blob::write_if_changed(input, output) == dump::Status::success);
    std::string first;
    {
        std::ifstream first_stream(output, std::ios::binary);
        first.assign(std::istreambuf_iterator<char>(first_stream), {});
    }
    REQUIRE(dump::blob::write_if_changed(input, output) == dump::Status::success);
    std::string second;
    {
        std::ifstream second_stream(output, std::ios::binary);
        second.assign(std::istreambuf_iterator<char>(second_stream), {});
    }
    REQUIRE(first == second);
    REQUIRE(dump::blob::verify(input, output) == dump::Status::success);
    {
        std::ofstream stream(input, std::ios::binary | std::ios::app);
        stream.put('\x42');
    }
    REQUIRE(dump::blob::verify(input, output) == dump::Status::validation_failure);
    std::filesystem::remove_all(root);
}
