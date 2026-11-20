#include "test.hxx"

#include "dumper/application.hxx"
#include "dumper/manifest_writer.hxx"
#include "dumper/process_locator.hxx"

#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

TEST_CASE("application", application_parses_name_and_output_options) {
    const std::array<std::wstring_view, 4> arguments{L"--output", L"C:\\dumps", L"--keep-partial", L"malware.exe"};
    const auto options = dump::parse_options(arguments);
    REQUIRE(options);
    REQUIRE(options.value().process_name == L"malware.exe");
    REQUIRE(options.value().output_directory == L"C:\\dumps");
    REQUIRE(options.value().keep_partial);
    REQUIRE(!options.value().process_id.has_value());
}

TEST_CASE("application", application_parses_pid_and_rejects_mixed_target) {
    const std::array<std::wstring_view, 2> pid_arguments{L"--pid", L"1234"};
    const auto pid = dump::parse_options(pid_arguments);
    REQUIRE(pid);
    REQUIRE(pid.value().process_id == std::uint32_t{1234});
    const std::array<std::wstring_view, 3> mixed{L"--pid", L"1234", L"malware.exe"};
    REQUIRE(dump::parse_options(mixed).status() == dump::Status::invalid_argument);
}

TEST_CASE("application", application_formats_exact_output_name) {
    std::tm time{};
    time.tm_year = 126;
    time.tm_mon = 10;
    time.tm_mday = 17;
    time.tm_hour = 12;
    time.tm_min = 1;
    time.tm_sec = 2;
    REQUIRE(dump::make_output_stem(L"malware.exe", time) == L"dumped-20261117-120102-malware.exe");
}

TEST_CASE("application", application_selects_highest_pid_for_ambiguous_process_name) {
    const std::array processes{dump::ProcessInfo{10, L"malware.exe"}, dump::ProcessInfo{11, L"Malware.exe"}};
    const auto selected = dump::ProcessLocator::select(processes, std::nullopt, L"malware.exe");
    REQUIRE(selected);
    REQUIRE(selected.value().process_id == std::uint32_t{11});
    REQUIRE(selected.value().match_count == std::size_t{2});
}

TEST_CASE("application", application_manifest_uses_required_log_prefixes) {
    const auto root = std::filesystem::temp_directory_path() / L"dump-driver-manifest-test";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);
    const auto dump_path = root / L"sample.dmp";
    const auto manifest_path = root / L"sample.txt";
    {
        std::ofstream dump(dump_path, std::ios::binary);
        dump << "sample";
    }
    dump::ManifestWriter manifest;
    REQUIRE(manifest.begin(manifest_path) == dump::Status::success);
    REQUIRE(manifest.success(L"attached to malware.exe") == dump::Status::success);
    REQUIRE(manifest.progress(L"region=0") == dump::Status::success);
    REQUIRE(manifest.error(L"partial copy") == dump::Status::success);
    REQUIRE(manifest.finalize(dump_path) == dump::Status::success);
    std::ifstream input(manifest_path, std::ios::binary);
    const std::string text((std::istreambuf_iterator<char>(input)), {});
    REQUIRE(text.find("[+] attached to malware.exe") != std::string::npos);
    REQUIRE(text.find("[~] region=0") != std::string::npos);
    REQUIRE(text.find("[-] partial copy") != std::string::npos);
    REQUIRE(text.find("[+] sha256=") != std::string::npos);
    input.close();
    std::filesystem::remove_all(root);
}
