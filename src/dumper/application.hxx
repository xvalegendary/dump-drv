#pragma once

#include "console.hxx"
#include "shared/status.hxx"

#include <cstdint>
#include <ctime>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace dump {

enum class Mode : unsigned int {
    dump = 0,
    sections,
    sections_and_dump
};

struct Options {
    std::optional<std::uint32_t> process_id;
    std::wstring process_name;
    std::filesystem::path output_directory;
    std::wstring module_name;
    Mode mode{Mode::dump};
    std::uint32_t net_seconds{30};
    bool keep_partial{};
    bool conceal{true};
    bool net{};
    bool explicit_mode{};
};

Result<Options> parse_options(std::span<const std::wstring_view> arguments) noexcept;
std::wstring make_output_stem(std::wstring_view process_name, const std::tm& local_time);

class Application {
public:
    explicit Application(IConsole& console) noexcept;
    int run(std::span<const std::wstring_view> arguments) noexcept;

private:
    IConsole& console_;
};

}