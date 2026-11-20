#include "application.hxx"

#include <cerrno>
#include <cwchar>
#include <iomanip>
#include <limits>
#include <sstream>

namespace {

std::wstring sanitize(std::wstring name) {
    for (auto& value : name) {
        if (value < 32 || value == L'<' || value == L'>' || value == L':' || value == L'"' || value == L'/' || value == L'\\' || value == L'|' || value == L'?' || value == L'*') value = L'_';
    }
    return name;
}

}

namespace dump {

Result<Options> parse_options(const std::span<const std::wstring_view> arguments) noexcept {
    try {
        Options result{};
        result.output_directory = std::filesystem::current_path();
        for (std::size_t index = 0; index < arguments.size(); ++index) {
            const auto argument = arguments[index];
            if (argument == L"--keep-partial") {
                result.keep_partial = true;
            } else if (argument == L"--output") {
                if (++index == arguments.size() || arguments[index].empty()) return Status::invalid_argument;
                result.output_directory = arguments[index];
            } else if (argument == L"--pid") {
                if (++index == arguments.size()) return Status::invalid_argument;
                const auto text = arguments[index];
                const std::wstring owned(text);
                wchar_t* end{};
                errno = 0;
                const auto parsed = std::wcstoul(owned.c_str(), &end, 10);
                if (errno == ERANGE || end != owned.c_str() + owned.size() || parsed == 0 || parsed > std::numeric_limits<std::uint32_t>::max()) return Status::invalid_argument;
                result.process_id = static_cast<std::uint32_t>(parsed);
            } else if (!argument.empty() && argument.front() == L'-') {
                return Status::invalid_argument;
            } else if (!result.process_name.empty()) {
                return Status::invalid_argument;
            } else {
                result.process_name.assign(argument);
            }
        }
        if (result.process_id.has_value() == !result.process_name.empty()) {
            return Status::invalid_argument;
        }
        return result;
    } catch (...) {
        return Status::io_error;
    }
}

std::wstring make_output_stem(const std::wstring_view process_name, const std::tm& local_time) {
    std::wostringstream stream;
    stream << L"dumped-" << std::put_time(&local_time, L"%Y%m%d-%H%M%S") << L'-' << sanitize(std::wstring(process_name));
    return stream.str();
}

}
