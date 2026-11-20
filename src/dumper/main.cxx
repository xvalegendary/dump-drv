#include "application.hxx"
#include "console.hxx"

#include <iostream>
#include <string>
#include <string_view>
#include <vector>

int wmain(const int argc, wchar_t** argv) {
    std::vector<std::wstring_view> arguments;
    bool pause = true;
    for (int index = 1; index < argc; ++index) {
        if (std::wstring_view(argv[index]) == L"--no-pause") pause = false;
        else arguments.emplace_back(argv[index]);
    }
    dump::Console console;
    dump::Application application(console);
    const auto result = application.run(arguments);
    if (pause) {
        std::wcout << L"[~] press Enter to exit\n";
        std::wstring line;
        std::getline(std::wcin, line);
    }
    return result;
}
