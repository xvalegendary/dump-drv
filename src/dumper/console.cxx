#include "console.hxx"

#include <iostream>

namespace dump {

void Console::success(const std::wstring_view message) {
    std::wcout << L"[+] " << message << L'\n' << std::flush;
}

void Console::progress(const std::wstring_view message) {
    std::wcout << L"[~] " << message << L'\n' << std::flush;
}

void Console::error(const std::wstring_view message) {
    std::wcerr << L"[-] " << message << L'\n' << std::flush;
}

}
