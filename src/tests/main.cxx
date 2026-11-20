#include "test.hxx"

#include <iostream>
#include <string>

int wmain(int argc, wchar_t** argv) {
    std::wstring filter;
    if (argc == 3 && std::wstring_view(argv[1]) == L"--suite") {
        filter.assign(argv[2]);
    }

    std::size_t passed = 0;
    std::size_t failed = 0;
    for (const auto& entry : test::registry()) {
        const std::wstring suite(entry.suite.begin(), entry.suite.end());
        if (!filter.empty() && suite != filter) {
            continue;
        }
        try {
            entry.run();
            ++passed;
            std::cout << "[+] " << entry.suite << ":" << entry.name << '\n';
        } catch (const std::exception& error) {
            ++failed;
            std::cout << "[-] " << entry.suite << ":" << entry.name << " " << error.what() << '\n';
        }
    }
    std::cout << "[~] passed=" << passed << " failed=" << failed << '\n';
    return failed == 0 && passed != 0 ? 0 : 1;
}
