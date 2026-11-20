#include "blob_encoder.hxx"

#include <iostream>
#include <string_view>

int wmain(const int argc, wchar_t** argv) {
    if (argc == 4 && std::wstring_view(argv[1]) == L"--verify") {
        const auto status = dump::blob::verify(argv[2], argv[3]);
        if (status != dump::Status::success) {
            std::wcerr << L"[-] blob verification failed: " << static_cast<unsigned long>(status) << L'\n';
            return 1;
        }
        std::wcout << L"[+] driver blob verified\n";
        return 0;
    }
    if (argc != 3) {
        std::wcerr << L"[-] usage: BlobGen.exe Driver.sys driver_blob.hxx\n";
        return 2;
    }
    const auto status = dump::blob::write_if_changed(argv[1], argv[2]);
    if (status != dump::Status::success) {
        std::wcerr << L"[-] blob generation failed: " << static_cast<unsigned long>(status) << L'\n';
        return 1;
    }
    std::wcout << L"[+] driver blob generated\n";
    return 0;
}
