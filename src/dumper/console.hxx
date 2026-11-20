#pragma once

#include <string_view>

namespace dump {

class IConsole {
public:
    virtual ~IConsole() = default;
    virtual void success(std::wstring_view message) = 0;
    virtual void progress(std::wstring_view message) = 0;
    virtual void error(std::wstring_view message) = 0;
};

class Console final : public IConsole {
public:
    void success(std::wstring_view message) override;
    void progress(std::wstring_view message) override;
    void error(std::wstring_view message) override;
};

}
