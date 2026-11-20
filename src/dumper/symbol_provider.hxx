#pragma once

#include "shared/protocol.hxx"
#include "shared/status.hxx"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace dump {

struct SymbolField {
    std::wstring name;
    std::uint32_t offset{};
    std::uint64_t size{};
    std::wstring type_name;
};

struct SymbolType {
    std::uint64_t size{};
    std::vector<SymbolField> fields;
};

struct KernelSymbolIdentity {
    protocol::KernelIdentity identity{};
    std::uint64_t kernel_base{};
    std::filesystem::path image_path;
};

class ISymbolProvider {
public:
    virtual ~ISymbolProvider() = default;
    virtual Result<KernelSymbolIdentity> identity() = 0;
    virtual Result<SymbolType> type(std::wstring_view name) = 0;
};

class DbgHelpSymbolProvider final : public ISymbolProvider {
public:
    explicit DbgHelpSymbolProvider(std::filesystem::path cache);
    ~DbgHelpSymbolProvider() override;
    Result<KernelSymbolIdentity> identity() override;
    Result<SymbolType> type(std::wstring_view name) override;

private:
    Status initialize() noexcept;

    std::filesystem::path cache_;
    KernelSymbolIdentity identity_{};
    std::uint64_t symbol_base_{};
    bool initialized_{};
    bool attempted_{};
};

}
