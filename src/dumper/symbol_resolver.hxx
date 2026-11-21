#pragma once

#include "symbol_provider.hxx"

#include <string_view>

namespace dump {

class SymbolResolver {
public:
    explicit SymbolResolver(ISymbolProvider& provider) noexcept;
    Result<protocol::SymbolPacket> resolve() noexcept;
    Result<protocol::ConcealTargets> resolve_conceal(std::wstring_view module_name) noexcept;

private:
    Result<std::uint32_t> field_offset(std::wstring_view root_type, std::wstring_view path) noexcept;

    ISymbolProvider& provider_;
};

}
