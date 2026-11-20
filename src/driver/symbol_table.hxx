#pragma once

#include <ntifs.h>

#include "shared/protocol.hxx"

namespace dump::driver {

class SymbolTable {
public:
    NTSTATUS set(const protocol::SymbolPacket& packet, PEPROCESS process) noexcept;
    [[nodiscard]] const protocol::SymbolPacket& packet() const noexcept;
    [[nodiscard]] bool valid() const noexcept;

private:
    protocol::SymbolPacket packet_{};
    bool valid_{};
};

}
