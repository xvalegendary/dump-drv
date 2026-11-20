#include "symbol_table.hxx"

namespace dump::driver {

NTSTATUS SymbolTable::set(const protocol::SymbolPacket& packet, PEPROCESS process) noexcept {
    if (!process || packet.eprocess_size == 0 || packet.eprocess_size > 0x4000 || packet.unique_process_id >= packet.eprocess_size || packet.image_file_name >= packet.eprocess_size) {
        return STATUS_INVALID_PARAMETER;
    }
    __try {
        const auto* bytes = reinterpret_cast<const unsigned char*>(process);
        const auto stored_pid = *reinterpret_cast<const HANDLE*>(bytes + packet.unique_process_id);
        if (stored_pid != PsGetProcessId(process)) {
            return STATUS_REVISION_MISMATCH;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    packet_ = packet;
    valid_ = true;
    return STATUS_SUCCESS;
}

const protocol::SymbolPacket& SymbolTable::packet() const noexcept {
    return packet_;
}

bool SymbolTable::valid() const noexcept {
    return valid_;
}

}
