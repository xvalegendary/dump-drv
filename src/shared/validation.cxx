#ifdef _KERNEL_MODE
#include <ntifs.h>
#endif

#include "validation.hxx"

namespace dump::validation {

Status validate_header(const protocol::Header& header, const protocol::Nonce& expected_nonce, const protocol::usize actual_size) noexcept {
    if (header.magic != protocol::magic) {
        return Status::invalid_magic;
    }
    if (header.version != protocol::version) {
        return Status::version_mismatch;
    }
    if (header.size != actual_size) {
        return Status::size_mismatch;
    }
    for (protocol::usize index = 0; index < header.nonce.size(); ++index) {
        if (header.nonce[index] != expected_nonce[index]) {
            return Status::nonce_mismatch;
        }
    }
    return Status::success;
}

Status validate_range(const protocol::u64 base, const protocol::u64 size) noexcept {
    if (size == 0) {
        return Status::invalid_argument;
    }
    if (base > ~protocol::u64{0} - size) {
        return Status::range_overflow;
    }
    constexpr protocol::u64 highest_user_address = 0x00007fffffffffff;
    if (base > highest_user_address || base + size - 1 > highest_user_address) {
        return Status::noncanonical_address;
    }
    return Status::success;
}

Status validate_symbol_packet(const protocol::SymbolPacket& packet, const protocol::KernelIdentity& running) noexcept {
    if (packet.kernel_timestamp != running.timestamp || packet.kernel_image_size != running.image_size || packet.pdb_guid != running.pdb_guid || packet.pdb_age != running.pdb_age) {
        return Status::kernel_identity_mismatch;
    }
    if (packet.eprocess_size == 0 || packet.eprocess_size > 0x4000) {
        return Status::invalid_symbol_packet;
    }
    const protocol::u32 offsets[] = {packet.unique_process_id, packet.active_process_links, packet.image_file_name, packet.vad_root};
    for (const auto offset : offsets) {
        if (offset != protocol::unavailable_offset && offset >= packet.eprocess_size) {
            return Status::invalid_symbol_packet;
        }
    }
    if (packet.directory_table_base != protocol::unavailable_offset && packet.directory_table_base >= 0x1000) {
        return Status::invalid_symbol_packet;
    }
    return Status::success;
}

Status validate_sequence(const protocol::u64 incoming, const protocol::u64 last_accepted) noexcept {
    return incoming > last_accepted ? Status::success : Status::sequence_replay;
}

}
