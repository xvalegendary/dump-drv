#include "test.hxx"

#include "dumper/crypto.hxx"
#include "dumper/symbol_resolver.hxx"

#include <algorithm>
#include <array>
#include <filesystem>
#include <map>
#include <string>
#include <utility>

namespace {

class FakeProvider final : public dump::ISymbolProvider {
public:
    dump::Result<dump::KernelSymbolIdentity> identity() override {
        if (identity_status != dump::Status::success) {
            return identity_status;
        }
        return identity_value;
    }

    dump::Result<dump::SymbolType> type(const std::wstring_view name) override {
        const auto found = types.find(std::wstring(name));
        if (found == types.end()) {
            return dump::Status::invalid_symbol_packet;
        }
        return found->second;
    }

    dump::Status identity_status{dump::Status::success};
    dump::KernelSymbolIdentity identity_value{};
    std::map<std::wstring, dump::SymbolType> types;
};

FakeProvider provider_with_epocess() {
    FakeProvider provider;
    provider.identity_value.identity.timestamp = 0x11223344;
    provider.identity_value.identity.image_size = 0x900000;
    provider.identity_value.identity.pdb_age = 7;
    provider.identity_value.identity.pdb_guid.fill(0x42);
    dump::SymbolType eprocess{0x900, {
        {L"Pcb", 0x0, 0x400, L"_KPROCESS"},
        {L"UniqueProcessId", 0x440, 8, L""},
        {L"ActiveProcessLinks", 0x448, 16, L""},
        {L"ImageFileName", 0x5a8, 15, L""},
        {L"VadRoot", 0x7d8, 8, L""}
    }};
    dump::SymbolType kprocess{0x400, {{L"DirectoryTableBase", 0x28, 8, L""}}};
    provider.types.emplace(L"_EPROCESS", std::move(eprocess));
    provider.types.emplace(L"_KPROCESS", std::move(kprocess));
    return provider;
}

}

TEST_CASE("symbols", symbol_resolver_resolves_recursive_and_exact_offsets) {
    auto provider = provider_with_epocess();
    dump::SymbolResolver resolver(provider);
    auto result = resolver.resolve();
    REQUIRE(static_cast<bool>(result));
    const auto& packet = result.value();
    REQUIRE(packet.directory_table_base == 0x28);
    REQUIRE(packet.unique_process_id == 0x440);
    REQUIRE(packet.active_process_links == 0x448);
    REQUIRE(packet.image_file_name == 0x5a8);
    REQUIRE(packet.vad_root == 0x7d8);
}

TEST_CASE("symbols", symbol_resolver_rejects_missing_kernel_identity) {
    auto provider = provider_with_epocess();
    provider.identity_status = dump::Status::io_error;
    dump::SymbolResolver resolver(provider);
    const auto result = resolver.resolve();
    REQUIRE(!result);
    REQUIRE(result.status() == dump::Status::io_error);
}

TEST_CASE("symbols", symbol_resolver_rejects_field_outside_type) {
    auto provider = provider_with_epocess();
    provider.types[L"_EPROCESS"].size = 0x100;
    dump::SymbolResolver resolver(provider);
    const auto result = resolver.resolve();
    REQUIRE(!result);
    REQUIRE(result.status() == dump::Status::invalid_symbol_packet);
}

TEST_CASE("symbols", symbol_packet_hash_is_deterministic) {
    auto provider = provider_with_epocess();
    dump::SymbolResolver resolver(provider);
    const auto first = resolver.resolve();
    const auto second = resolver.resolve();
    REQUIRE(first && second);
    REQUIRE(first.value().packet_hash == second.value().packet_hash);
    REQUIRE(std::any_of(first.value().packet_hash.begin(), first.value().packet_hash.end(), [](const auto value) { return value != 0; }));
}

TEST_CASE("symbols", symbol_resolver_marks_optional_field_unavailable) {
    auto provider = provider_with_epocess();
    auto& fields = provider.types[L"_EPROCESS"].fields;
    fields.erase(std::remove_if(fields.begin(), fields.end(), [](const auto& field) { return field.name == L"VadRoot"; }), fields.end());
    dump::SymbolResolver resolver(provider);
    const auto result = resolver.resolve();
    REQUIRE(result);
    REQUIRE(result.value().vad_root == dump::protocol::unavailable_offset);
}

TEST_CASE("symbols-live", symbol_resolver_uses_live_kernel_identity_or_exact_error) {
    dump::DbgHelpSymbolProvider provider(std::filesystem::current_path() / L"symbols");
    dump::SymbolResolver resolver(provider);
    const auto result = resolver.resolve();
    if (result) {
        REQUIRE(result.value().kernel_timestamp != 0);
        REQUIRE(result.value().kernel_image_size != 0);
        REQUIRE(result.value().unique_process_id != dump::protocol::unavailable_offset);
        REQUIRE(result.value().image_file_name != dump::protocol::unavailable_offset);
    } else {
        REQUIRE(result.status() != dump::Status::success);
    }
}
