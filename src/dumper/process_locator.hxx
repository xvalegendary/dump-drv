#pragma once

#include "shared/status.hxx"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace dump {

struct ProcessInfo {
    std::uint32_t process_id{};
    std::wstring name;
    std::size_t match_count{1};
};

class ProcessLocator {
public:
    static Result<std::vector<ProcessInfo>> enumerate() noexcept;
    static Result<ProcessInfo> select(std::span<const ProcessInfo> processes, std::optional<std::uint32_t> process_id, std::wstring_view name) noexcept;
    static Result<ProcessInfo> find(std::optional<std::uint32_t> process_id, std::wstring_view name) noexcept;
};

}
