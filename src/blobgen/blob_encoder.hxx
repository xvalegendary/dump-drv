#pragma once

#include "shared/status.hxx"

#include <cstddef>
#include <filesystem>
#include <span>
#include <string>

namespace dump::blob {

std::string encode(std::span<const std::byte> bytes);
Status write_if_changed(const std::filesystem::path& input, const std::filesystem::path& output) noexcept;
Status verify(const std::filesystem::path& input, const std::filesystem::path& header) noexcept;

}
