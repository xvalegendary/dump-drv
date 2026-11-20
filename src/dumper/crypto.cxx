#include "crypto.hxx"

#include <Windows.h>
#include <bcrypt.h>

#include <vector>

namespace dump::crypto {

protocol::FixedArray<std::uint8_t, 32> sha256(const std::span<const std::byte> bytes) noexcept {
    protocol::FixedArray<std::uint8_t, 32> digest{};
    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_HASH_HANDLE hash{};
    DWORD object_size{};
    DWORD received{};
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) {
        return digest;
    }
    if (!BCRYPT_SUCCESS(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &received, 0))) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return digest;
    }
    std::vector<std::uint8_t> object(object_size);
    if (BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, object.data(), object_size, nullptr, 0, 0)) &&
        BCRYPT_SUCCESS(BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()), 0))) {
        BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    }
    if (hash) {
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return digest;
}

protocol::Nonce random_nonce() noexcept {
    protocol::Nonce nonce{};
    BCryptGenRandom(nullptr, nonce.data(), static_cast<ULONG>(nonce.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return nonce;
}

}
