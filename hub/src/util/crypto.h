#pragma once

#include "util/encoding.h"

namespace douve {

// 암호학적으로 안전한 난수 (OpenSSL RAND_bytes). 실패 시 예외.
Bytes randomBytes(std::size_t n);
// URL에 바로 쓸 수 있는 랜덤 토큰 (기본 32바이트 = 256비트).
std::string randomToken(std::size_t bytes = 32);

Bytes sha256(const std::uint8_t* data, std::size_t len);
inline Bytes sha256(const Bytes& b) {
    return sha256(b.data(), b.size());
}
inline Bytes sha256(std::string_view s) {
    return sha256(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}

// Ed25519 서명 검증 (RFC 8032). 공개키 32바이트, 서명 64바이트.
bool ed25519Verify(const Bytes& publicKey, std::string_view message, const Bytes& signature);

// HMAC-SHA256 (웹훅 서명용)
Bytes hmacSha256(std::string_view key, std::string_view message);

// 타이밍 공격을 피하는 비교.
bool constantTimeEquals(const Bytes& a, const Bytes& b);

} // namespace douve
