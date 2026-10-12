#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace douve {

using Bytes = std::vector<std::uint8_t>;

// RFC 4648 §5 base64url, 패딩 없음 (WebAuthn·JWT 표준 형식).
std::string base64UrlEncode(const std::uint8_t* data, std::size_t len);
inline std::string base64UrlEncode(const Bytes& b) {
    return base64UrlEncode(b.data(), b.size());
}
inline std::string base64UrlEncode(std::string_view s) {
    return base64UrlEncode(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}
// 패딩('=')은 허용하되 그 외 문자가 있으면 nullopt.
std::optional<Bytes> base64UrlDecode(std::string_view in);

std::string toHex(const Bytes& b);

// application/x-www-form-urlencoded 및 쿼리 문자열용 퍼센트 인코딩 (RFC 3986 unreserved 외 모두
// 인코딩).
std::string urlEncode(std::string_view s);

inline Bytes toBytes(std::string_view s) {
    return Bytes(s.begin(), s.end());
}
inline std::string toString(const Bytes& b) {
    return std::string(b.begin(), b.end());
}

} // namespace douve
