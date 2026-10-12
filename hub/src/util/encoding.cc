#include "util/encoding.h"

#include <array>
#include <cctype>

namespace douve {
namespace {
constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

constexpr std::array<int, 256> makeDecodeTable() {
    std::array<int, 256> t{};
    for (auto& v : t)
        v = -1;
    for (int i = 0; i < 64; ++i)
        t[static_cast<unsigned char>(kAlphabet[i])] = i;
    // 표준 base64 문자도 관대하게 허용 (일부 구현이 섞어 보냄)
    t[static_cast<unsigned char>('+')] = 62;
    t[static_cast<unsigned char>('/')] = 63;
    return t;
}
constexpr auto kDecode = makeDecodeTable();
} // namespace

std::string base64UrlEncode(const std::uint8_t* data, std::size_t len) {
    std::string out;
    out.reserve((len + 2) / 3 * 4);
    std::size_t i = 0;
    for (; i + 2 < len; i += 3) {
        std::uint32_t v = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out += kAlphabet[(v >> 18) & 63];
        out += kAlphabet[(v >> 12) & 63];
        out += kAlphabet[(v >> 6) & 63];
        out += kAlphabet[v & 63];
    }
    if (len - i == 1) {
        std::uint32_t v = data[i] << 16;
        out += kAlphabet[(v >> 18) & 63];
        out += kAlphabet[(v >> 12) & 63];
    } else if (len - i == 2) {
        std::uint32_t v = (data[i] << 16) | (data[i + 1] << 8);
        out += kAlphabet[(v >> 18) & 63];
        out += kAlphabet[(v >> 12) & 63];
        out += kAlphabet[(v >> 6) & 63];
    }
    return out;
}

std::optional<Bytes> base64UrlDecode(std::string_view in) {
    while (!in.empty() && in.back() == '=')
        in.remove_suffix(1);
    if (in.size() % 4 == 1)
        return std::nullopt;
    Bytes out;
    out.reserve(in.size() * 3 / 4);
    std::uint32_t buf = 0;
    int bits = 0;
    for (char c : in) {
        int v = kDecode[static_cast<unsigned char>(c)];
        if (v < 0)
            return std::nullopt;
        buf = (buf << 6) | static_cast<std::uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((buf >> bits) & 0xFF));
        }
    }
    // 남은 비트가 0이 아니면 정규형이 아닌 입력 → 거부
    if (bits > 0 && (buf & ((1u << bits) - 1)) != 0)
        return std::nullopt;
    return out;
}

std::string toHex(const Bytes& b) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (auto x : b) {
        s += kHex[x >> 4];
        s += kHex[x & 15];
    }
    return s;
}

std::string urlEncode(std::string_view s) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += kHex[c >> 4];
            out += kHex[c & 15];
        }
    }
    return out;
}

} // namespace douve
