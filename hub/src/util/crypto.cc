#include "util/crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <stdexcept>

namespace douve {

Bytes randomBytes(std::size_t n) {
    Bytes b(n);
    if (n > 0 && RAND_bytes(b.data(), static_cast<int>(n)) != 1) {
        throw std::runtime_error("RAND_bytes 실패");
    }
    return b;
}

std::string randomToken(std::size_t bytes) {
    return base64UrlEncode(randomBytes(bytes));
}

Bytes sha256(const std::uint8_t* data, std::size_t len) {
    Bytes out(32);
    unsigned int outLen = 0;
    if (EVP_Digest(data, len, out.data(), &outLen, EVP_sha256(), nullptr) != 1 || outLen != 32) {
        throw std::runtime_error("SHA-256 실패");
    }
    return out;
}

bool ed25519Verify(const Bytes& publicKey, std::string_view message, const Bytes& signature) {
    if (publicKey.size() != 32 || signature.size() != 64)
        return false;
    EVP_PKEY* key =
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, publicKey.data(), publicKey.size());
    if (!key)
        return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = ctx && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, key) == 1 &&
              EVP_DigestVerify(ctx, signature.data(), signature.size(),
                               reinterpret_cast<const unsigned char*>(message.data()),
                               message.size()) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

bool constantTimeEquals(const Bytes& a, const Bytes& b) {
    return a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

Bytes hmacSha256(std::string_view key, std::string_view message) {
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
              reinterpret_cast<const unsigned char*>(message.data()), message.size(), out, &len))
        throw std::runtime_error("HMAC 실패");
    return Bytes(out, out + len);
}

} // namespace douve
