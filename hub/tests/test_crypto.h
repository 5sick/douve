#pragma once
// 테스트 전용: 키 생성과 서명 (실제 인증기·구글을 흉내 내기 위함)

#include "util/encoding.h"

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <memory>
#include <stdexcept>
#include <string>

namespace douve::testing {

struct PkeyFree {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
using Pkey = std::unique_ptr<EVP_PKEY, PkeyFree>;

inline Pkey genRsa(unsigned bits = 2048) {
    return Pkey(EVP_RSA_gen(bits));
}
inline Pkey genP256() {
    return Pkey(EVP_EC_gen("P-256"));
}

inline Bytes bnParam(EVP_PKEY* k, const char* name, std::size_t pad = 0) {
    BIGNUM* bn = nullptr;
    if (!EVP_PKEY_get_bn_param(k, name, &bn))
        throw std::runtime_error("bn param");
    std::size_t len = std::max<std::size_t>(BN_num_bytes(bn), pad);
    Bytes out(len);
    BN_bn2binpad(bn, out.data(), static_cast<int>(len));
    BN_free(bn);
    return out;
}

// 메시지에 SHA-256 서명. RSA는 PKCS#1 v1.5, EC는 DER 인코딩 ECDSA.
inline Bytes sign(EVP_PKEY* k, const std::string& msg) {
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    std::size_t len = 0;
    EVP_DigestSignInit(md, nullptr, EVP_sha256(), nullptr, k);
    EVP_DigestSign(md, nullptr, &len, reinterpret_cast<const unsigned char*>(msg.data()),
                   msg.size());
    Bytes sig(len);
    EVP_DigestSign(md, sig.data(), &len, reinterpret_cast<const unsigned char*>(msg.data()),
                   msg.size());
    sig.resize(len);
    EVP_MD_CTX_free(md);
    return sig;
}
inline Bytes sign(EVP_PKEY* k, const Bytes& msg) {
    return sign(k, toString(msg));
}

// EC 공개키의 x, y 좌표 (각 32바이트).
inline std::pair<Bytes, Bytes> ecXY(EVP_PKEY* k) {
    return {bnParam(k, OSSL_PKEY_PARAM_EC_PUB_X, 32), bnParam(k, OSSL_PKEY_PARAM_EC_PUB_Y, 32)};
}

} // namespace douve::testing
