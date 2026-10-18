#include "auth/jwt.h"
#include "util/json.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

#include <algorithm>
#include <memory>
#include <sstream>

namespace douve {
namespace {

std::optional<Json::Value> parseJson(const std::string& s) {
    Json::Value v;
    if (!douve::parseJson(s, v))
        return std::nullopt;
    return v;
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

template <typename T, void (*F)(T*)> struct Deleter {
    void operator()(T* p) const { F(p); }
};
using PkeyPtr = std::unique_ptr<EVP_PKEY, Deleter<EVP_PKEY, EVP_PKEY_free>>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, Deleter<EVP_PKEY_CTX, EVP_PKEY_CTX_free>>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, Deleter<EVP_MD_CTX, EVP_MD_CTX_free>>;
using BnPtr = std::unique_ptr<BIGNUM, Deleter<BIGNUM, BN_free>>;
using ParamBldPtr = std::unique_ptr<OSSL_PARAM_BLD, Deleter<OSSL_PARAM_BLD, OSSL_PARAM_BLD_free>>;
using ParamPtr = std::unique_ptr<OSSL_PARAM, Deleter<OSSL_PARAM, OSSL_PARAM_free>>;

PkeyPtr rsaPublicKey(const Bytes& n, const Bytes& e) {
    BnPtr bn(BN_bin2bn(n.data(), static_cast<int>(n.size()), nullptr));
    BnPtr be(BN_bin2bn(e.data(), static_cast<int>(e.size()), nullptr));
    ParamBldPtr bld(OSSL_PARAM_BLD_new());
    if (!bn || !be || !bld || !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_N, bn.get()) ||
        !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_E, be.get()))
        return nullptr;
    ParamPtr params(OSSL_PARAM_BLD_to_param(bld.get()));
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr));
    EVP_PKEY* raw = nullptr;
    if (!params || !ctx || EVP_PKEY_fromdata_init(ctx.get()) <= 0 ||
        EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params.get()) <= 0)
        return nullptr;
    return PkeyPtr(raw);
}

} // namespace

std::optional<JwkSet> JwkSet::parse(const std::string& json, std::string& error) {
    auto root = parseJson(json);
    if (!root || !(*root)["keys"].isArray()) {
        error = "JWKS 형식 오류";
        return std::nullopt;
    }
    JwkSet set;
    for (const auto& k : (*root)["keys"]) {
        if (k.get("kty", "").asString() != "RSA")
            continue;
        auto alg = k.get("alg", "RS256").asString();
        if (alg != "RS256")
            continue;
        auto n = base64UrlDecode(k.get("n", "").asString());
        auto e = base64UrlDecode(k.get("e", "").asString());
        auto kid = k.get("kid", "").asString();
        // 2048비트 미만 키는 받지 않는다
        if (!n || !e || kid.empty() || n->size() < 256)
            continue;
        set.keys_[kid] = RsaKey{*n, *e};
    }
    if (set.keys_.empty()) {
        error = "JWKS에 사용할 수 있는 RSA 키가 없습니다";
        return std::nullopt;
    }
    return set;
}

const JwkSet::RsaKey* JwkSet::find(const std::string& kid) const {
    auto it = keys_.find(kid);
    return it == keys_.end() ? nullptr : &it->second;
}

std::optional<JwtParts> splitJwt(const std::string& token, std::string& error) {
    if (token.size() > 16384) {
        error = "토큰이 너무 깁니다";
        return std::nullopt;
    }
    auto d1 = token.find('.');
    auto d2 = d1 == std::string::npos ? std::string::npos : token.find('.', d1 + 1);
    if (d2 == std::string::npos || token.find('.', d2 + 1) != std::string::npos) {
        error = "JWT 형식 오류";
        return std::nullopt;
    }
    auto h = base64UrlDecode(std::string_view(token).substr(0, d1));
    auto p = base64UrlDecode(std::string_view(token).substr(d1 + 1, d2 - d1 - 1));
    auto s = base64UrlDecode(std::string_view(token).substr(d2 + 1));
    if (!h || !p || !s) {
        error = "JWT 인코딩 오류";
        return std::nullopt;
    }
    auto hj = parseJson(toString(*h));
    auto pj = parseJson(toString(*p));
    if (!hj || !pj || !hj->isObject() || !pj->isObject()) {
        error = "JWT JSON 오류";
        return std::nullopt;
    }
    return JwtParts{*hj, *pj, token.substr(0, d2), *s};
}

bool rsaSha256Verify(const Bytes& n, const Bytes& e, const std::uint8_t* msg, std::size_t msgLen,
                     const Bytes& sig) {
    auto key = rsaPublicKey(n, e);
    if (!key)
        return false;
    MdCtxPtr md(EVP_MD_CTX_new());
    EVP_PKEY_CTX* pctx = nullptr;
    if (!md || EVP_DigestVerifyInit(md.get(), &pctx, EVP_sha256(), nullptr, key.get()) != 1)
        return false;
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) != 1)
        return false;
    return EVP_DigestVerify(md.get(), sig.data(), sig.size(), msg, msgLen) == 1;
}

bool verifyRs256(const JwtParts& jwt, const JwkSet& keys, std::string& error) {
    if (jwt.header.get("alg", "").asString() != "RS256") {
        error = "허용되지 않은 서명 알고리즘";
        return false;
    }
    const auto* key = keys.find(jwt.header.get("kid", "").asString());
    if (!key) {
        error = "알 수 없는 키 ID";
        return false;
    }
    if (!rsaSha256Verify(key->n, key->e,
                         reinterpret_cast<const std::uint8_t*>(jwt.signingInput.data()),
                         jwt.signingInput.size(), jwt.signature)) {
        error = "서명 검증 실패";
        return false;
    }
    return true;
}

std::optional<GoogleIdentity> checkGoogleClaims(const Json::Value& c, const IdTokenExpectations& x,
                                                std::string& error) {
    const auto iss = c.get("iss", "").asString();
    if (iss != "https://accounts.google.com" && iss != "accounts.google.com") {
        error = "발급자(iss) 불일치";
        return std::nullopt;
    }
    // aud는 문자열 또는 배열일 수 있다
    bool audOk = false;
    if (c["aud"].isString())
        audOk = c["aud"].asString() == x.clientId;
    else if (c["aud"].isArray())
        for (const auto& a : c["aud"])
            audOk |= a.asString() == x.clientId;
    if (!audOk || x.clientId.empty()) {
        error = "대상(aud) 불일치";
        return std::nullopt;
    }
    if (c["aud"].isArray() && c.get("azp", "").asString() != x.clientId) {
        error = "azp 불일치";
        return std::nullopt;
    }
    if (!c["exp"].isNumeric() || c["exp"].asInt64() + x.skewSeconds < x.now) {
        error = "토큰 만료";
        return std::nullopt;
    }
    if (c["iat"].isNumeric() && c["iat"].asInt64() - x.skewSeconds > x.now) {
        error = "발급 시각(iat)이 미래";
        return std::nullopt;
    }
    if (x.nonce.empty() || c.get("nonce", "").asString() != x.nonce) {
        error = "nonce 불일치";
        return std::nullopt;
    }
    const auto& ev = c["email_verified"];
    const bool verified = ev.isBool() ? ev.asBool() : (ev.isString() && ev.asString() == "true");
    const auto email = lower(c.get("email", "").asString());
    if (email.empty() || !verified) {
        error = "인증된 이메일이 없습니다";
        return std::nullopt;
    }
    return GoogleIdentity{email, c.get("sub", "").asString()};
}

} // namespace douve
