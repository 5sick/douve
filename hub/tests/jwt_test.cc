#include "auth/jwt.h"
#include "test_crypto.h"
#include "testing.h"

#include <openssl/core_names.h>

using namespace douve;
using namespace douve::testing;

namespace {

struct Signer {
    Pkey key = genRsa();
    std::string kid = "test-kid";

    std::string jwks() const {
        auto n = base64UrlEncode(bnParam(key.get(), OSSL_PKEY_PARAM_RSA_N));
        auto e = base64UrlEncode(bnParam(key.get(), OSSL_PKEY_PARAM_RSA_E));
        return R"({"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":")" + kid + R"(","n":")" +
               n + R"(","e":")" + e + R"("}]})";
    }

    std::string token(const std::string& claims, const std::string& header = "") const {
        std::string h =
            header.empty() ? R"({"alg":"RS256","typ":"JWT","kid":")" + kid + "\"}" : header;
        std::string input =
            base64UrlEncode(std::string_view(h)) + "." + base64UrlEncode(std::string_view(claims));
        return input + "." + base64UrlEncode(sign(key.get(), input));
    }
};

const std::int64_t kNow = 1'800'000'000;

std::string claims(const std::string& overrides = "") {
    std::string base =
        R"("iss":"https://accounts.google.com","aud":"cid.apps.googleusercontent.com",)"
        R"("sub":"1234","email":"Me@Example.com","email_verified":true,"nonce":"N1",)"
        R"("iat":1799999990,"exp":1800003600)";
    return "{" + base + overrides + "}";
}

IdTokenExpectations expect() {
    return {"cid.apps.googleusercontent.com", "N1", kNow, 120};
}

// 서명 검증 + 클레임 검증 전체 경로
std::optional<GoogleIdentity> verifyAll(const Signer& s, const std::string& tok,
                                        const IdTokenExpectations& x, std::string& err) {
    auto keys = JwkSet::parse(s.jwks(), err);
    if (!keys)
        return std::nullopt;
    auto parts = splitJwt(tok, err);
    if (!parts || !verifyRs256(*parts, *keys, err))
        return std::nullopt;
    return checkGoogleClaims(parts->claims, x, err);
}

} // namespace

TEST(jwt_valid_google_token) {
    Signer s;
    std::string err;
    auto id = verifyAll(s, s.token(claims()), expect(), err);
    CHECK(id.has_value());
    if (id) {
        CHECK_EQ(id->email, "me@example.com");
        CHECK_EQ(id->subject, "1234");
    }
}

TEST(jwt_rejects_tampered_payload) {
    Signer s;
    std::string err;
    auto tok = s.token(claims());
    // 서명은 그대로 두고 payload만 다른 이메일로 교체
    auto d1 = tok.find('.'), d2 = tok.rfind('.');
    auto forged = tok.substr(0, d1 + 1) +
                  base64UrlEncode(std::string_view(claims(R"(,"email":"attacker@evil.com")"))) +
                  tok.substr(d2);
    CHECK(!verifyAll(s, forged, expect(), err));
}

TEST(jwt_rejects_alg_none_and_hs256) {
    Signer s;
    std::string err;
    std::string none = base64UrlEncode(std::string_view(R"({"alg":"none","kid":"test-kid"})")) +
                       "." + base64UrlEncode(std::string_view(claims())) + ".";
    CHECK(!verifyAll(s, none, expect(), err));
    CHECK(!verifyAll(s, s.token(claims(), R"({"alg":"HS256","kid":"test-kid"})"), expect(), err));
}

TEST(jwt_rejects_unknown_kid_and_other_key) {
    Signer s, other;
    std::string err;
    CHECK(!verifyAll(s, s.token(claims(), R"({"alg":"RS256","kid":"nope"})"), expect(), err));
    other.kid = s.kid; // 같은 kid지만 다른 키로 서명
    CHECK(!verifyAll(s, other.token(claims()), expect(), err));
}

TEST(jwt_rejects_bad_claims) {
    Signer s;
    std::string err;
    CHECK(!verifyAll(s, s.token(claims(R"(,"iss":"https://evil.com")")), expect(), err));
    CHECK(!verifyAll(s, s.token(claims(R"(,"aud":"other-client")")), expect(), err));
    CHECK(!verifyAll(s, s.token(claims(R"(,"nonce":"N2")")), expect(), err));
    CHECK(!verifyAll(s, s.token(claims(R"(,"exp":1799990000)")), expect(), err));
    CHECK(!verifyAll(s, s.token(claims(R"(,"iat":1800001000)")), expect(), err));
    CHECK(!verifyAll(s, s.token(claims(R"(,"email_verified":false)")), expect(), err));
    CHECK(!verifyAll(s, s.token(claims(R"(,"email":"")")), expect(), err));
    auto x = expect();
    x.nonce = "";
    CHECK(!verifyAll(s, s.token(claims(R"(,"nonce":"")")), x, err)); // 빈 nonce는 항상 거부
}

TEST(jwt_aud_array_requires_azp) {
    Signer s;
    std::string err;
    CHECK(!verifyAll(s, s.token(claims(R"(,"aud":["cid.apps.googleusercontent.com","x"])")),
                     expect(), err));
    CHECK(verifyAll(
        s,
        s.token(claims(
            R"(,"aud":["cid.apps.googleusercontent.com","x"],"azp":"cid.apps.googleusercontent.com")")),
        expect(), err));
}

TEST(jwt_malformed_inputs) {
    std::string err;
    CHECK(!splitJwt("", err));
    CHECK(!splitJwt("a.b", err));
    CHECK(!splitJwt("a.b.c.d", err));
    CHECK(!splitJwt("!!.!!.!!", err));
    CHECK(!splitJwt(std::string(20000, 'a'), err));
    CHECK(!JwkSet::parse("{}", err));
    CHECK(!JwkSet::parse(R"({"keys":[{"kty":"EC","kid":"x"}]})", err));
}

TEST(jwt_rejects_short_rsa_key) {
    Signer s;
    s.key = genRsa(1024);
    std::string err;
    CHECK(!JwkSet::parse(s.jwks(), err));
}
