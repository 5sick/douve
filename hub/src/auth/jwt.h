#pragma once

#include "util/encoding.h"

#include <json/json.h>

#include <cstdint>
#include <map>
#include <optional>
#include <string>

namespace douve {

// RS256 공개키 집합 (JWKS). kid → DER 형식이 아니라 (n, e) 원본 바이트로 보관.
class JwkSet {
  public:
    // {"keys":[{"kty":"RSA","kid":..,"n":..,"e":..,"alg":"RS256"},...]} 파싱. RSA 키만 받는다.
    static std::optional<JwkSet> parse(const std::string& json, std::string& error);
    bool has(const std::string& kid) const { return keys_.count(kid) > 0; }
    std::size_t size() const { return keys_.size(); }

    struct RsaKey {
        Bytes n, e;
    };
    const RsaKey* find(const std::string& kid) const;

  private:
    std::map<std::string, RsaKey> keys_;
};

struct JwtParts {
    Json::Value header;
    Json::Value claims;
    std::string signingInput; // base64url(header) "." base64url(payload)
    Bytes signature;
};

// 서명 검증 없이 구조만 분해 (kid 조회용). 형식 오류 시 nullopt.
std::optional<JwtParts> splitJwt(const std::string& token, std::string& error);

// RS256 서명 검증. alg가 RS256이 아니면 실패 ("none" 등 다운그레이드 거부).
bool verifyRs256(const JwtParts& jwt, const JwkSet& keys, std::string& error);

// RSASSA-PKCS1-v1_5 + SHA-256 서명 검증 (공개키 n, e). WebAuthn RS256에서도 재사용.
bool rsaSha256Verify(const Bytes& n, const Bytes& e, const std::uint8_t* msg, std::size_t msgLen,
                     const Bytes& sig);

// Google ID 토큰의 클레임 검증 결과.
struct GoogleIdentity {
    std::string email; // 소문자
    std::string subject;
};

struct IdTokenExpectations {
    std::string clientId;
    std::string nonce;
    std::int64_t now = 0;
    std::int64_t skewSeconds = 120;
};

// iss, aud, exp, iat, nonce, email, email_verified 검사.
std::optional<GoogleIdentity> checkGoogleClaims(const Json::Value& claims,
                                                const IdTokenExpectations& exp, std::string& error);

} // namespace douve
