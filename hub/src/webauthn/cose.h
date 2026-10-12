#pragma once
// COSE 공개키 (RFC 9053) 파싱과 서명 검증. WebAuthn에서 쓰는 ES256 / RS256 / EdDSA만 지원한다.

#include "util/encoding.h"

#include <cstdint>
#include <optional>
#include <string>

namespace douve::webauthn {

inline constexpr int kAlgES256 = -7;
inline constexpr int kAlgEdDSA = -8;
inline constexpr int kAlgRS256 = -257;

struct CoseKey {
    int alg = 0;
    // EC2(P-256): x, y / RSA: n, e / OKP(Ed25519): x
    Bytes x, y, n, e;
};

// CBOR로 인코딩된 COSE_Key를 파싱한다. consumed에 읽은 바이트 수를 돌려준다 (authData 뒤 확장
// 데이터 구분용).
std::optional<CoseKey> parseCoseKey(const std::uint8_t* data, std::size_t len,
                                    std::size_t* consumed, std::string& error);

// message에 대한 서명 검증 (ES256은 DER 인코딩 ECDSA 서명).
bool verifySignature(const CoseKey& key, const Bytes& message, const Bytes& signature);

} // namespace douve::webauthn
