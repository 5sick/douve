#pragma once
// WebAuthn Level 2 등록·인증 검증 (§7.1, §7.2). 순수 함수 — 저장소·HTTP와 분리해 테스트한다.
// 증명(attestation)은 신뢰하지 않는다("none" 정책): 공개키만 받아 저장하고 attStmt는 검증하지
// 않는다.

#include "webauthn/cose.h"

#include <cstdint>
#include <optional>
#include <string>

namespace douve::webauthn {

inline constexpr std::uint8_t kFlagUP = 0x01; // 사용자 존재 (터치)
inline constexpr std::uint8_t kFlagUV = 0x04; // 사용자 검증 (지문·PIN 등)
inline constexpr std::uint8_t kFlagBE = 0x08; // 백업 가능 (동기화 패스키)
inline constexpr std::uint8_t kFlagBS = 0x10; // 백업됨
inline constexpr std::uint8_t kFlagAT = 0x40; // 인증 정보 포함
inline constexpr std::uint8_t kFlagED = 0x80; // 확장 데이터 포함

struct AuthData {
    Bytes rpIdHash;
    std::uint8_t flags = 0;
    std::uint32_t signCount = 0;
    // AT 플래그가 있을 때만
    Bytes aaguid;
    Bytes credentialId;
    Bytes coseKeyBytes;
    std::optional<CoseKey> coseKey;
};

std::optional<AuthData> parseAuthData(const Bytes& raw, std::string& error);

struct Expectations {
    Bytes challenge;
    std::string origin; // 예: https://douve.example.com
    std::string rpId;   // 예: example.com
    bool requireUserVerification = true;
};

struct NewCredential {
    Bytes credentialId;
    Bytes coseKeyBytes; // DB에 그대로 저장
    int alg = 0;
    std::uint32_t signCount = 0;
    bool backupEligible = false;
};

std::optional<NewCredential> verifyRegistration(const Bytes& clientDataJson,
                                                const Bytes& attestationObject,
                                                const Expectations& exp, std::string& error);

struct AssertionResult {
    std::uint32_t signCount = 0;
};

// storedSignCount: 저장된 서명 카운터. 둘 다 0이 아닌데 증가하지 않았으면 복제된 인증기로 보고
// 거부.
std::optional<AssertionResult> verifyAssertion(const Bytes& clientDataJson,
                                               const Bytes& authenticatorData,
                                               const Bytes& signature, const Bytes& storedCoseKey,
                                               std::uint32_t storedSignCount,
                                               const Expectations& exp, std::string& error);

} // namespace douve::webauthn
