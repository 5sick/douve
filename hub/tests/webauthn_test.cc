#include "soft_authenticator.h"
#include "testing.h"

using namespace douve;
using namespace douve::webauthn;
using namespace douve::testing;

namespace {
const std::string kOrigin = "https://douve.example.com";
const std::string kRpId = "example.com";

Expectations expect(const Bytes& challenge) {
    return {challenge, kOrigin, kRpId, true};
}

// 등록 후 저장할 값(공개키, 카운터)을 돌려준다.
std::optional<NewCredential> registerWith(SoftAuthenticator& a) {
    auto ch = randomBytes(32);
    auto r = a.create(ch, kOrigin, kRpId);
    std::string err;
    return verifyRegistration(r.clientDataJson, r.attestationObject, expect(ch), err);
}
} // namespace

TEST(webauthn_register_and_login_all_algorithms) {
    for (auto t : {KeyType::ES256, KeyType::RS256, KeyType::EdDSA}) {
        SoftAuthenticator a(t);
        auto cred = registerWith(a);
        CHECK(cred.has_value());
        if (!cred)
            continue;
        CHECK(cred->credentialId == a.credentialId);
        CHECK_EQ(cred->alg, t == KeyType::ES256   ? kAlgES256
                            : t == KeyType::RS256 ? kAlgRS256
                                                  : kAlgEdDSA);
        auto ch = randomBytes(32);
        auto as = a.get(ch, kOrigin, kRpId);
        std::string err;
        auto res = verifyAssertion(as.clientDataJson, as.authenticatorData, as.signature,
                                   cred->coseKeyBytes, cred->signCount, expect(ch), err);
        CHECK(res.has_value());
        if (res)
            CHECK_EQ(res->signCount, cred->signCount + 1);
    }
}

TEST(webauthn_register_rejects_wrong_context) {
    SoftAuthenticator a;
    std::string err;
    auto ch = randomBytes(32);
    // 다른 origin (피싱 사이트)
    auto r1 = a.create(ch, "https://douve.example.com.evil.com", kRpId);
    CHECK(!verifyRegistration(r1.clientDataJson, r1.attestationObject, expect(ch), err));
    // 다른 challenge (재전송)
    auto r2 = a.create(randomBytes(32), kOrigin, kRpId);
    CHECK(!verifyRegistration(r2.clientDataJson, r2.attestationObject, expect(ch), err));
    // 다른 rpId로 만든 키
    auto r3 = a.create(ch, kOrigin, "evil.com");
    CHECK(!verifyRegistration(r3.clientDataJson, r3.attestationObject, expect(ch), err));
    // UV 없음 (PIN/지문 없이 터치만)
    auto r4 = a.create(ch, kOrigin, kRpId, kFlagUP | kFlagAT);
    CHECK(!verifyRegistration(r4.clientDataJson, r4.attestationObject, expect(ch), err));
    // UP 없음
    auto r5 = a.create(ch, kOrigin, kRpId, kFlagUV | kFlagAT);
    CHECK(!verifyRegistration(r5.clientDataJson, r5.attestationObject, expect(ch), err));
    // 인증용 clientData(type=webauthn.get)를 등록에 사용
    auto r6 = a.create(ch, kOrigin, kRpId);
    r6.clientDataJson = SoftAuthenticator::clientData("webauthn.get", ch, kOrigin);
    CHECK(!verifyRegistration(r6.clientDataJson, r6.attestationObject, expect(ch), err));
    // crossOrigin iframe
    auto r7 = a.create(ch, kOrigin, kRpId);
    r7.clientDataJson = toBytes(R"({"type":"webauthn.create","challenge":")" + base64UrlEncode(ch) +
                                R"(","origin":")" + kOrigin + R"(","crossOrigin":true})");
    CHECK(!verifyRegistration(r7.clientDataJson, r7.attestationObject, expect(ch), err));
    // 빈 기대 challenge는 항상 실패
    auto r8 = a.create(Bytes{}, kOrigin, kRpId);
    CHECK(!verifyRegistration(r8.clientDataJson, r8.attestationObject, expect(Bytes{}), err));
    // 형식이 틀린 clientData: 예외 없이 거부 (로그인 전 입력)
    auto r9 = a.create(ch, kOrigin, kRpId);
    for (std::string cd : {std::string(R"({"type":["webauthn.create"]})"),
                           std::string(R"({"type":"webauthn.create","challenge":{},"origin":1})"),
                           std::string(2000, '[') + std::string(2000, ']')}) {
        r9.clientDataJson = toBytes(cd);
        CHECK(!verifyRegistration(r9.clientDataJson, r9.attestationObject, expect(ch), err));
    }
    // crossOrigin이 불리언이 아니면 거부
    r9.clientDataJson = toBytes(R"({"type":"webauthn.create","challenge":")" + base64UrlEncode(ch) +
                                R"(","origin":")" + kOrigin + R"(","crossOrigin":"no"})");
    CHECK(!verifyRegistration(r9.clientDataJson, r9.attestationObject, expect(ch), err));
}

TEST(webauthn_assertion_rejects_attacks) {
    SoftAuthenticator a;
    auto cred = registerWith(a);
    CHECK(cred.has_value());
    if (!cred)
        return;
    std::string err;
    auto ch = randomBytes(32);

    auto ok = a.get(ch, kOrigin, kRpId);
    // 서명 변조
    auto bad = ok;
    bad.signature.back() ^= 1;
    CHECK(!verifyAssertion(bad.clientDataJson, bad.authenticatorData, bad.signature,
                           cred->coseKeyBytes, 0, expect(ch), err));
    // clientData 변조 (서명은 원래 것)
    auto bad2 = ok;
    bad2.clientDataJson = SoftAuthenticator::clientData("webauthn.get", ch, kOrigin, R"(,"x":1)");
    CHECK(!verifyAssertion(bad2.clientDataJson, bad2.authenticatorData, bad2.signature,
                           cred->coseKeyBytes, 0, expect(ch), err));
    // 다른 인증기의 공개키로 검증 (다른 사용자의 credential id를 내미는 경우)
    SoftAuthenticator other;
    auto otherCred = registerWith(other);
    CHECK(!verifyAssertion(ok.clientDataJson, ok.authenticatorData, ok.signature,
                           otherCred->coseKeyBytes, 0, expect(ch), err));
    // 다른 challenge
    CHECK(!verifyAssertion(ok.clientDataJson, ok.authenticatorData, ok.signature,
                           cred->coseKeyBytes, 0, expect(randomBytes(32)), err));
    // UV 없이 서명
    auto noUv = a.get(ch, kOrigin, kRpId, kFlagUP);
    CHECK(!verifyAssertion(noUv.clientDataJson, noUv.authenticatorData, noUv.signature,
                           cred->coseKeyBytes, 0, expect(ch), err));
    // 등록용 type을 인증에 사용
    auto wrongType = ok;
    wrongType.clientDataJson = SoftAuthenticator::clientData("webauthn.create", ch, kOrigin);
    CHECK(!verifyAssertion(wrongType.clientDataJson, wrongType.authenticatorData,
                           wrongType.signature, cred->coseKeyBytes, 0, expect(ch), err));
    // 정상은 통과
    CHECK(verifyAssertion(ok.clientDataJson, ok.authenticatorData, ok.signature, cred->coseKeyBytes,
                          0, expect(ch), err));
}

TEST(webauthn_sign_count_regression_rejected) {
    SoftAuthenticator a;
    auto cred = registerWith(a);
    std::string err;
    auto ch = randomBytes(32);
    auto as = a.get(ch, kOrigin, kRpId); // counter = 2
    // 저장된 카운터가 이미 5라면 → 복제 의심
    CHECK(!verifyAssertion(as.clientDataJson, as.authenticatorData, as.signature,
                           cred->coseKeyBytes, 5, expect(ch), err));
    CHECK(verifyAssertion(as.clientDataJson, as.authenticatorData, as.signature, cred->coseKeyBytes,
                          1, expect(ch), err));
}

TEST(webauthn_sign_count_zero_allowed_for_synced_passkeys) {
    SoftAuthenticator a;
    a.countUp = false; // 항상 0 (iCloud/Google 동기화 패스키)
    auto cred = registerWith(a);
    CHECK(cred.has_value());
    std::string err;
    for (int i = 0; i < 3; ++i) {
        auto ch = randomBytes(32);
        auto as = a.get(ch, kOrigin, kRpId);
        CHECK(verifyAssertion(as.clientDataJson, as.authenticatorData, as.signature,
                              cred->coseKeyBytes, 0, expect(ch), err));
    }
}

TEST(webauthn_authdata_malformed) {
    std::string err;
    CHECK(!parseAuthData(Bytes(36, 0), err));
    Bytes ad = sha256(std::string_view("x"));
    ad.push_back(kFlagUP);
    ad.insert(ad.end(), {0, 0, 0, 1});
    CHECK(parseAuthData(ad, err).has_value());
    auto trailing = ad;
    trailing.push_back(0);
    CHECK(!parseAuthData(trailing, err)); // 남는 바이트
    auto atTruncated = ad;
    atTruncated[32] |= kFlagAT; // AT 플래그인데 데이터 없음
    CHECK(!parseAuthData(atTruncated, err));
}

TEST(webauthn_cose_rejects_unsupported) {
    std::string err;
    // P-384 같은 다른 곡선, 잘못된 좌표 길이
    cbor_item_t* m = cbor_new_definite_map(5);
    put(m, cborInt(1), cborInt(2));
    put(m, cborInt(3), cborInt(-7));
    put(m, cborInt(-1), cborInt(2)); // crv P-384
    Bytes x(48, 1), y(48, 2);
    put(m, cborInt(-2), cbor_build_bytestring(x.data(), x.size()));
    put(m, cborInt(-3), cbor_build_bytestring(y.data(), y.size()));
    auto b = serialize(m);
    CHECK(!parseCoseKey(b.data(), b.size(), nullptr, err));
    // 곡선 위에 없는 점은 서명 검증 단계에서 실패해야 함
    CoseKey bogus{kAlgES256, Bytes(32, 1), Bytes(32, 2), {}, {}};
    CHECK(!verifySignature(bogus, toBytes("m"), Bytes(70, 0)));
    // 쓰레기 입력
    Bytes junk{0xff, 0x00, 0x13};
    CHECK(!parseCoseKey(junk.data(), junk.size(), nullptr, err));
}
