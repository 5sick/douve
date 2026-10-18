#include "soft_authenticator.h"
#include "testing.h"
#include "webauthn/cbor_guard.h"
#include "webauthn/webauthn.h"

using namespace douve;
using douve::webauthn::cborWithinBounds;

namespace {
bool ok(std::initializer_list<int> b) {
    std::vector<std::uint8_t> v;
    for (int x : b)
        v.push_back(static_cast<std::uint8_t>(x));
    return cborWithinBounds(v.data(), v.size());
}
} // namespace

TEST(cbor_guard_bounds) {
    CHECK(ok({0x01}));                                   // 정수
    CHECK(ok({0x43, 1, 2, 3}));                          // 3바이트 문자열
    CHECK(!ok({0x45, 1, 2}));                            // 5바이트라면서 2바이트
    CHECK(ok({0x82, 0x01, 0x02}));                       // 배열 2개
    CHECK(!ok({0x9b, 0, 0, 0, 0, 0x30, 0, 0, 0, 0x01})); // 원소 8억 개 선언 (퍼징이 찾은 형태)
    CHECK(!ok({0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})); // 맵 2^64-1
    CHECK(ok({0xa1, 0x01, 0x02}));                                      // 맵 1쌍
    CHECK(!ok({0xa1, 0x01}));                                           // 값 없음
    CHECK(ok({0x9f, 0x01, 0x02, 0xff}));                                // 무한 길이 배열
    CHECK(!ok({0x9f, 0x01, 0x02}));                                     // break 없음
    CHECK(ok({0x5f, 0x41, 1, 0x41, 2, 0xff}));                          // 무한 길이 바이트 문자열
    CHECK(!ok({0x5f, 0x61, 'a', 0xff}));                                // 조각 형식이 다름
    CHECK(!ok({0x1c}));                                                 // 예약된 추가 정보
    CHECK(ok({0xc1, 0x01}));                                            // 태그
    std::vector<std::uint8_t> deep(100, 0x81);                          // [[[[...]]]] 100단
    deep.push_back(0x01);
    CHECK(!cborWithinBounds(deep.data(), deep.size()));
    CHECK(!cborWithinBounds(nullptr, 0));
}

TEST(cbor_guard_accepts_real_authenticators) {
    for (auto kt : {testing::KeyType::ES256, testing::KeyType::RS256, testing::KeyType::EdDSA}) {
        testing::SoftAuthenticator a(kt);
        auto reg = a.create(Bytes(32, 7), "https://douve.example.com", "example.com");
        CHECK(cborWithinBounds(reg.attestationObject.data(), reg.attestationObject.size()));
        const auto key = a.coseKey();
        CHECK(cborWithinBounds(key.data(), key.size()));
        webauthn::Expectations exp{Bytes(32, 7), "https://douve.example.com", "example.com", true};
        std::string err;
        CHECK(webauthn::verifyRegistration(reg.clientDataJson, reg.attestationObject, exp, err)
                  .has_value());
    }
}
