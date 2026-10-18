// WebAuthn 응답 처리 퍼징: 인증기 데이터·CBOR 증명 객체·COSE 키·clientDataJSON
// 입력: [2바이트 길이][clientDataJSON][2][증명 객체 또는 인증기 데이터][2][서명][나머지 = COSE 키]
// (fuzz_seedgen이 진짜 소프트웨어 인증기로 만든 올바른 등록·인증 입력을 씨앗으로 쓴다)
#include "util/encoding.h"
#include "webauthn/cose.h"
#include "webauthn/webauthn.h"

#include <cstdint>

using namespace douve;

namespace {
Bytes take(const std::uint8_t*& p, std::size_t& left) {
    if (left < 2) {
        left = 0;
        return {};
    }
    std::size_t n = (p[0] << 8) | p[1];
    p += 2;
    left -= 2;
    n = std::min(n, left);
    Bytes out(p, p + n);
    p += n;
    left -= n;
    return out;
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::uint8_t* p = data;
    std::size_t left = size;
    const Bytes clientData = take(p, left);
    const Bytes blob = take(p, left);
    const Bytes sig = take(p, left);
    const Bytes key(p, p + left);
    webauthn::Expectations exp{Bytes(32, 7), "https://douve.example.com", "example.com", true};
    std::string err;
    (void)webauthn::parseAuthData(blob, err);
    (void)webauthn::verifyRegistration(clientData, blob, exp, err);
    (void)webauthn::verifyAssertion(clientData, blob, sig, key, 5, exp, err);
    std::size_t used = 0;
    if (auto k = webauthn::parseCoseKey(key.data(), key.size(), &used, err))
        (void)webauthn::verifySignature(*k, blob, sig);
    return 0;
}
