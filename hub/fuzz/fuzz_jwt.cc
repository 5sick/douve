// Google ID 토큰(JWT) 분해·클레임 검사 퍼징
#include "auth/jwt.h"

#include <cstdint>

using namespace douve;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string token(reinterpret_cast<const char*>(data), size);
    std::string err;
    auto parts = splitJwt(token, err);
    if (!parts)
        return 0;
    JwkSet empty;
    (void)verifyRs256(*parts, empty, err);
    IdTokenExpectations exp{"client.apps.googleusercontent.com", "nonce", 1700000000, 120};
    (void)checkGoogleClaims(parts->claims, exp, err);
    return 0;
}
