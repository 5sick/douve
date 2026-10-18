// 퍼징 씨앗 만들기: 소프트웨어 인증기로 올바른 등록·인증 응답을 만들어 fuzz_webauthn 입력 형식으로
// 저장
#include "soft_authenticator.h"

#include <fstream>
#include <iostream>

using namespace douve;
using namespace douve::testing;

namespace {
void put(std::ofstream& f, const Bytes& b) {
    f.put(static_cast<char>(b.size() >> 8));
    f.put(static_cast<char>(b.size() & 0xff));
    f.write(reinterpret_cast<const char*>(b.data()), b.size());
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "사용: fuzz_seedgen <씨앗 폴더>\n";
        return 2;
    }
    const std::string dir = argv[1];
    int i = 0;
    for (auto kt : {KeyType::ES256, KeyType::RS256, KeyType::EdDSA}) {
        SoftAuthenticator a(kt);
        const Bytes challenge(32, 7);
        auto reg = a.create(challenge, "https://douve.example.com", "example.com");
        std::ofstream r(dir + "/reg" + std::to_string(i));
        put(r, reg.clientDataJson);
        put(r, reg.attestationObject);
        put(r, {});
        auto as = a.get(challenge, "https://douve.example.com", "example.com");
        std::ofstream s(dir + "/assert" + std::to_string(i));
        put(s, as.clientDataJson);
        put(s, as.authenticatorData);
        put(s, as.signature);
        const Bytes key = a.coseKey();
        s.write(reinterpret_cast<const char*>(key.data()), key.size());
        ++i;
    }
    std::cout << "씨앗 " << i * 2 << "개: " << dir << "\n";
    return 0;
}
