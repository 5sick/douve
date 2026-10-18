// 로그인 후 돌아갈 주소 검사 퍼징 — 충돌뿐 아니라 "바깥 주소로 보내지 않는다"는 성질을 확인한다.
#include "auth/redirect.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iostream>

using namespace douve;

namespace {
bool endsWith(const std::string& s, const std::string& suf) {
    return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}
// 브라우저가 실제로 갈 호스트 (WHATWG URL의 단순화: 스킴 뒤 / \ ? # 앞까지, userinfo 뒤)
std::string browserHost(const std::string& url) {
    auto start = url.find("://");
    if (start == std::string::npos)
        return "";
    start += 3;
    auto end = url.find_first_of("/\\?#", start);
    std::string auth =
        url.substr(start, end == std::string::npos ? std::string::npos : end - start);
    if (auto at = auth.rfind('@'); at != std::string::npos)
        auth = auth.substr(at + 1);
    std::string host = auth.substr(0, auth.find(':'));
    std::transform(host.begin(), host.end(), host.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return host;
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static HubConfig cfg = [] {
        HubConfig c;
        c.publicUrl = "https://douve.example.com";
        c.cookieDomain = "example.com";
        c.redirectHostSuffix = ".example.com";
        return c;
    }();
    const std::string target(reinterpret_cast<const char*>(data), size);
    const std::string out = safeRedirect(target, cfg, "/");
    if (out == "/")
        return 0;
    bool ok;
    if (out[0] == '/') {
        // Hub 안 경로: //, /\ 로 시작하면 브라우저가 다른 호스트로 해석한다
        ok = out.size() == 1 || (out[1] != '/' && out[1] != '\\');
    } else {
        const std::string host = browserHost(out);
        ok = out.rfind("https://", 0) == 0 &&
             (host == "example.com" || endsWith(host, ".example.com"));
    }
    for (unsigned char c : out)
        if (c < 0x21 || c == 0x7f || c == '\\')
            ok = false;
    if (!ok) {
        std::cerr << "바깥 주소로 보낼 수 있음: " << out << "\n";
        std::abort();
    }
    return 0;
}
