#include "net/https_client.h"
#include "testing.h"

using namespace douve;

TEST(https_client_has_tls) {
    // 회귀 방지: Ubuntu의 Drogon HttpClient는 TLS 없이 빌드되어 https를 평문으로 보냈다.
    CHECK(httpsSupported());
}

TEST(https_client_rejects_other_schemes) {
    auto r = httpFetch("file:///etc/hostname", std::nullopt, 2);
    CHECK(!r.ok);
    auto g = httpFetch("gopher://127.0.0.1/", std::nullopt, 2);
    CHECK(!g.ok);
}
