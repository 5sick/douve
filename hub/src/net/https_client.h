#pragma once

#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace douve {

// 바깥으로 나가는 HTTP(S) 요청 (Google 토큰·JWKS 등).
// Ubuntu 패키지의 Drogon/trantor는 TLS 없이 빌드되어 있어 https 주소도 평문으로 보내므로
// 외부 요청은 libcurl로 한다. Hub 자체는 nginx 뒤에서 평문 HTTP로 동작한다.
struct HttpResult {
    bool ok = false; // 응답을 받았는지 (상태 코드와 무관)
    long status = 0;
    std::string body;
    std::string cacheControl;
    std::string contentType;
    std::string error; // ok=false일 때 원인
    double elapsedMs = 0;
};

// 동기 요청. formBody가 있으면 application/x-www-form-urlencoded POST, 없으면 GET.
// http/https만 허용하고 인증서·호스트 검증을 항상 한다.
// insecure=true는 인증서 검증을 끈다 (자체 서명 업스트림의 상태 확인 전용).
HttpResult httpFetch(const std::string& url, const std::optional<std::string>& formBody,
                     long timeoutSeconds = 10, bool insecure = false);

// 본문·헤더를 직접 정하는 POST (알림 채널: JSON 웹훅, ntfy 등).
struct HttpPost {
    std::string url;
    std::string body;
    std::string contentType = "application/json";
    std::vector<std::pair<std::string, std::string>> headers;
};
HttpResult httpPost(const HttpPost& req, long timeoutSeconds = 10);
void httpPostAsync(HttpPost req, std::function<void(HttpResult)> cb, long timeoutSeconds = 10);

// 별도 스레드에서 httpFetch 후 Drogon 메인 루프에서 콜백을 부른다.
void httpFetchAsync(std::string url, std::optional<std::string> formBody,
                    std::function<void(HttpResult)> cb, long timeoutSeconds = 10,
                    bool insecure = false);

// 프로세스 시작 시 한 번 호출.
void httpGlobalInit();

// 링크된 libcurl이 TLS를 지원하는지 (https 요청이 평문으로 새지 않는다는 보장).
bool httpsSupported();

} // namespace douve
