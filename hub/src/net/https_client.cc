#include "net/https_client.h"

#include <curl/curl.h>
#include <drogon/drogon.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <thread>

#include <unistd.h>

namespace douve {
namespace {

constexpr std::size_t kMaxBody = 1 << 20; // 1 MiB

size_t onBody(char* data, size_t size, size_t n, void* user) {
    auto* out = static_cast<std::string*>(user);
    const size_t len = size * n;
    if (out->size() + len > kMaxBody)
        return 0; // 너무 크면 중단
    out->append(data, len);
    return len;
}

size_t onHeader(char* data, size_t size, size_t n, void* user) {
    const size_t len = size * n;
    std::string line(data, len);
    std::string lower = line;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    auto value = [&](std::string_view key) {
        auto v = line.substr(key.size());
        v.erase(0, v.find_first_not_of(" \t"));
        v.erase(v.find_last_not_of(" \t\r\n") + 1);
        return v;
    };
    auto* res = static_cast<HttpResult*>(user);
    if (lower.starts_with("cache-control:"))
        res->cacheControl = value("cache-control:");
    else if (lower.starts_with("content-type:"))
        res->contentType = value("content-type:");
    return len;
}

// 정적 빌드(musl)는 빌드 환경의 OpenSSL 기본 경로를 쓰므로, 배포판별 CA 묶음 위치를 직접 찾는다.
const std::string& caBundle() {
    static const std::string path = [] {
        for (const char* p : {"/etc/ssl/certs/ca-certificates.crt", // Debian·Ubuntu·Alpine
                              "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL·Rocky·Fedora
                              "/etc/ssl/ca-bundle.pem",             // openSUSE
                              "/etc/ssl/cert.pem"}) {
            if (access(p, R_OK) == 0)
                return std::string(p);
        }
        return std::string();
    }();
    return path;
}

} // namespace

void httpGlobalInit() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

bool httpsSupported() {
    const auto* info = curl_version_info(CURLVERSION_NOW);
    return info && (info->features & CURL_VERSION_SSL) != 0;
}

namespace {

HttpResult perform(const std::string& url, const std::optional<std::string>& body,
                   const std::vector<std::string>& headers, long timeoutSeconds, bool insecure) {
    HttpResult res;
    CURL* h = curl_easy_init();
    if (!h) {
        res.error = "curl 초기화 실패";
        return res;
    }
    curl_easy_setopt(h, CURLOPT_URL, url.c_str());
    curl_easy_setopt(h, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, insecure ? 0L : 1L);
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, insecure ? 0L : 2L);
    if (!caBundle().empty())
        curl_easy_setopt(h, CURLOPT_CAINFO, caBundle().c_str());
    curl_easy_setopt(h, CURLOPT_TIMEOUT, timeoutSeconds);
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, std::min(timeoutSeconds, 5L));
    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(h, CURLOPT_USERAGENT, "douve-hub");
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, onBody);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &res.body);
    curl_easy_setopt(h, CURLOPT_HEADERFUNCTION, onHeader);
    curl_easy_setopt(h, CURLOPT_HEADERDATA, &res);
    struct curl_slist* list = nullptr;
    for (const auto& hd : headers)
        list = curl_slist_append(list, hd.c_str());
    if (list)
        curl_easy_setopt(h, CURLOPT_HTTPHEADER, list);
    if (body) {
        curl_easy_setopt(h, CURLOPT_POST, 1L);
        curl_easy_setopt(h, CURLOPT_POSTFIELDS, body->c_str());
        curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE, static_cast<long>(body->size()));
    }
    const auto start = std::chrono::steady_clock::now();
    const CURLcode rc = curl_easy_perform(h);
    res.elapsedMs =
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
    if (rc == CURLE_OK) {
        res.ok = true;
        curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &res.status);
    } else {
        res.error = curl_easy_strerror(rc);
    }
    curl_slist_free_all(list);
    curl_easy_cleanup(h);
    return res;
}

} // namespace

HttpResult httpFetch(const std::string& url, const std::optional<std::string>& formBody,
                     long timeoutSeconds, bool insecure) {
    return perform(url, formBody, {}, timeoutSeconds, insecure);
}

HttpResult httpPost(const HttpPost& req, long timeoutSeconds) {
    std::vector<std::string> headers{"Content-Type: " + req.contentType};
    for (const auto& [k, v] : req.headers) {
        // 헤더 주입 방지: 줄바꿈이 든 값은 보내지 않는다
        if (k.find_first_of("\r\n:") != std::string::npos ||
            v.find_first_of("\r\n") != std::string::npos)
            continue;
        headers.push_back(k + ": " + v);
    }
    return perform(req.url, req.body, headers, timeoutSeconds, false);
}

void httpPostAsync(HttpPost req, std::function<void(HttpResult)> cb, long timeoutSeconds) {
    std::thread([req = std::move(req), cb = std::move(cb), timeoutSeconds]() mutable {
        auto res = httpPost(req, timeoutSeconds);
        drogon::app().getLoop()->queueInLoop(
            [cb = std::move(cb), res = std::move(res)]() mutable { cb(std::move(res)); });
    }).detach();
}

void httpFetchAsync(std::string url, std::optional<std::string> formBody,
                    std::function<void(HttpResult)> cb, long timeoutSeconds, bool insecure) {
    std::thread([url = std::move(url), body = std::move(formBody), cb = std::move(cb),
                 timeoutSeconds, insecure]() mutable {
        auto res = httpFetch(url, body, timeoutSeconds, insecure);
        drogon::app().getLoop()->queueInLoop(
            [cb = std::move(cb), res = std::move(res)]() mutable { cb(std::move(res)); });
    }).detach();
}

} // namespace douve
