#include "auth/redirect.h"

#include <algorithm>
#include <cctype>

namespace douve {
namespace {
bool endsWith(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}
} // namespace

std::string safeRedirect(const std::string& target, const HubConfig& cfg,
                         const std::string& fallback) {
    if (target.empty() || target.size() > 2048)
        return fallback;
    for (unsigned char c : target) {
        // 제어문자·공백·역슬래시는 브라우저마다 해석이 달라 우회에 쓰인다
        if (c < 0x21 || c == 0x7f || c == '\\')
            return fallback;
    }
    // Hub 내부 경로 ("//evil.com"은 프로토콜 상대 URL이라 거부)
    if (target[0] == '/')
        return (target.size() > 1 && target[1] == '/') ? fallback : target;

    const std::string scheme = cfg.publicUrl.rfind("https://", 0) == 0 ? "https://" : "http://";
    if (target.rfind(scheme, 0) != 0)
        return fallback;
    const auto hostStart = scheme.size();
    const auto hostEnd = target.find_first_of("/?#", hostStart);
    std::string authority = target.substr(
        hostStart, hostEnd == std::string::npos ? std::string::npos : hostEnd - hostStart);
    if (authority.find('@') != std::string::npos)
        return fallback; // user:pass@host 형태 거부
    std::string host = authority.substr(0, authority.find(':'));
    std::transform(host.begin(), host.end(), host.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (host.empty())
        return fallback;
    if (host == cfg.cookieDomain || endsWith(host, cfg.redirectHostSuffix))
        return target;
    return fallback;
}

} // namespace douve
