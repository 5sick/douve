#include "init.h"
#include "cli_i18n.h"

#include "config.h"

#include <json/json.h>
#include <sys/stat.h>

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <unistd.h>

namespace douve {
namespace {

const char* kUsage =
    "사용법: douve-hub init --public-url URL --email 이메일 [옵션]\n"
    "  --public-url URL            Hub 공개 주소 (예: https://douve.example.com)\n"
    "  --email 이메일              로그인 허용 이메일 (여러 번 지정 가능)\n"
    "  --google-client-id ID       Google OAuth 클라이언트 ID\n"
    "  --google-client-secret 값   Google OAuth 클라이언트 보안 비밀\n"
    "  --cookie-domain 도메인      로그인을 공유할 도메인 (기본: 공개 주소의 상위 도메인)\n"
    "  --listen 주소:포트          수신 주소 (기본 127.0.0.1:8700)\n"
    "  --trusted-proxy IP          X-Forwarded-For를 신뢰할 프록시 (여러 번 지정 가능)\n"
    "  --tailscale-auth            Tailscale 내부 전용: tailscale serve의 사용자 헤더로 로그인\n"
    "  --language ko|en            알림 언어 (기본: LANG 환경 변수)\n"
    "  --output 파일               설정 파일 경로 (기본 /etc/douve/hub.json)\n"
    "  --force                     기존 파일 덮어쓰기\n";

} // namespace

std::string inferCookieDomain(const std::string& publicUrl) {
    auto start = publicUrl.find("://");
    std::string host = start == std::string::npos ? publicUrl : publicUrl.substr(start + 3);
    host = host.substr(0, host.find_first_of(":/"));
    // 라벨이 3개 이상이면 첫 라벨(서비스 이름)을 뗀다
    auto first = host.find('.');
    if (first != std::string::npos && host.find('.', first + 1) != std::string::npos)
        return host.substr(first + 1);
    return host;
}

int runInit(const std::vector<std::string>& args) {
    Json::Value cfg;
    std::string output = "/etc/douve/hub.json";
    bool force = false;
    Json::Value emails(Json::arrayValue), proxies(Json::arrayValue);
    proxies.append("127.0.0.1");
    proxies.append("::1");

    for (std::size_t i = 0; i < args.size(); ++i) {
        const auto& a = args[i];
        auto next = [&](std::string& out) {
            if (i + 1 >= args.size())
                return false;
            out = args[++i];
            return true;
        };
        std::string v;
        if (a == "--force") {
            force = true;
        } else if (a == "--help" || a == "-h") {
            std::cout << T(kUsage);
            return 0;
        } else if (a == "--tailscale-auth") {
            cfg["tailscale_auth"] = true;
        } else if (!next(v)) {
            std::cerr << a << T(" 에 값이 필요합니다\n") << T(kUsage);
            return 2;
        } else if (a == "--public-url") {
            cfg["public_url"] = v;
        } else if (a == "--email") {
            emails.append(v);
        } else if (a == "--google-client-id") {
            cfg["google"]["client_id"] = v;
        } else if (a == "--google-client-secret") {
            cfg["google"]["client_secret"] = v;
        } else if (a == "--cookie-domain") {
            cfg["cookie_domain"] = v;
        } else if (a == "--language") {
            if (v != "ko" && v != "en") {
                std::cerr << "--language: ko | en\n";
                return 2;
            }
            cfg["language"] = v;
        } else if (a == "--listen") {
            auto colon = v.rfind(':');
            if (colon == std::string::npos) {
                std::cerr << T("--listen 은 주소:포트 형식입니다\n");
                return 2;
            }
            cfg["listen_address"] = v.substr(0, colon);
            cfg["listen_port"] = std::stoi(v.substr(colon + 1));
        } else if (a == "--trusted-proxy") {
            proxies.append(v);
        } else if (a == "--output") {
            output = v;
        } else {
            std::cerr << T("알 수 없는 옵션: ") << a << "\n" << T(kUsage);
            return 2;
        }
    }
    if (!cfg.isMember("public_url") || emails.empty()) {
        std::cerr << T(kUsage);
        return 2;
    }
    if (!cfg.isMember("language"))
        cfg["language"] = cliLang();
    if (!cfg.isMember("cookie_domain"))
        cfg["cookie_domain"] = inferCookieDomain(cfg["public_url"].asString());
    cfg["allowed_emails"] = emails;
    cfg["trusted_proxies"] = proxies;
    cfg["database_path"] = "/var/lib/douve/hub.db";

    Json::StreamWriterBuilder w;
    w["indentation"] = "  ";
    w["emitUTF8"] = true;
    const std::string json = Json::writeString(w, cfg) + "\n";

    // 저장 전에 실제 로더로 검증
    std::string error;
    auto parsed = parseConfig(json, error);
    if (!parsed) {
        std::cerr << T("설정 오류: ") << error << "\n";
        return 2;
    }

    int flags = O_WRONLY | O_CREAT | (force ? O_TRUNC : O_EXCL);
    int fd = ::open(output.c_str(), flags, 0600);
    if (fd < 0) {
        std::cerr << output << T(" 을(를) 만들 수 없습니다: ") << std::strerror(errno)
                  << (errno == EEXIST ? T(" (덮어쓰려면 --force)") : "") << "\n";
        return 1;
    }
    ::fchmod(fd, 0600);
    bool ok = ::write(fd, json.data(), json.size()) == static_cast<ssize_t>(json.size());
    ::close(fd);
    if (!ok) {
        std::cerr << T("쓰기 실패\n");
        return 1;
    }
    std::cout << T("설정 파일을 만들었습니다: ") << output << T(" (권한 600)\n")
              << T("  공개 주소:") << " " << parsed->publicUrl << "\n"
              << T("  쿠키 도메인:") << " " << parsed->cookieDomain
              << T(" (이 도메인의 모든 서브도메인에서 로그인 공유)\n") << T("  패스키 RP ID:")
              << " " << parsed->effectiveRpId() << "\n"
              << T("  수신 주소:") << " " << parsed->listenAddress << ":" << parsed->listenPort
              << "\n"
              << T("  Google 로그인:") << " "
              << (parsed->googleEnabled() ? T("사용")
                                          : T("미설정 (패스키 등록 전 첫 로그인에 필요)"))
              << "\n"
              << T("  Google 리디렉션 URI: ") << parsed->publicUrl << "/auth/google/callback\n";
    return 0;
}

} // namespace douve
