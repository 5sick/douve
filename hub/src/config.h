#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace douve {

// /etc/douve/hub.json 내용. 설정은 이 파일 하나로 끝나도록 유지한다.
struct HubConfig {
    std::string sourcePath; // 읽은 설정 파일 경로 (백업에 원문을 담을 때)
    // Hub에 접속하는 공개 주소 (예: https://douve.example.com). origin 검사·리다이렉트에 사용.
    std::string publicUrl;
    // 세션 쿠키 도메인 (예: example.com → 모든 서브도메인에서 로그인 공유).
    std::string cookieDomain;
    // WebAuthn RP ID. 비우면 cookieDomain을 사용 (서브도메인 어디서든 같은 패스키 사용 가능).
    std::string rpId;
    std::string rpName = "Douve";

    std::string listenAddress = "127.0.0.1";
    std::uint16_t listenPort = 8700;
    std::string databasePath = "/var/lib/douve/hub.db";

    std::string googleClientId;
    std::string googleClientSecret;
    // Google 엔드포인트 (테스트에서 가짜 서버로 바꿀 때만 설정)
    std::string googleAuthUrl = "https://accounts.google.com/o/oauth2/v2/auth";
    std::string googleTokenUrl = "https://oauth2.googleapis.com/token";
    std::string googleJwksUrl = "https://www.googleapis.com/oauth2/v3/certs";
    bool googleEnabled() const { return !googleClientId.empty() && !googleClientSecret.empty(); }
    // 로그인 허용 이메일 (소문자로 정규화). 비어 있으면 아무도 로그인할 수 없다.
    std::vector<std::string> allowedEmails;

    int sessionIdleDays = 30; // 이 기간 동안 사용하지 않으면 만료
    int sessionMaxDays = 90;  // 사용 여부와 무관한 최대 수명
    int reauthMinutes = 5;    // 민감한 작업 전 재인증 유효 시간

    // X-Forwarded-For / X-Real-IP를 신뢰할 프록시 주소 (예: 입구 서버 10.200.0.1).
    std::vector<std::string> trustedProxies = {"127.0.0.1", "::1"};

    // 로그인 후 돌아갈 주소로 허용할 호스트 접미사 (예: .example.com). 비우면 cookieDomain
    // 사용.
    std::string redirectHostSuffix;

    // 입구(edge) Agent가 로그인 확인(/auth/verify)과 Hub 프록시에 쓸 내부 주소.
    // 비우면 http://<listen_address>:<listen_port> (0.0.0.0이면 127.0.0.1).
    std::string internalUrl;
    // Agent 터널 주소. 비우면 public_url이 가리키는 입구 (wss://<호스트>/_douve/tunnel).
    // Hub 주소가 입구를 거치지 않는 구성에서만 지정한다.
    std::string tunnelUrl;
    // Tailscale 내부 전용 모드: `tailscale serve`가 127.0.0.1로 넘기는 Tailscale-User-Login을
    // 로그인으로 인정 (패스키 불필요). Hub는 127.0.0.1에서만 받아야 한다 — 다른 경로로 들어온
    // 헤더는 믿지 않는다.
    bool tailscaleAuth = false;
    std::string effectiveInternalUrl() const;

    // join.sh가 내려줄 Agent 바이너리 위치 (douve-agent-linux-amd64, -arm64, SHA256SUMS).
    std::string agentDir = "/usr/local/share/douve/agent";
    // 개인정보처리방침에 보일 운영자 연락처 (이메일 등, 비우면 문구 숨김)
    std::string privacyContact;
    // 알림(텔레그램) 언어 기본값: ko | en (웹 설정이 있으면 그것이 우선)
    std::string language = "ko";
    int metricsRetentionDays = 30;

    // 텔레그램 알림. 둘 다 있어야 보낸다.
    std::string telegramBotToken;
    std::string telegramChatId;
    // 테스트에서 가짜 서버로 바꿀 때만 설정
    std::string telegramApiUrl = "https://api.telegram.org";
    bool telegramEnabled() const { return !telegramBotToken.empty() && !telegramChatId.empty(); }

    const std::string& effectiveRpId() const { return rpId.empty() ? cookieDomain : rpId; }
    // publicUrl의 origin (scheme://host[:port]).
    std::string origin() const;
};

// JSON 문자열에서 설정을 읽고 검증한다. 실패 시 nullopt + error.
std::optional<HubConfig> parseConfig(const std::string& json, std::string& error);
std::optional<HubConfig> loadConfigFile(const std::string& path, std::string& error);

} // namespace douve
