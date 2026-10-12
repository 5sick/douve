#pragma once

#include "config.h"
#include "store/db.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace douve {

inline constexpr const char* kSessionCookie = "douve_session";
// 기기(브라우저) 구분용 쿠키. 로그인 정보가 아니며 Hub 주소에만 보낸다 (Domain 없음).
inline constexpr const char* kDeviceCookie = "douve_device";

struct SessionInfo {
    std::int64_t userId = 0;
    std::string email;
    std::string authMethod; // "google" | "passkey"
    std::int64_t createdAt = 0;
    std::int64_t lastSeenAt = 0;
    std::int64_t reauthAt = 0; // 마지막으로 패스키/구글로 직접 인증한 시각
    std::string ip;
    std::string userAgent;
    std::string idHint; // 목록 표시용 (토큰 해시 앞 8자, 원본 토큰은 노출하지 않음)
};

// 서버 저장 세션. DB에는 토큰의 SHA-256만 저장하므로 DB가 유출돼도 세션을 탈취할 수 없다.
class SessionManager {
  public:
    SessionManager(Database& db, const HubConfig& cfg) : db_(db), cfg_(cfg) {}

    // 새 세션을 만들고 쿠키에 넣을 원본 토큰을 반환한다.
    // deviceHash가 있으면 같은 사용자의 같은 기기 세션은 이 새 세션 하나만 남긴다.
    std::string create(std::int64_t userId, const std::string& method, const std::string& ip,
                       const std::string& userAgent, std::int64_t now,
                       const std::string& deviceHash = "");

    // 유효하면 세션 정보를 반환하고 미사용 만료 시각을 연장한다 (쓰기 줄이려고 5분 단위로만 갱신).
    std::optional<SessionInfo> validate(const std::string& token, std::int64_t now);

    // 민감한 작업 전 재인증 시각 갱신 / 재인증이 아직 유효한지.
    void markReauth(const std::string& token, std::int64_t now);
    bool reauthFresh(const SessionInfo& s, std::int64_t now) const;

    void revoke(const std::string& token);
    void revokeByHint(std::int64_t userId, const std::string& idHint);
    int revokeAllForUser(std::int64_t userId);
    std::vector<SessionInfo> listForUser(std::int64_t userId, std::int64_t now);
    void purgeExpired(std::int64_t now);

    // Set-Cookie 헤더 값. maxAge는 초.
    std::string cookieHeader(const std::string& token) const;
    std::string clearCookieHeader() const;

  private:
    Database& db_;
    const HubConfig& cfg_;
};

// Cookie 헤더에서 이름에 해당하는 값을 찾는다.
std::optional<std::string> cookieValue(const std::string& cookieHeader, const std::string& name);

} // namespace douve
