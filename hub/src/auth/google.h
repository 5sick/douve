#pragma once

#include "auth/jwt.h"
#include "config.h"

#include <functional>
#include <mutex>
#include <optional>
#include <string>

namespace douve {

// PKCE (RFC 7636) S256.
struct Pkce {
    std::string verifier;
    std::string challenge;
};
Pkce makePkce();

// Google OIDC 인가 요청 URL.
std::string googleAuthorizeUrl(const HubConfig& cfg, const std::string& clientId,
                               const std::string& state, const std::string& nonce,
                               const std::string& codeChallenge);
std::string googleRedirectUri(const HubConfig& cfg);

// "https://host[:port]/path" → {"https://host[:port]", "/path"}.
std::pair<std::string, std::string> splitUrl(const std::string& url);

// 토큰 교환과 ID 토큰 검증. Google은 신원 확인에만 쓰므로 access/refresh 토큰은 저장하지 않는다.
class GoogleOidc {
  public:
    explicit GoogleOidc(const HubConfig& cfg) : cfg_(cfg) {}

    using Done = std::function<void(std::optional<GoogleIdentity>, std::string error)>;

    // 인가 코드 → ID 토큰 → 서명·클레임 검증. 콜백은 Drogon 이벤트 루프에서 호출된다.
    void completeLogin(const std::string& code, const std::string& verifier,
                       const std::string& nonce, std::int64_t now, const std::string& clientId,
                       const std::string& clientSecret, Done done);

  private:
    void withKeys(const std::string& kid, std::int64_t now,
                  std::function<void(std::optional<JwkSet>)> cb);

    const HubConfig& cfg_;
    std::mutex mu_;
    std::optional<JwkSet> keys_;
    std::int64_t keysExpireAt_ = 0;
    std::int64_t lastFetchAt_ = 0;
};

} // namespace douve
