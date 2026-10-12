#include "auth/google.h"

#include "util/crypto.h"

#include "net/https_client.h"

#include <drogon/drogon.h>
#include <json/json.h>

#include <sstream>

#include <regex>

namespace douve {

Pkce makePkce() {
    Pkce p;
    p.verifier = randomToken(48);
    p.challenge = base64UrlEncode(sha256(p.verifier));
    return p;
}

std::string googleRedirectUri(const HubConfig& cfg) {
    return cfg.publicUrl + "/auth/google/callback";
}

std::string googleAuthorizeUrl(const HubConfig& cfg, const std::string& clientId,
                               const std::string& state, const std::string& nonce,
                               const std::string& codeChallenge) {
    return cfg.googleAuthUrl + "?response_type=code" + "&client_id=" + urlEncode(clientId) +
           "&redirect_uri=" + urlEncode(googleRedirectUri(cfg)) +
           "&scope=" + urlEncode("openid email") + "&state=" + urlEncode(state) +
           "&nonce=" + urlEncode(nonce) + "&code_challenge=" + urlEncode(codeChallenge) +
           "&code_challenge_method=S256" + "&prompt=select_account";
}

std::pair<std::string, std::string> splitUrl(const std::string& url) {
    auto scheme = url.find("://");
    auto slash = scheme == std::string::npos ? std::string::npos : url.find('/', scheme + 3);
    if (slash == std::string::npos)
        return {url, "/"};
    return {url.substr(0, slash), url.substr(slash)};
}

namespace {
// Cache-Control: max-age=N → N (없으면 1시간)
std::int64_t maxAge(const std::string& cacheControl) {
    static const std::regex re(R"(max-age=(\d+))");
    std::smatch m;
    if (std::regex_search(cacheControl, m, re))
        return std::min<std::int64_t>(std::stoll(m[1]), 86400);
    return 3600;
}
} // namespace

void GoogleOidc::withKeys(const std::string& kid, std::int64_t now,
                          std::function<void(std::optional<JwkSet>)> cb) {
    {
        std::lock_guard lk(mu_);
        // 캐시가 유효하고 kid를 알면 바로 사용. 모르는 kid면 키 교체 중일 수 있으니 재조회(10초에
        // 1회로 제한).
        if (keys_ && now < keysExpireAt_ && (keys_->has(kid) || now - lastFetchAt_ < 10))
            return cb(keys_);
        lastFetchAt_ = now;
    }
    httpFetchAsync(cfg_.googleJwksUrl, std::nullopt, [this, now, cb](HttpResult r) {
        if (!r.ok || r.status != 200) {
            LOG_WARN << "Google JWKS 조회 실패: "
                     << (r.ok ? "HTTP " + std::to_string(r.status) : r.error);
            std::lock_guard lk(mu_);
            return cb(keys_); // 실패하면 기존 키로라도 시도
        }
        std::string err;
        auto set = JwkSet::parse(r.body, err);
        std::lock_guard lk(mu_);
        if (set) {
            keys_ = std::move(set);
            keysExpireAt_ = now + maxAge(r.cacheControl);
        }
        cb(keys_);
    });
}

void GoogleOidc::completeLogin(const std::string& code, const std::string& verifier,
                               const std::string& nonce, std::int64_t now,
                               const std::string& clientId, const std::string& clientSecret,
                               Done done) {
    const std::string form = "grant_type=authorization_code&code=" + urlEncode(code) +
                             "&redirect_uri=" + urlEncode(googleRedirectUri(cfg_)) +
                             "&client_id=" + urlEncode(clientId) +
                             "&client_secret=" + urlEncode(clientSecret) +
                             "&code_verifier=" + urlEncode(verifier);

    httpFetchAsync(cfg_.googleTokenUrl, form, [this, nonce, now, clientId, done](HttpResult r) {
        if (!r.ok)
            return done(std::nullopt, "토큰 서버에 연결할 수 없습니다: " + r.error);
        Json::Value body;
        std::string parseErr;
        Json::CharReaderBuilder rb;
        std::istringstream in(r.body);
        const bool parsed = Json::parseFromStream(rb, in, &body, &parseErr);
        if (r.status != 200 || !parsed || !body["id_token"].isString()) {
            return done(std::nullopt, "토큰 교환 실패 (HTTP " + std::to_string(r.status) + ")");
        }
        std::string err;
        auto parts = splitJwt(body["id_token"].asString(), err);
        if (!parts)
            return done(std::nullopt, err);
        const std::string kid = parts->header.get("kid", "").asString();
        withKeys(kid, now,
                 [this, parts = std::move(*parts), nonce, now, clientId,
                  done](std::optional<JwkSet> keys) {
                     std::string err;
                     if (!keys)
                         return done(std::nullopt, "Google 공개키를 가져올 수 없습니다");
                     if (!verifyRs256(parts, *keys, err))
                         return done(std::nullopt, err);
                     auto id = checkGoogleClaims(parts.claims, {clientId, nonce, now, 120}, err);
                     done(id, err);
                 });
    });
}

} // namespace douve
