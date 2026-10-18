#include "config.h"

#include <json/json.h>

#include <algorithm>
#include <fstream>
#include <sstream>

namespace douve {
namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

bool startsWith(const std::string& s, const std::string& p) {
    return s.rfind(p, 0) == 0;
}

bool endsWith(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// publicUrl에서 호스트만 추출 (https://host[:port][/...]).
std::string hostOf(const std::string& url) {
    auto start = url.find("://");
    if (start == std::string::npos)
        return {};
    start += 3;
    auto end = url.find_first_of(":/", start);
    return lower(url.substr(start, end == std::string::npos ? std::string::npos : end - start));
}

} // namespace

std::string HubConfig::origin() const {
    auto start = publicUrl.find("://");
    if (start == std::string::npos)
        return publicUrl;
    auto end = publicUrl.find('/', start + 3);
    return end == std::string::npos ? publicUrl : publicUrl.substr(0, end);
}

std::string HubConfig::effectiveInternalUrl() const {
    if (!internalUrl.empty())
        return internalUrl;
    std::string host = listenAddress;
    if (host == "0.0.0.0" || host.empty())
        host = "127.0.0.1";
    else if (host == "::")
        host = "[::1]";
    return "http://" + host + ":" + std::to_string(listenPort);
}

namespace {
std::optional<HubConfig> parseConfigImpl(const std::string& json, std::string& error) {
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string parseErrors;
    std::istringstream in(json);
    if (!Json::parseFromStream(builder, in, &root, &parseErrors) || !root.isObject()) {
        error = "설정 파일 JSON 오류: " + parseErrors;
        return std::nullopt;
    }

    HubConfig c;
    auto str = [&](const char* key, std::string& out) {
        if (root.isMember(key))
            out = root[key].asString();
    };
    auto num = [&](const char* key, int& out) {
        if (root.isMember(key))
            out = root[key].asInt();
    };
    str("public_url", c.publicUrl);
    str("cookie_domain", c.cookieDomain);
    str("rp_id", c.rpId);
    str("rp_name", c.rpName);
    str("listen_address", c.listenAddress);
    str("database_path", c.databasePath);
    str("redirect_host_suffix", c.redirectHostSuffix);
    if (root.isMember("listen_port")) {
        int p = root["listen_port"].asInt();
        if (p <= 0 || p > 65535) {
            error = "listen_port 범위 오류";
            return std::nullopt;
        }
        c.listenPort = static_cast<std::uint16_t>(p);
    }
    if (root.isMember("google")) {
        const auto& g = root["google"];
        c.googleClientId = g.get("client_id", "").asString();
        c.googleClientSecret = g.get("client_secret", "").asString();
        c.googleAuthUrl = g.get("auth_url", c.googleAuthUrl).asString();
        c.googleTokenUrl = g.get("token_url", c.googleTokenUrl).asString();
        c.googleJwksUrl = g.get("jwks_url", c.googleJwksUrl).asString();
    }
    for (const auto& e : root["allowed_emails"])
        c.allowedEmails.push_back(lower(e.asString()));
    if (root.isMember("trusted_proxies")) {
        c.trustedProxies.clear();
        for (const auto& p : root["trusted_proxies"])
            c.trustedProxies.push_back(p.asString());
    }
    str("agent_dir", c.agentDir);
    str("privacy_contact", c.privacyContact);
    str("language", c.language);
    str("internal_url", c.internalUrl);
    str("tunnel_url", c.tunnelUrl);
    if (root.isMember("tailscale_auth"))
        c.tailscaleAuth = root["tailscale_auth"].asBool();
    num("metrics_retention_days", c.metricsRetentionDays);
    if (root.isMember("telegram")) {
        const auto& t = root["telegram"];
        c.telegramBotToken = t.get("bot_token", "").asString();
        c.telegramChatId = t.get("chat_id", "").asString();
        c.telegramApiUrl = t.get("api_url", c.telegramApiUrl).asString();
    }
    num("session_idle_days", c.sessionIdleDays);
    num("session_max_days", c.sessionMaxDays);
    num("reauth_minutes", c.reauthMinutes);

    c.publicUrl = c.publicUrl.empty()
                      ? c.publicUrl
                      : (c.publicUrl.back() == '/' ? c.publicUrl.substr(0, c.publicUrl.size() - 1)
                                                   : c.publicUrl);
    c.cookieDomain = lower(c.cookieDomain);
    c.rpId = lower(c.rpId);
    if (c.cookieDomain.size() > 0 && c.cookieDomain.front() == '.')
        c.cookieDomain.erase(0, 1);
    if (c.redirectHostSuffix.empty() && !c.cookieDomain.empty())
        c.redirectHostSuffix = "." + c.cookieDomain;

    // 검증
    if (!startsWith(c.publicUrl, "https://") && !startsWith(c.publicUrl, "http://localhost") &&
        !startsWith(c.publicUrl, "http://127.0.0.1")) {
        error = "public_url은 https:// 이어야 합니다 (로컬 테스트용 http://localhost 예외)";
        return std::nullopt;
    }
    if (c.cookieDomain.empty()) {
        error = "cookie_domain이 필요합니다";
        return std::nullopt;
    }
    const std::string host = hostOf(c.publicUrl);
    if (host != c.cookieDomain && !endsWith(host, "." + c.cookieDomain)) {
        error = "public_url 호스트(" + host + ")가 cookie_domain(" + c.cookieDomain +
                ")에 속하지 않습니다";
        return std::nullopt;
    }
    const std::string& rp = c.effectiveRpId();
    if (host != rp && !endsWith(host, "." + rp)) {
        error = "rp_id(" + rp + ")는 public_url 호스트와 같거나 그 상위 도메인이어야 합니다";
        return std::nullopt;
    }
    if (c.sessionIdleDays <= 0 || c.sessionMaxDays < c.sessionIdleDays || c.reauthMinutes <= 0) {
        error = "세션 기간 설정 오류 (session_max_days >= session_idle_days > 0)";
        return std::nullopt;
    }
    if (c.metricsRetentionDays <= 0) {
        error = "metrics_retention_days는 1 이상이어야 합니다";
        return std::nullopt;
    }
    return c;
}

} // namespace

// 형식이 틀린 값(예: "google"이 객체가 아니라 배열)에서 jsoncpp가 예외를 던지므로 오류로 바꾼다
// (퍼징으로 발견).
std::optional<HubConfig> parseConfig(const std::string& json, std::string& error) {
    try {
        return parseConfigImpl(json, error);
    } catch (const Json::Exception& e) {
        error = std::string("설정 파일 형식 오류: ") + e.what();
        return std::nullopt;
    }
}

std::optional<HubConfig> loadConfigFile(const std::string& path, std::string& error) {
    std::ifstream f(path);
    if (!f) {
        error = "설정 파일을 열 수 없습니다: " + path;
        return std::nullopt;
    }
    std::stringstream ss;
    ss << f.rdbuf();
    auto cfg = parseConfig(ss.str(), error);
    if (cfg)
        cfg->sourcePath = path;
    return cfg;
}

} // namespace douve
