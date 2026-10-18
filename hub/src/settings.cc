#include "settings.h"
#include "util/json.h"

#include "store/invites.h"

#include <regex>
#include <sstream>

namespace douve {
namespace {
struct Key {
    const char* name;
    std::string Credentials::* field;
    std::string HubConfig::* fallback;
};
const Key kKeys[] = {
    {"google.client_id", &Credentials::googleClientId, &HubConfig::googleClientId},
    {"google.client_secret", &Credentials::googleClientSecret, &HubConfig::googleClientSecret},
    {"telegram.bot_token", &Credentials::telegramBotToken, &HubConfig::telegramBotToken},
    {"telegram.chat_id", &Credentials::telegramChatId, &HubConfig::telegramChatId},
};
} // namespace

Json::Value Features::toJson() const {
    Json::Value v;
    v["monitoring"] = monitoring;
    v["service_checks"] = serviceChecks;
    v["terminal"] = terminal;
    v["security"]["ssh"] = secSsh;
    v["security"]["sudo"] = secSudo;
    v["security"]["account"] = secAccount;
    v["security"]["files"] = secFiles;
    v["security"]["ports"] = secPorts;
    return v;
}

Features Features::fromJson(const Json::Value& v) {
    Features f;
    if (!v.isObject())
        return f;
    f.monitoring = v.get("monitoring", true).asBool();
    f.serviceChecks = v.get("service_checks", true).asBool();
    f.terminal = v.get("terminal", true).asBool();
    const auto& sec = v["security"];
    if (sec.isObject()) {
        f.secSsh = sec.get("ssh", true).asBool();
        f.secSudo = sec.get("sudo", true).asBool();
        f.secAccount = sec.get("account", true).asBool();
        f.secFiles = sec.get("files", true).asBool();
        f.secPorts = sec.get("ports", true).asBool();
    }
    return f;
}

Features RuntimeSettings::features() const {
    std::lock_guard lk(mu_);
    return f_;
}

void RuntimeSettings::saveFeatures(Database& db, const Features& f, std::int64_t now) {
    Json::StreamWriterBuilder w;
    w["indentation"] = "";
    putSetting(db, "features", Json::writeString(w, f.toJson()), now);
    std::lock_guard lk(mu_);
    f_ = f;
}

void RuntimeSettings::load(const HubConfig& cfg, Database& db) {
    if (auto raw = getSetting(db, "features")) {
        Json::Value v;
        if (parseJson(*raw, v)) {
            std::lock_guard lk(mu_);
            f_ = Features::fromJson(v);
        }
    }
    Credentials c;
    for (const auto& k : kKeys) {
        auto v = getSetting(db, k.name);
        c.*k.field = v ? *v : cfg.*k.fallback;
    }
    std::lock_guard lk(mu_);
    c_ = std::move(c);
}

Credentials RuntimeSettings::get() const {
    std::lock_guard lk(mu_);
    return c_;
}

void RuntimeSettings::save(Database& db, const HubConfig& cfg, const Credentials& c,
                           std::int64_t now) {
    {
        Transaction tx(db);
        for (const auto& k : kKeys) {
            const std::string& v = c.*k.field;
            if (v.empty())
                deleteSetting(db, k.name);
            else
                putSetting(db, k.name, v, now);
        }
        tx.commit();
    }
    load(cfg, db);
}

std::string validateTelegram(const std::string& botToken, const std::string& chatId) {
    static const std::regex token(R"(^\d{5,15}:[A-Za-z0-9_-]{30,50}$)");
    static const std::regex chat(R"(^(-?\d{1,20}|@[A-Za-z0-9_]{5,32})$)");
    if (!botToken.empty() && !std::regex_match(botToken, token))
        return "텔레그램 봇 토큰 형식이 올바르지 않습니다 (예: 123456789:ABC…)";
    if (!chatId.empty() && !std::regex_match(chatId, chat))
        return "텔레그램 chat id 형식이 올바르지 않습니다 (숫자 또는 @채널이름)";
    return {};
}

std::string validateGoogle(const std::string& clientId, const std::string& clientSecret) {
    static const std::regex id(R"(^[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com$)");
    if (!clientId.empty() && !std::regex_match(clientId, id))
        return "Google 클라이언트 ID 형식이 올바르지 않습니다 (…apps.googleusercontent.com)";
    if (clientSecret.size() > 200 || clientSecret.find_first_of(" \t\r\n") != std::string::npos)
        return "Google 클라이언트 보안 비밀 형식이 올바르지 않습니다";
    return {};
}

} // namespace douve
