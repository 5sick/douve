#include "cluster/channels.h"

#include "util/crypto.h"
#include "util/encoding.h"

#include <algorithm>
#include <regex>

namespace douve {

namespace {

std::string compact(const Json::Value& v) {
    Json::StreamWriterBuilder w;
    w["indentation"] = "";
    w["emitUTF8"] = true;
    return Json::writeString(w, v);
}

Json::Value parseJson(const std::string& s) {
    Json::Value v;
    Json::CharReaderBuilder b;
    std::string errs;
    std::istringstream in(s);
    if (!Json::parseFromStream(b, in, &v, &errs) || !v.isObject())
        return Json::Value(Json::objectValue);
    return v;
}

bool cleanText(const std::string& s, std::size_t max) {
    return s.size() <= max && std::none_of(s.begin(), s.end(), [](unsigned char c) {
               return c < 0x20 || c == 0x7f || c == ' ';
           });
}

bool httpUrl(const std::string& u, bool allowHttp) {
    return cleanText(u, 2000) &&
           (u.rfind("https://", 0) == 0 || (allowHttp && u.rfind("http://", 0) == 0)) &&
           u.find('@') == std::string::npos;
}

// 문자열 끝 일부만 남긴다: https://discord.com/…a1b2
std::string maskUrl(const std::string& u) {
    auto start = u.find("://");
    start = start == std::string::npos ? 0 : start + 3;
    auto slash = u.find('/', start);
    const std::string base = u.substr(0, slash);
    return base + "/…" + (u.size() > 4 ? u.substr(u.size() - 4) : "");
}

// 알림 시작 이모지로 중요도 (🔴 장애, 🚨 심각 보안, ⚠️ 경고)
bool urgent(const std::string& text) {
    for (const char* e : {"🔴", "🚨", "⚠️"})
        if (text.rfind(e, 0) == 0)
            return true;
    return false;
}

Channel fromRow(Statement& s) {
    Channel c;
    c.id = s.int64(0);
    c.kind = s.text(1);
    c.name = s.text(2);
    c.config = parseJson(s.text(3));
    c.enabled = s.int64(4) != 0;
    c.createdAt = s.int64(5);
    return c;
}

} // namespace

std::string validateChannel(Channel& c) {
    auto& cfg = c.config;
    if (!cfg.isObject())
        cfg = Json::Value(Json::objectValue);
    auto str = [&](const char* k) { return cfg.get(k, "").asString(); };
    if (c.name.empty())
        c.name = c.kind;
    if (c.name.size() > 40)
        return "이름은 40자까지입니다";
    Json::Value out(Json::objectValue);
    if (c.kind == "ntfy") {
        std::string server = str("server");
        if (server.empty())
            server = "https://ntfy.sh";
        while (!server.empty() && server.back() == '/')
            server.pop_back();
        // 집 안의 ntfy 서버(http)도 쓸 수 있게
        if (!httpUrl(server, true))
            return "ntfy 서버 주소는 https:// 또는 http:// 로 시작해야 합니다";
        static const std::regex topicRe("^[A-Za-z0-9_-]{1,64}$");
        const std::string topic = str("topic");
        if (!std::regex_match(topic, topicRe))
            return "ntfy 토픽은 영문·숫자·_·- 1~64자입니다";
        const std::string token = str("token");
        if (!cleanText(token, 200))
            return "ntfy 토큰 형식이 올바르지 않습니다";
        out["server"] = server;
        out["topic"] = topic;
        if (!token.empty())
            out["token"] = token;
    } else if (c.kind == "discord") {
        static const std::regex re(
            R"(^https://((ptb\.|canary\.)?discord\.com|discordapp\.com)/api/webhooks/[0-9]+/[A-Za-z0-9_-]+$)");
        if (!std::regex_match(str("url"), re))
            return "Discord 웹훅 주소가 아닙니다 (https://discord.com/api/webhooks/…)";
        out["url"] = str("url");
    } else if (c.kind == "slack") {
        static const std::regex re(R"(^https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+$)");
        if (!std::regex_match(str("url"), re))
            return "Slack 웹훅 주소가 아닙니다 (https://hooks.slack.com/services/…)";
        out["url"] = str("url");
    } else if (c.kind == "webhook") {
        if (!httpUrl(str("url"), true))
            return "웹훅 주소는 https:// 또는 http:// 로 시작해야 합니다";
        if (!cleanText(str("secret"), 200))
            return "서명 비밀값 형식이 올바르지 않습니다";
        out["url"] = str("url");
        if (!str("secret").empty())
            out["secret"] = str("secret");
    } else {
        return "알림 채널 종류는 ntfy, discord, slack, webhook 입니다";
    }
    cfg = out;
    return {};
}

std::vector<Channel> listChannels(Database& db) {
    std::vector<Channel> out;
    Statement s(db, "SELECT id, kind, name, config, enabled, created_at FROM notify_channels "
                    "ORDER BY id");
    while (s.step())
        out.push_back(fromRow(s));
    return out;
}

std::optional<Channel> findChannel(Database& db, std::int64_t id) {
    Statement s(db, "SELECT id, kind, name, config, enabled, created_at FROM notify_channels "
                    "WHERE id = ?");
    s.bind(1, id);
    if (!s.step())
        return std::nullopt;
    return fromRow(s);
}

std::int64_t createChannel(Database& db, const Channel& c, std::int64_t now) {
    auto guard = db.lock();
    Statement(db, "INSERT INTO notify_channels (kind, name, config, enabled, created_at) "
                  "VALUES (?, ?, ?, ?, ?)")
        .bind(1, c.kind)
        .bind(2, c.name)
        .bind(3, compact(c.config))
        .bind(4, c.enabled ? 1 : 0)
        .bind(5, now)
        .run();
    return db.lastInsertId();
}

bool deleteChannel(Database& db, std::int64_t id) {
    auto guard = db.lock();
    Statement(db, "DELETE FROM notify_channels WHERE id = ?").bind(1, id).run();
    return db.changes() > 0;
}

bool setChannelEnabled(Database& db, std::int64_t id, bool enabled) {
    auto guard = db.lock();
    Statement(db, "UPDATE notify_channels SET enabled = ? WHERE id = ?")
        .bind(1, enabled ? 1 : 0)
        .bind(2, id)
        .run();
    return db.changes() > 0;
}

Json::Value channelJson(const Channel& c) {
    Json::Value v;
    v["id"] = Json::Int64(c.id);
    v["kind"] = c.kind;
    v["name"] = c.name;
    v["enabled"] = c.enabled;
    if (c.kind == "ntfy") {
        // 공개 ntfy.sh에서는 토픽 이름이 곧 비밀번호다
        const std::string topic = c.config.get("topic", "").asString();
        v["target"] = c.config.get("server", "").asString() + "/" + topic.substr(0, 2) + "…";
        v["has_token"] = c.config.isMember("token");
    } else {
        v["target"] = maskUrl(c.config.get("url", "").asString());
        v["has_secret"] = c.config.isMember("secret");
    }
    return v;
}

HttpPost channelRequest(const Channel& c, const std::string& text, std::int64_t now) {
    HttpPost r;
    const auto& cfg = c.config;
    if (c.kind == "ntfy") {
        r.url =
            cfg.get("server", "https://ntfy.sh").asString() + "/" + cfg.get("topic", "").asString();
        r.body = text;
        r.contentType = "text/plain; charset=utf-8";
        r.headers.emplace_back("Title", "Douve");
        r.headers.emplace_back("Priority", urgent(text) ? "high" : "default");
        if (cfg.isMember("token"))
            r.headers.emplace_back("Authorization", "Bearer " + cfg["token"].asString());
    } else if (c.kind == "discord") {
        Json::Value b;
        b["username"] = "Douve";
        // Discord 메시지는 2000자까지. 서버 이름 등에 든 @everyone 같은 멘션이 울리지 않게 막는다.
        b["content"] = text.size() > 1900 ? text.substr(0, 1900) + "…" : text;
        b["allowed_mentions"]["parse"] = Json::Value(Json::arrayValue);
        r.url = cfg.get("url", "").asString();
        r.body = compact(b);
    } else if (c.kind == "slack") {
        // Slack 서식 문자 이스케이프 (<!channel> 같은 멘션 방지)
        std::string esc;
        for (char ch : text) {
            if (ch == '&')
                esc += "&amp;";
            else if (ch == '<')
                esc += "&lt;";
            else if (ch == '>')
                esc += "&gt;";
            else
                esc += ch;
        }
        Json::Value b;
        b["text"] = esc;
        r.url = cfg.get("url", "").asString();
        r.body = compact(b);
    } else { // webhook
        Json::Value b;
        b["source"] = "douve";
        b["text"] = text;
        b["time"] = Json::Int64(now);
        r.url = cfg.get("url", "").asString();
        r.body = compact(b);
        if (cfg.isMember("secret")) {
            // 받는 쪽 검증: HMAC-SHA256(secret, "<timestamp>.<body>")
            const std::string ts = std::to_string(now);
            r.headers.emplace_back("X-Douve-Timestamp", ts);
            r.headers.emplace_back(
                "X-Douve-Signature",
                "sha256=" + toHex(hmacSha256(cfg["secret"].asString(), ts + "." + r.body)));
        }
    }
    return r;
}

} // namespace douve
