#include "store/invites.h"

#include "util/crypto.h"
#include "util/json.h"

#include <algorithm>
#include <cctype>

namespace douve {

Invite createInvite(Database& db, const std::string& email, std::optional<std::int64_t> createdBy,
                    int ttlSeconds, std::int64_t now, const InviteAccess& access) {
    Invite inv;
    inv.token = randomToken(32);
    inv.email = email;
    std::transform(inv.email.begin(), inv.email.end(), inv.email.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    inv.expiresAt = now + ttlSeconds;
    Json::Value g(Json::objectValue);
    g["nodes"] = Json::Value(Json::arrayValue);
    g["services"] = Json::Value(Json::arrayValue);
    for (auto id : access.nodes)
        g["nodes"].append(Json::Int64(id));
    for (auto id : access.services)
        g["services"].append(Json::Int64(id));
    Json::StreamWriterBuilder w;
    w["indentation"] = "";
    Statement s(db, "INSERT INTO invites (token_hash, email, created_by, created_at, expires_at, "
                    "role, grants) VALUES (?, ?, ?, ?, ?, ?, ?)");
    s.bind(1, sha256(inv.token)).bind(2, inv.email).bind(3, createdBy).bind(4, now);
    s.bind(5, inv.expiresAt).bind(6, roleName(access.role)).bind(7, Json::writeString(w, g)).run();
    return inv;
}

std::optional<InviteAccess> inviteAccess(Database& db, const std::string& token) {
    Statement s(db, "SELECT role, grants FROM invites WHERE token_hash = ?");
    s.bind(1, sha256(token));
    if (!s.step())
        return std::nullopt;
    InviteAccess a;
    a.role = parseRole(s.text(0)).value_or(Role::App);
    Json::Value g;
    if (parseJson(s.text(1), g) && g.isObject()) {
        for (const auto& id : g["nodes"])
            if (id.isInt64())
                a.nodes.insert(id.asInt64());
        for (const auto& id : g["services"])
            if (id.isInt64())
                a.services.insert(id.asInt64());
    }
    return a;
}

std::optional<std::string> peekInvite(Database& db, const std::string& token, std::int64_t now) {
    if (token.size() < 32 || token.size() > 128)
        return std::nullopt;
    Statement s(db, "SELECT email FROM invites WHERE token_hash = ? AND used_at IS NULL AND "
                    "expires_at > ?");
    s.bind(1, sha256(token)).bind(2, now);
    if (!s.step())
        return std::nullopt;
    return s.text(0);
}

bool consumeInvite(Database& db, const std::string& token, std::int64_t now) {
    auto guard = db.lock();
    Statement s(db, "UPDATE invites SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND "
                    "expires_at > ?");
    s.bind(1, now).bind(2, sha256(token)).bind(3, now).run();
    return db.changes() == 1;
}

void setUserAllowed(Database& db, std::int64_t userId, bool allowed) {
    Statement s(db, "UPDATE users SET allowed = ? WHERE id = ?");
    s.bind(1, allowed ? 1 : 0).bind(2, userId).run();
}

bool userAllowed(Database& db, const std::string& email) {
    Statement s(db, "SELECT allowed FROM users WHERE email = ?");
    s.bind(1, email);
    return s.step() && s.int64(0) != 0;
}

std::optional<std::string> getSetting(Database& db, const std::string& key) {
    Statement s(db, "SELECT value FROM settings WHERE key = ?");
    s.bind(1, key);
    if (!s.step())
        return std::nullopt;
    return s.text(0);
}

void putSetting(Database& db, const std::string& key, const std::string& value, std::int64_t now) {
    Statement s(
        db,
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at");
    s.bind(1, key).bind(2, value).bind(3, now).run();
}

void deleteSetting(Database& db, const std::string& key) {
    Statement s(db, "DELETE FROM settings WHERE key = ?");
    s.bind(1, key).run();
}

} // namespace douve
