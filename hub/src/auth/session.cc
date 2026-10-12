#include "auth/session.h"

#include "util/crypto.h"

namespace douve {
namespace {
constexpr std::int64_t kDay = 24 * 60 * 60;
constexpr std::int64_t kTouchInterval = 5 * 60;

Bytes tokenHash(const std::string& token) {
    return sha256(token);
}
} // namespace

std::string SessionManager::create(std::int64_t userId, const std::string& method,
                                   const std::string& ip, const std::string& userAgent,
                                   std::int64_t now, const std::string& deviceHash) {
    std::string token = randomToken(32);
    auto guard = db_.lock();
    if (!deviceHash.empty())
        Statement(db_, "DELETE FROM sessions WHERE user_id = ? AND device_hash = ?")
            .bind(1, userId)
            .bind(2, deviceHash)
            .run();
    Statement(db_,
              "INSERT INTO sessions (token_hash, user_id, auth_method, created_at, last_seen_at, "
              "idle_expires_at, absolute_expires_at, reauth_at, ip, user_agent, device_hash) "
              "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(1, tokenHash(token))
        .bind(2, userId)
        .bind(3, method)
        .bind(4, now)
        .bind(5, now)
        .bind(6, now + cfg_.sessionIdleDays * kDay)
        .bind(7, now + cfg_.sessionMaxDays * kDay)
        .bind(8, now)
        .bind(9, ip)
        .bind(10, userAgent.substr(0, 300))
        .bind(11, deviceHash)
        .run();
    return token;
}

std::optional<SessionInfo> SessionManager::validate(const std::string& token, std::int64_t now) {
    if (token.size() < 32 || token.size() > 128)
        return std::nullopt;
    const Bytes hash = tokenHash(token);
    auto guard = db_.lock();
    Statement q(
        db_, "SELECT s.user_id, u.email, s.auth_method, s.created_at, s.last_seen_at, s.reauth_at, "
             "s.idle_expires_at, s.absolute_expires_at, s.ip, s.user_agent "
             "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?");
    q.bind(1, hash);
    if (!q.step())
        return std::nullopt;
    SessionInfo s{q.int64(0), q.text(1),  q.text(2),
                  q.int64(3), q.int64(4), q.int64(5),
                  q.text(8),  q.text(9),  toHex(hash).substr(0, 8)};
    const std::int64_t idleExp = q.int64(6), absExp = q.int64(7);
    if (now >= idleExp || now >= absExp) {
        Statement(db_, "DELETE FROM sessions WHERE token_hash = ?").bind(1, hash).run();
        return std::nullopt;
    }
    if (now - s.lastSeenAt >= kTouchInterval) {
        Statement(db_,
                  "UPDATE sessions SET last_seen_at = ?, idle_expires_at = ? WHERE token_hash = ?")
            .bind(1, now)
            .bind(2, std::min(now + cfg_.sessionIdleDays * kDay, absExp))
            .bind(3, hash)
            .run();
        s.lastSeenAt = now;
    }
    return s;
}

void SessionManager::markReauth(const std::string& token, std::int64_t now) {
    auto guard = db_.lock();
    Statement(db_, "UPDATE sessions SET reauth_at = ? WHERE token_hash = ?")
        .bind(1, now)
        .bind(2, tokenHash(token))
        .run();
}

bool SessionManager::reauthFresh(const SessionInfo& s, std::int64_t now) const {
    return now - s.reauthAt <= static_cast<std::int64_t>(cfg_.reauthMinutes) * 60;
}

void SessionManager::revoke(const std::string& token) {
    auto guard = db_.lock();
    Statement(db_, "DELETE FROM sessions WHERE token_hash = ?").bind(1, tokenHash(token)).run();
}

void SessionManager::revokeByHint(std::int64_t userId, const std::string& idHint) {
    if (idHint.size() != 8)
        return;
    auto guard = db_.lock();
    // 힌트는 해시 앞 8자(hex). 해당 사용자의 세션 중 일치하는 것만 삭제.
    Statement(db_,
              "DELETE FROM sessions WHERE user_id = ? AND lower(hex(substr(token_hash, 1, 4))) = ?")
        .bind(1, userId)
        .bind(2, idHint)
        .run();
}

int SessionManager::revokeAllForUser(std::int64_t userId) {
    auto guard = db_.lock();
    Statement(db_, "DELETE FROM sessions WHERE user_id = ?").bind(1, userId).run();
    return db_.changes();
}

std::vector<SessionInfo> SessionManager::listForUser(std::int64_t userId, std::int64_t now) {
    auto guard = db_.lock();
    Statement q(
        db_,
        "SELECT s.token_hash, u.email, s.auth_method, s.created_at, s.last_seen_at, s.reauth_at, "
        "s.ip, s.user_agent FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.user_id = ? AND s.idle_expires_at > ? AND s.absolute_expires_at > ? "
        "ORDER BY s.last_seen_at DESC");
    q.bind(1, userId).bind(2, now).bind(3, now);
    std::vector<SessionInfo> out;
    while (q.step()) {
        out.push_back(SessionInfo{userId, q.text(1), q.text(2), q.int64(3), q.int64(4), q.int64(5),
                                  q.text(6), q.text(7), toHex(q.blob(0)).substr(0, 8)});
    }
    return out;
}

void SessionManager::purgeExpired(std::int64_t now) {
    auto guard = db_.lock();
    Statement(db_, "DELETE FROM sessions WHERE idle_expires_at <= ? OR absolute_expires_at <= ?")
        .bind(1, now)
        .bind(2, now)
        .run();
}

std::string SessionManager::cookieHeader(const std::string& token) const {
    const bool secure = cfg_.publicUrl.rfind("https://", 0) == 0;
    std::string c =
        std::string(kSessionCookie) + "=" + token +
        "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + std::to_string(cfg_.sessionMaxDays * kDay);
    if (cfg_.cookieDomain != "localhost")
        c += "; Domain=" + cfg_.cookieDomain;
    if (secure)
        c += "; Secure";
    return c;
}

std::string SessionManager::clearCookieHeader() const {
    std::string c = std::string(kSessionCookie) + "=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
    if (cfg_.cookieDomain != "localhost")
        c += "; Domain=" + cfg_.cookieDomain;
    if (cfg_.publicUrl.rfind("https://", 0) == 0)
        c += "; Secure";
    return c;
}

std::optional<std::string> cookieValue(const std::string& header, const std::string& name) {
    std::size_t pos = 0;
    while (pos < header.size()) {
        while (pos < header.size() && (header[pos] == ' ' || header[pos] == ';'))
            ++pos;
        auto eq = header.find('=', pos);
        if (eq == std::string::npos)
            break;
        auto end = header.find(';', eq);
        if (end == std::string::npos)
            end = header.size();
        if (header.compare(pos, eq - pos, name) == 0)
            return header.substr(eq + 1, end - eq - 1);
        pos = end + 1;
    }
    return std::nullopt;
}

} // namespace douve
