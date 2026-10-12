#include "store/repo.h"

#include "util/crypto.h"

namespace douve {

User findOrCreateUser(Database& db, const std::string& email, std::int64_t now) {
    auto guard = db.lock();
    if (auto u = findUserByEmail(db, email))
        return *u;
    Statement(db, "INSERT INTO users (email, created_at) VALUES (?, ?)")
        .bind(1, email)
        .bind(2, now)
        .run();
    return User{db.lastInsertId(), email, now};
}

std::optional<User> findUserById(Database& db, std::int64_t id) {
    auto guard = db.lock();
    Statement q(db, "SELECT id, email, created_at FROM users WHERE id = ?");
    q.bind(1, id);
    if (!q.step())
        return std::nullopt;
    return User{q.int64(0), q.text(1), q.int64(2)};
}

std::optional<User> findUserByEmail(Database& db, const std::string& email) {
    auto guard = db.lock();
    Statement q(db, "SELECT id, email, created_at FROM users WHERE email = ?");
    q.bind(1, email);
    if (!q.step())
        return std::nullopt;
    return User{q.int64(0), q.text(1), q.int64(2)};
}

void touchUserLogin(Database& db, std::int64_t userId, std::int64_t now) {
    auto guard = db.lock();
    Statement(db, "UPDATE users SET last_login_at = ? WHERE id = ?")
        .bind(1, now)
        .bind(2, userId)
        .run();
}

std::int64_t countPasskeys(Database& db, std::int64_t userId) {
    auto guard = db.lock();
    Statement q(db, "SELECT count(*) FROM passkeys WHERE user_id = ?");
    q.bind(1, userId);
    return q.step() ? q.int64(0) : 0;
}

std::string putPending(Database& db, const std::string& kind, const std::string& payload,
                       int ttlSeconds, std::int64_t now) {
    auto guard = db.lock();
    std::string id = randomToken(24);
    Statement(db, "INSERT INTO pending (id, kind, payload, expires_at) VALUES (?, ?, ?, ?)")
        .bind(1, id)
        .bind(2, kind)
        .bind(3, payload)
        .bind(4, now + ttlSeconds)
        .run();
    return id;
}

std::optional<std::string> takePending(Database& db, const std::string& id, const std::string& kind,
                                       std::int64_t now) {
    Transaction tx(db);
    Statement q(db, "SELECT payload, expires_at FROM pending WHERE id = ? AND kind = ?");
    q.bind(1, id).bind(2, kind);
    if (!q.step())
        return std::nullopt;
    std::string payload = q.text(0);
    std::int64_t expires = q.int64(1);
    Statement(db, "DELETE FROM pending WHERE id = ?").bind(1, id).run();
    tx.commit();
    if (expires < now)
        return std::nullopt;
    return payload;
}

void purgeExpiredPending(Database& db, std::int64_t now) {
    auto guard = db.lock();
    Statement(db, "DELETE FROM pending WHERE expires_at < ?").bind(1, now).run();
}

void audit(Database& db, std::optional<std::int64_t> userId, const std::string& event,
           const std::string& ip, const std::string& detail, std::int64_t now) {
    auto guard = db.lock();
    Statement(db, "INSERT INTO audit_log (ts, user_id, event, ip, detail) VALUES (?, ?, ?, ?, ?)")
        .bind(1, now)
        .bind(2, userId)
        .bind(3, event)
        .bind(4, ip)
        .bind(5, detail)
        .run();
}

} // namespace douve
