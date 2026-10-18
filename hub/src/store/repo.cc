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

Bytes auditHash(const Bytes& prev, const AuditRow& r) {
    // 길이를 앞에 붙여 필드 경계를 모호하지 않게 한다
    std::string m = "douve-audit-v1";
    auto field = [&m](const std::string& v) { m += std::to_string(v.size()) + ":" + v; };
    field(std::string(prev.begin(), prev.end()));
    field(std::to_string(r.id));
    field(std::to_string(r.ts));
    field(r.userId ? std::to_string(*r.userId) : "");
    field(r.event);
    field(r.ip);
    field(r.detail);
    return sha256(m);
}

namespace {

AuditRow auditRow(Statement& s) {
    AuditRow r;
    r.id = s.int64(0);
    r.ts = s.int64(1);
    if (!s.isNull(2))
        r.userId = s.int64(2);
    r.event = s.text(3);
    r.ip = s.text(4);
    r.detail = s.text(5);
    if (!s.isNull(6))
        r.hash = s.blob(6);
    return r;
}

// 해시가 없는 행(체인 도입 전·이전 버전이 쓴 행)에 차례로 해시를 채운다. 호출자가 쓰기 잠금을 잡고
// 있어야 한다.
void backfill(Database& db) {
    Statement q(db, "SELECT id, ts, user_id, event, ip, detail, hash FROM audit_log ORDER BY id");
    Bytes prev(32, 0);
    std::vector<std::pair<std::int64_t, Bytes>> updates;
    while (q.step()) {
        auto r = auditRow(q);
        if (r.hash.empty()) {
            r.hash = auditHash(prev, r);
            updates.emplace_back(r.id, r.hash);
        }
        prev = r.hash;
    }
    for (const auto& [id, h] : updates)
        Statement(db, "UPDATE audit_log SET hash = ? WHERE id = ?").bind(1, h).bind(2, id).run();
}

} // namespace

void sealAuditLog(Database& db) {
    auto guard = db.lock();
    db.exec("BEGIN IMMEDIATE");
    try {
        backfill(db);
        db.exec("COMMIT");
    } catch (...) {
        db.exec("ROLLBACK");
        throw;
    }
}

AuditCheck verifyAuditChain(Database& db) {
    AuditCheck c;
    Bytes prev(32, 0);
    Statement q(db, "SELECT id, ts, user_id, event, ip, detail, hash FROM audit_log ORDER BY id");
    while (q.step()) {
        auto r = auditRow(q);
        ++c.rows;
        if (r.hash.empty() || auditHash(prev, r) != r.hash) {
            c.ok = false;
            c.brokenAt = r.id;
            break;
        }
        prev = r.hash;
    }
    c.head = prev;
    return c;
}

std::vector<AuditRow> auditRowsAfter(Database& db, std::int64_t afterId, int limit) {
    std::vector<AuditRow> out;
    Statement q(db, "SELECT id, ts, user_id, event, ip, detail, hash FROM audit_log WHERE id > ? "
                    "ORDER BY id LIMIT ?");
    q.bind(1, afterId).bind(2, limit);
    while (q.step())
        out.push_back(auditRow(q));
    return out;
}

Bytes auditHashAt(Database& db, std::int64_t afterId) {
    Statement q(db, "SELECT hash FROM audit_log WHERE id <= ? ORDER BY id DESC LIMIT 1");
    q.bind(1, afterId);
    if (q.step() && !q.isNull(0))
        return q.blob(0);
    return Bytes(32, 0);
}

void audit(Database& db, std::optional<std::int64_t> userId, const std::string& event,
           const std::string& ip, const std::string& detail, std::int64_t now) {
    auto guard = db.lock();
    // 다른 프로세스(root CLI)와 동시에 써도 체인이 갈라지지 않게 쓰기 잠금 안에서 이전 해시를
    // 읽는다
    const bool own = !db.inTransaction();
    if (own)
        db.exec("BEGIN IMMEDIATE");
    try {
        AuditRow r;
        r.ts = now;
        r.userId = userId;
        r.event = event;
        r.ip = ip;
        r.detail = detail;
        Bytes prev(32, 0);
        {
            Statement last(db, "SELECT hash IS NULL, hash FROM audit_log ORDER BY id DESC LIMIT 1");
            if (last.step()) {
                if (last.int64(0) != 0) {
                    backfill(db);
                    Statement again(db, "SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1");
                    again.step();
                    prev = again.blob(0);
                } else {
                    prev = last.blob(1);
                }
            }
        }
        Statement(db,
                  "INSERT INTO audit_log (ts, user_id, event, ip, detail) VALUES (?, ?, ?, ?, ?)")
            .bind(1, now)
            .bind(2, userId)
            .bind(3, event)
            .bind(4, ip)
            .bind(5, detail)
            .run();
        r.id = db.lastInsertId();
        Statement(db, "UPDATE audit_log SET hash = ? WHERE id = ?")
            .bind(1, auditHash(prev, r))
            .bind(2, r.id)
            .run();
        if (own)
            db.exec("COMMIT");
    } catch (...) {
        if (own)
            db.exec("ROLLBACK");
        throw;
    }
}

} // namespace douve
