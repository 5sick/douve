#include "store/passkeys.h"

namespace douve {
namespace {
constexpr const char* kCols = "id, user_id, credential_id, public_key_cose, sign_count, name, "
                              "transports, created_at, last_used_at";

Passkey row(Statement& q) {
    Passkey p;
    p.id = q.int64(0);
    p.userId = q.int64(1);
    p.credentialId = q.blob(2);
    p.publicKeyCose = q.blob(3);
    p.signCount = static_cast<std::uint32_t>(q.int64(4));
    p.name = q.text(5);
    p.transports = q.text(6);
    p.createdAt = q.int64(7);
    if (!q.isNull(8))
        p.lastUsedAt = q.int64(8);
    return p;
}
} // namespace

std::optional<std::int64_t> insertPasskey(Database& db, const Passkey& p) {
    Transaction tx(db);
    Statement exists(db, "SELECT 1 FROM passkeys WHERE credential_id = ?");
    exists.bind(1, p.credentialId);
    if (exists.step())
        return std::nullopt;
    Statement(db, "INSERT INTO passkeys (user_id, credential_id, public_key_cose, sign_count, "
                  "name, transports, "
                  "created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(1, p.userId)
        .bind(2, p.credentialId)
        .bind(3, p.publicKeyCose)
        .bind(4, static_cast<std::int64_t>(p.signCount))
        .bind(5, p.name)
        .bind(6, p.transports)
        .bind(7, p.createdAt)
        .run();
    auto id = db.lastInsertId();
    tx.commit();
    return id;
}

std::optional<Passkey> findPasskeyByCredentialId(Database& db, const Bytes& credentialId) {
    auto guard = db.lock();
    Statement q(db, std::string("SELECT ") + kCols + " FROM passkeys WHERE credential_id = ?");
    q.bind(1, credentialId);
    if (!q.step())
        return std::nullopt;
    return row(q);
}

std::vector<Passkey> listPasskeys(Database& db, std::int64_t userId) {
    auto guard = db.lock();
    Statement q(db, std::string("SELECT ") + kCols +
                        " FROM passkeys WHERE user_id = ? ORDER BY created_at");
    q.bind(1, userId);
    std::vector<Passkey> out;
    while (q.step())
        out.push_back(row(q));
    return out;
}

void updatePasskeyUse(Database& db, std::int64_t id, std::uint32_t signCount, std::int64_t now) {
    auto guard = db.lock();
    Statement(db, "UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?")
        .bind(1, static_cast<std::int64_t>(signCount))
        .bind(2, now)
        .bind(3, id)
        .run();
}

bool deletePasskey(Database& db, std::int64_t userId, std::int64_t id) {
    auto guard = db.lock();
    Statement(db, "DELETE FROM passkeys WHERE id = ? AND user_id = ?")
        .bind(1, id)
        .bind(2, userId)
        .run();
    return db.changes() > 0;
}

bool renamePasskey(Database& db, std::int64_t userId, std::int64_t id, const std::string& name) {
    auto guard = db.lock();
    Statement(db, "UPDATE passkeys SET name = ? WHERE id = ? AND user_id = ?")
        .bind(1, name)
        .bind(2, id)
        .bind(3, userId)
        .run();
    return db.changes() > 0;
}

} // namespace douve
