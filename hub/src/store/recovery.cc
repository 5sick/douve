#include "store/recovery.h"

#include "util/crypto.h"

namespace douve {

namespace {
// 0/o, 1/l/i 처럼 헷갈리는 글자를 뺀 31자
constexpr std::string_view kAlphabet = "abcdefghjkmnpqrstuvwxyz23456789";
constexpr std::size_t kCodeLen = 12;
} // namespace

std::string normalizeRecoveryCode(const std::string& code) {
    std::string out;
    for (unsigned char c : code) {
        const char l = static_cast<char>(std::tolower(c));
        if (kAlphabet.find(l) != std::string_view::npos)
            out += l;
    }
    return out;
}

std::vector<std::string> generateRecoveryCodes(Database& db, std::int64_t userId,
                                               std::int64_t now) {
    std::vector<std::string> codes;
    while (codes.size() < static_cast<std::size_t>(kRecoveryCodeCount)) {
        std::string c;
        // 거절 샘플링: 248 = 31*8 미만만 써서 치우침 없이
        while (c.size() < kCodeLen) {
            for (auto b : randomBytes(16)) {
                if (b < 248 && c.size() < kCodeLen)
                    c += kAlphabet[b % kAlphabet.size()];
            }
        }
        codes.push_back(c.substr(0, 4) + "-" + c.substr(4, 4) + "-" + c.substr(8, 4));
    }
    auto guard = db.lock();
    db.exec("BEGIN");
    try {
        Statement(db, "DELETE FROM recovery_codes WHERE user_id = ?").bind(1, userId).run();
        for (const auto& c : codes) {
            Statement(db, "INSERT INTO recovery_codes (user_id, code_hash, created_at) "
                          "VALUES (?, ?, ?)")
                .bind(1, userId)
                .bind(2, sha256(normalizeRecoveryCode(c)))
                .bind(3, now)
                .run();
        }
        db.exec("COMMIT");
    } catch (...) {
        db.exec("ROLLBACK");
        throw;
    }
    return codes;
}

std::optional<std::int64_t> useRecoveryCode(Database& db, const std::string& code,
                                            std::int64_t now) {
    const std::string n = normalizeRecoveryCode(code);
    if (n.size() != kCodeLen)
        return std::nullopt;
    const Bytes h = sha256(n);
    auto guard = db.lock();
    Statement q(db,
                "SELECT id, user_id FROM recovery_codes WHERE code_hash = ? AND used_at IS NULL");
    q.bind(1, h);
    if (!q.step())
        return std::nullopt;
    const auto id = q.int64(0), userId = q.int64(1);
    Statement(db, "UPDATE recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL")
        .bind(1, now)
        .bind(2, id)
        .run();
    if (db.changes() != 1)
        return std::nullopt;
    return userId;
}

RecoveryStatus recoveryStatus(Database& db, std::int64_t userId) {
    Statement q(db, "SELECT count(*) FILTER (WHERE used_at IS NULL), coalesce(max(created_at), 0) "
                    "FROM recovery_codes WHERE user_id = ?");
    q.bind(1, userId);
    RecoveryStatus s;
    if (q.step()) {
        s.remaining = static_cast<int>(q.int64(0));
        s.createdAt = q.int64(1);
    }
    return s;
}

} // namespace douve
