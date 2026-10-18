#pragma once
// 단순 테이블 접근 함수들 (users, pending, audit_log). 시간은 모두 유닉스 초이며 호출자가
// 넘긴다(테스트 용이).

#include "store/db.h"

#include <cstdint>
#include <optional>
#include <string>

namespace douve {

struct User {
    std::int64_t id = 0;
    std::string email;
    std::int64_t createdAt = 0;
};

// 이메일(소문자)로 사용자를 찾거나 새로 만든다.
User findOrCreateUser(Database& db, const std::string& email, std::int64_t now);
std::optional<User> findUserById(Database& db, std::int64_t id);
std::optional<User> findUserByEmail(Database& db, const std::string& email);
void touchUserLogin(Database& db, std::int64_t userId, std::int64_t now);
std::int64_t countPasskeys(Database& db, std::int64_t userId);

// 1회용 임시 값 (OIDC state, WebAuthn challenge). take는 꺼내면서 삭제하므로 재사용 불가.
std::string putPending(Database& db, const std::string& kind, const std::string& payload,
                       int ttlSeconds, std::int64_t now);
std::optional<std::string> takePending(Database& db, const std::string& id, const std::string& kind,
                                       std::int64_t now);
void purgeExpiredPending(Database& db, std::int64_t now);

// 감사 기록 해시 체인
struct AuditRow {
    std::int64_t id = 0, ts = 0;
    std::optional<std::int64_t> userId;
    std::string event, ip, detail;
    Bytes hash;
};
// 이 행의 체인 해시 (prev: 이전 행 hash, 첫 행은 32바이트 0)
Bytes auditHash(const Bytes& prev, const AuditRow& r);
struct AuditCheck {
    bool ok = true;
    std::int64_t rows = 0;
    std::int64_t brokenAt = 0; // 처음 맞지 않는 행 id
    Bytes head;                // 마지막 행 hash
};
// 해시가 없는 행(체인 도입 전 기록)에 해시를 채운다. Hub 시작 때 한 번.
void sealAuditLog(Database& db);
// 처음부터 체인을 다시 계산해 확인한다.
AuditCheck verifyAuditChain(Database& db);
// id > afterId 인 행들 (내보내기용, 최대 limit개)
std::vector<AuditRow> auditRowsAfter(Database& db, std::int64_t afterId, int limit);
// id <= afterId 인 마지막 행의 hash (없으면 32바이트 0) — 내보내는 묶음의 시작점
Bytes auditHashAt(Database& db, std::int64_t afterId);

void audit(Database& db, std::optional<std::int64_t> userId, const std::string& event,
           const std::string& ip, const std::string& detail, std::int64_t now);

} // namespace douve
