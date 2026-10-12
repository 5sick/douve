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

void audit(Database& db, std::optional<std::int64_t> userId, const std::string& event,
           const std::string& ip, const std::string& detail, std::int64_t now);

} // namespace douve
