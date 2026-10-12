#pragma once
// 초대: 1회용 링크로 패스키를 등록해 사용자가 된다 (Google 없이 시작, 다른 사람 초대).

#include "store/db.h"

#include <cstdint>
#include <optional>
#include <string>

namespace douve {

struct Invite {
    std::string token; // 평문은 만들 때만
    std::string email;
    std::int64_t expiresAt = 0;
};

Invite createInvite(Database& db, const std::string& email, std::optional<std::int64_t> createdBy,
                    int ttlSeconds, std::int64_t now);
// 유효한(미사용·미만료) 초대의 이메일. 소모하지 않는다.
std::optional<std::string> peekInvite(Database& db, const std::string& token, std::int64_t now);
// 초대를 소모한다. 동시에 두 번 써도 한 번만 성공한다.
bool consumeInvite(Database& db, const std::string& token, std::int64_t now);

void setUserAllowed(Database& db, std::int64_t userId, bool allowed);
bool userAllowed(Database& db, const std::string& email);

// 웹 설정 (key → value)
std::optional<std::string> getSetting(Database& db, const std::string& key);
void putSetting(Database& db, const std::string& key, const std::string& value, std::int64_t now);
void deleteSetting(Database& db, const std::string& key);

} // namespace douve
