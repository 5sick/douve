#pragma once
// 복구 코드: 패스키·기기를 모두 잃었을 때 로그인하는 일회용 코드 (사용자당 10개, 해시만 저장).

#include "store/db.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace douve {

inline constexpr int kRecoveryCodeCount = 10;

// 새 코드 묶음을 만들고(기존 코드는 모두 무효) 원문을 돌려준다. 원문은 이때 한 번만 보인다.
// 형식: xxxx-xxxx-xxxx (헷갈리는 글자 없는 31자 알파벳, 약 59비트)
std::vector<std::string> generateRecoveryCodes(Database& db, std::int64_t userId, std::int64_t now);

// 코드를 쓰고 그 사용자 id를 돌려준다. 없거나 이미 쓴 코드면 nullopt. 공백·하이픈·대소문자 무시.
std::optional<std::int64_t> useRecoveryCode(Database& db, const std::string& code,
                                            std::int64_t now);

struct RecoveryStatus {
    int remaining = 0;
    std::int64_t createdAt = 0; // 0 = 만든 적 없음
};
RecoveryStatus recoveryStatus(Database& db, std::int64_t userId);

// 비교용 정규화 (소문자, 알파벳 밖 글자 제거)
std::string normalizeRecoveryCode(const std::string& code);

} // namespace douve
