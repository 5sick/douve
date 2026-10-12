#pragma once

#include "store/db.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace douve {

struct Passkey {
    std::int64_t id = 0;
    std::int64_t userId = 0;
    Bytes credentialId;
    Bytes publicKeyCose;
    std::uint32_t signCount = 0;
    std::string name;
    std::string transports; // 쉼표 구분 (usb,nfc,ble,internal,hybrid)
    std::int64_t createdAt = 0;
    std::optional<std::int64_t> lastUsedAt;
};

// 같은 credentialId가 이미 있으면 nullopt (다른 사용자 계정에 붙이는 공격 방지).
std::optional<std::int64_t> insertPasskey(Database& db, const Passkey& p);
std::optional<Passkey> findPasskeyByCredentialId(Database& db, const Bytes& credentialId);
std::vector<Passkey> listPasskeys(Database& db, std::int64_t userId);
void updatePasskeyUse(Database& db, std::int64_t id, std::uint32_t signCount, std::int64_t now);
bool deletePasskey(Database& db, std::int64_t userId, std::int64_t id);
bool renamePasskey(Database& db, std::int64_t userId, std::int64_t id, const std::string& name);

} // namespace douve
