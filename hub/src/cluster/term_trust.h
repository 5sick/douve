#pragma once
// 터미널 신뢰 목록: Agent가 터미널 열기 요청의 패스키 서명을 직접 확인하는 데 쓰는 키 목록.
// Hub가 장악돼도 사용자의 패스키 없이는 터미널을 열 수 없게 한다.
//
//   - 터미널을 열 때마다 사용자는 termOpenStatement(서버, 계정, 시각, 1회용 값)에 서명한다.
//   - Agent는 처음(과 관리자 패스키가 아직 없는 동안) 받은 목록만 그대로 믿고, 그다음 변경은
//     그 목록에 있는 관리자 패스키 서명이 있어야 받는다 (버전은 늘기만 한다).
// 형식과 문장은 agent/internal/termauth와 같아야 한다.

#include "store/db.h"

#include <json/json.h>

#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace douve {

std::string termOpenStatement(std::int64_t nodeId, const std::string& user, std::int64_t ts,
                              const std::string& nonce);
Bytes termOpenChallenge(std::int64_t nodeId, const std::string& user, std::int64_t ts,
                        const std::string& nonce);
Bytes termTrustChallenge(const std::string& snapshot);
// 서버를 바꾸는 작업(action, 예: "fix:ssh_password")에 서명하는 문장 — 터미널과 같은 권한으로
// Agent가 확인
std::string serverActionStatement(std::int64_t nodeId, const std::string& action, std::int64_t ts,
                                  const std::string& nonce);

struct TrustRecord {
    std::int64_t version = 0;
    std::string snapshot;
    std::string sig; // 서명 JSON {id, client_data, auth_data, sig}. 빈 문자열: 서명 없는 첫 판
    std::optional<std::int64_t> signerId;
    std::int64_t createdAt = 0;
};

// 지금 사용자·패스키로 신뢰 목록을 만든다 (관리자: 모든 서버, 운영자: 허락된 서버, 앱 사용자는
// 빠짐). alwaysAdmin: hub.json allowed_emails (항상 관리자). Agent가 받지 않는 키(1024비트 RSA
// 등)는 뺀다.
std::string buildTrustSnapshot(Database& db, const std::string& origin, const std::string& rpId,
                               const std::vector<std::string>& alwaysAdmin, std::int64_t version);

std::optional<TrustRecord> latestTrust(Database& db);
// 오래된 판부터, 최근 limit개
std::vector<TrustRecord> trustRecords(Database& db, std::size_t limit = 50);
// 같은 버전이 이미 있으면 false
bool insertTrust(Database& db, const TrustRecord& r);

// 신뢰 목록의 키 id(base64url). nodeId가 있으면 그 서버 터미널을 열 수 있는 키만, adminOnly면
// 관리자 키만.
std::set<std::string> trustKeyIds(const std::string& snapshot, bool adminOnly,
                                  std::optional<std::int64_t> nodeId = std::nullopt);
// 버전을 뺀 내용이 같은지
bool sameTrustContent(const std::string& a, const std::string& b);
// Agent에 보낼 메시지 {"type":"term_trust","records":[...]}
Json::Value trustMessage(const std::vector<TrustRecord>& records);

} // namespace douve
