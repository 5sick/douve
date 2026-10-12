#pragma once
// 보안 감시: Agent가 보낸 사건을 분류(심각도·지문)하고 지문별 이슈 상태를 관리한다.
//   - Douve 웹 터미널에서 일어난 일(via)은 알리지 않는다 (내가 한 일)
//   - 이슈: open(알림) → 사람이 "확인함"(acked: 다시 생기면 알림) 또는 "문제 없음"(ignored: 앞으로
//   조용)
//   - 열려 있는 같은 이슈는 6시간에 한 번만 다시 알린다

#include "store/db.h"

#include <json/json.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace douve {

struct SecurityEvent {
    std::string kind, summary, viaSid;
    std::int64_t ts = 0;
    Json::Value fields;
};

struct Classified {
    std::string severity;    // info | warn | crit
    std::string fingerprint; // 같은 종류의 사건을 묶는 키
};

// adminUsers: 그 노드의 관리 계정(터미널 허용 계정). 이들의 sudo는 일상 작업으로 본다.
Classified classifySecurity(std::int64_t nodeId, const SecurityEvent& e,
                            const std::vector<std::string>& adminUsers);

struct SecurityContext {
    std::int64_t nodeId = 0;
    std::string nodeName;
    std::vector<std::string> adminUsers;
    // Douve 터미널 세션 ID → 사용자 이메일 (없으면 빈 문자열)
    std::function<std::string(const std::string& sid)> terminalUser;
    // 그 시각 전후로 이 노드에서 Douve 터미널을 쓰던 사용자 (없으면 빈 문자열)
    std::function<std::string(std::int64_t ts)> terminalActiveAt;
};

// 사건을 기록하고 이슈를 갱신한다. 알림으로 보낼 문장 목록을 돌려준다.
std::vector<std::string> ingestSecurity(Database& db, const SecurityContext& ctx,
                                        const std::vector<SecurityEvent>& events, std::int64_t now);

// "확인함"(mode=ack) 또는 "문제 없음"(mode=ignore). 바뀐 개수.
int resolveSecurityIssues(Database& db, const std::vector<std::string>& fingerprints,
                          const std::string& mode, std::int64_t userId, std::int64_t now);
// 무시를 그만두고 다시 감시 (status=acked: 다음에 생기면 알림)
bool reopenSecurityIssue(Database& db, const std::string& fingerprint);
void purgeSecurityEvents(Database& db, std::int64_t before);

std::vector<SecurityEvent> parseSecurityEvents(const Json::Value& msg);

} // namespace douve
