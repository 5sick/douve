#pragma once
// 노드(Agent)·join 토큰·메트릭·알림 테이블 접근. 시간은 유닉스 초이며 호출자가 넘긴다.

#include "store/db.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace douve {

struct Node {
    std::int64_t id = 0;
    std::string name;
    Bytes pubkey;
    std::string hostname, os, arch, agentVersion;
    std::int64_t createdAt = 0;
    std::optional<std::int64_t> lastSeenAt;
    std::string lastIp;
    std::string inventory; // JSON
    bool edge = false;
    std::string meshAddress;
    std::string connectMode = "auto"; // auto | direct | tunnel
    bool portForward = false;         // 공유기 포트 자동 열기
};

// 1분 평균 메트릭 한 줄.
struct MetricRow {
    std::int64_t ts = 0;
    double cpu = 0;
    std::int64_t memUsed = 0, memTotal = 0, swapUsed = 0, swapTotal = 0;
    std::int64_t diskUsed = 0, diskTotal = 0;
    double netRx = 0, netTx = 0, load1 = 0;
};

struct JoinToken {
    std::string token; // 평문은 발급 순간에만 존재 (DB에는 해시)
    std::int64_t expiresAt = 0;
};

// 일회용 join 토큰 발급.
JoinToken createJoinToken(Database& db, std::optional<std::int64_t> userId, const std::string& name,
                          int ttlSeconds, std::int64_t now);

struct EnrollRequest {
    std::string token;
    Bytes pubkey;
    std::string hostname, os, arch, agentVersion, ip;
};

// 토큰을 소모하고 노드를 만든다. 실패하면 nullopt + error.
// 이름은 토큰에 정한 이름 → hostname 순, 겹치면 "-2", "-3"… 을 붙인다.
std::optional<Node> enrollNode(Database& db, const EnrollRequest& req, std::int64_t now,
                               std::string& error);

std::vector<Node> listNodes(Database& db);
std::optional<Node> findNode(Database& db, std::int64_t id);
bool deleteNode(Database& db, std::int64_t id);
bool renameNode(Database& db, std::int64_t id, const std::string& name);
void touchNode(Database& db, std::int64_t id, const std::string& ip,
               const std::string& agentVersion, std::int64_t now);
void saveInventory(Database& db, std::int64_t id, const std::string& json);
bool setNodeEdge(Database& db, std::int64_t id, bool edge);
bool setNodeConnectMode(Database& db, std::int64_t id, const std::string& mode);
bool setNodePortForward(Database& db, std::int64_t id, bool on);
void setMeshAddress(Database& db, std::int64_t id, const std::string& address);
// 인벤토리의 인터페이스 주소에서 메시 주소를 고른다: wg* 인터페이스의 IPv4 → 없으면 첫 사설 IPv4.
std::string pickMeshAddress(const std::string& inventoryJson);

void insertMetric(Database& db, std::int64_t nodeId, const MetricRow& m);
std::vector<MetricRow> queryMetrics(Database& db, std::int64_t nodeId, std::int64_t since,
                                    std::int64_t bucketSeconds);
void purgeMetrics(Database& db, std::int64_t before);

// 알림 상태: 열려 있는(해소 안 된) 알림의 rule 목록.
struct OpenAlert {
    std::int64_t id = 0;
    std::optional<std::int64_t> nodeId;
    std::string rule, message;
    std::int64_t startedAt = 0;
};
std::vector<OpenAlert> openAlerts(Database& db);
std::int64_t openAlert(Database& db, std::optional<std::int64_t> nodeId, const std::string& rule,
                       const std::string& message, std::int64_t now);
void resolveAlert(Database& db, std::int64_t id, std::int64_t now);

// 이름 규칙: 영문 소문자·숫자·하이픈, 1~32자.
std::string sanitizeNodeName(const std::string& raw);

} // namespace douve
