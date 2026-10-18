#pragma once
// 알림 규칙 평가와 상태 비교. 순수 로직 (DB·네트워크 없음).
//   evaluateNode: 노드 하나의 현재 상태 → 지금 성립하는 조건(rule → 메시지)
//   reconcile:    열린 알림 vs 지금 조건 → 새로 열 것 / 해소할 것
// 상태가 바뀔 때만 알림이 나가므로 같은 문제로 반복 알림이 오지 않는다.

#include "cluster/live.h"
#include "store/nodes.h"

#include <json/json.h>

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace douve {

struct AlertThresholds {
    int offlineSeconds = 120;
    double diskPercent = 90;
    double memPercent = 95;
    // 타이머 유닛(dnf-makecache 등)은 한 번 실패해도 다음 실행에서 풀리는 일이 많다.
    // 이 시간 넘게 계속 실패 상태일 때만(대개 2회 연속 실패) 알린다.
    int timerUnitGraceSeconds = 7200;
};

// 유닛이 언제부터 계속 실패 상태인지 (노드 하나 분량, rule 이름이 아닌 유닛 이름이 키)
struct UnitSeen {
    std::int64_t since = 0;    // 연속 실패가 시작된 시각
    std::int64_t lastSeen = 0; // 마지막으로 실패 목록에서 본 시각
};
using UnitTracker = std::map<std::string, UnitSeen>;

// 인벤토리의 failed_units로 tracker를 갱신한다. 타이머가 다시 돌면서 잠깐 activating이 되어
// 목록에서 빠지는 것은 연속 실패로 본다 (forgetSeconds 동안 안 보여야 풀린 것으로 본다).
void trackFailedUnits(UnitTracker& t, const Json::Value& inventory, std::int64_t now,
                      std::int64_t forgetSeconds = 300);

struct NodeView {
    std::int64_t id = 0;
    std::string name;
    bool connected = false;
    std::optional<std::int64_t> lastSeenAt; // 마지막으로 살아 있던 시각
    std::optional<Sample> latest;
    std::optional<Json::Value> inventory;
    UnitTracker units; // 비어 있으면 타이머 유닛도 바로 알린다
};

struct Conditions {
    std::map<std::string, std::string> rules; // rule → 메시지
    // 응답 없는 노드는 메트릭·인벤토리 조건을 판단할 수 없으므로 기존 알림을 유지한다.
    bool stale = false;
};

Conditions evaluateNode(const NodeView& n, std::int64_t now, const AlertThresholds& th = {});

struct AlertOpen {
    std::int64_t nodeId;
    std::string rule, message;
};
struct AlertActions {
    std::vector<AlertOpen> open;
    std::vector<OpenAlert> resolve;
};

AlertActions reconcile(const std::vector<OpenAlert>& current,
                       const std::map<std::int64_t, Conditions>& desired);

// 텔레그램 메시지 문구
std::string alertOpenText(const std::string& nodeName, const std::string& message);
std::string alertResolvedText(const std::string& nodeName, const OpenAlert& a, std::int64_t now);

} // namespace douve
