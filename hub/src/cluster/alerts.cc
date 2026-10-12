#include "cluster/alerts.h"

#include <cmath>
#include <set>

namespace douve {
namespace {

std::string pct(double v) {
    return std::to_string(static_cast<int>(std::lround(v))) + "%";
}

std::string duration(std::int64_t seconds) {
    if (seconds < 120)
        return std::to_string(seconds) + "초";
    if (seconds < 7200)
        return std::to_string(seconds / 60) + "분";
    if (seconds < 172800)
        return std::to_string(seconds / 3600) + "시간";
    return std::to_string(seconds / 86400) + "일";
}

} // namespace

Conditions evaluateNode(const NodeView& n, std::int64_t now, const AlertThresholds& th) {
    Conditions c;
    if (!n.connected) {
        c.stale = true;
        if (n.lastSeenAt && now - *n.lastSeenAt >= th.offlineSeconds)
            c.rules["offline"] = "응답 없음 (마지막 접속 " + duration(now - *n.lastSeenAt) + " 전)";
        return c;
    }
    if (n.latest) {
        const auto& s = *n.latest;
        for (const auto& d : s.disks) {
            if (d.total <= 0)
                continue;
            const double p = 100.0 * static_cast<double>(d.used) / static_cast<double>(d.total);
            if (p >= th.diskPercent)
                c.rules["disk:" + d.mount] = "디스크 " + d.mount + " 사용률 " + pct(p);
        }
        if (s.memTotal > 0) {
            const double p =
                100.0 * static_cast<double>(s.memUsed) / static_cast<double>(s.memTotal);
            if (p >= th.memPercent)
                c.rules["mem"] = "메모리 사용률 " + pct(p);
        }
    }
    if (n.inventory && n.inventory->isObject()) {
        const auto& inv = *n.inventory;
        for (const auto& u : inv["failed_units"]) {
            if (u.isString())
                c.rules["unit:" + u.asString()] = "systemd 유닛 실패: " + u.asString();
        }
        for (const auto& ct : inv["containers"]) {
            const std::string name = ct.get("name", "").asString();
            if (name.empty())
                continue;
            const std::string state = ct.get("state", "").asString();
            const std::string health = ct.get("health", "").asString();
            const int exitCode = ct.get("exit_code", 0).asInt();
            if (state == "restarting")
                c.rules["container:" + name] = "컨테이너 재시작 반복: " + name;
            else if (health == "unhealthy")
                c.rules["container:" + name] = "컨테이너 비정상(unhealthy): " + name;
            else if (state == "exited" && exitCode != 0)
                c.rules["container:" + name] =
                    "컨테이너 종료: " + name + " (코드 " + std::to_string(exitCode) + ")";
        }
    }
    return c;
}

AlertActions reconcile(const std::vector<OpenAlert>& current,
                       const std::map<std::int64_t, Conditions>& desired) {
    AlertActions out;
    std::set<std::pair<std::int64_t, std::string>> open;
    for (const auto& a : current) {
        if (!a.nodeId)
            continue;
        open.insert({*a.nodeId, a.rule});
        auto it = desired.find(*a.nodeId);
        if (it == desired.end())
            continue; // 평가하지 않은 노드는 건드리지 않음
        const auto& cond = it->second;
        if (cond.rules.count(a.rule))
            continue;
        if (cond.stale && a.rule != "offline")
            continue; // 응답 없는 동안은 판단 보류
        out.resolve.push_back(a);
    }
    for (const auto& [nodeId, cond] : desired) {
        for (const auto& [rule, msg] : cond.rules) {
            if (!open.count({nodeId, rule}))
                out.open.push_back({nodeId, rule, msg});
        }
    }
    return out;
}

std::string alertOpenText(const std::string& nodeName, const std::string& message) {
    return "🔴 [" + nodeName + "] " + message;
}

std::string alertResolvedText(const std::string& nodeName, const OpenAlert& a, std::int64_t now) {
    return "✅ [" + nodeName + "] 해소: " + a.message + " (" + duration(now - a.startedAt) +
           " 지속)";
}

} // namespace douve
