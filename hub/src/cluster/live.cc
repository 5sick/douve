#include "cluster/live.h"

#include <algorithm>
#include <cmath>

namespace douve {
namespace {

bool num(const Json::Value& v) {
    return v.isNumeric() && std::isfinite(v.asDouble());
}

std::int64_t i64(const Json::Value& v) {
    return num(v) ? std::max<std::int64_t>(0, v.asInt64()) : 0;
}

} // namespace

std::optional<Sample> parseSample(const Json::Value& m, std::int64_t now) {
    if (!m.isObject() || !num(m["cpu"]) || !m["mem"].isObject())
        return std::nullopt;
    Sample s;
    s.ts = now; // Agent 시계는 믿지 않는다
    s.cpu = std::clamp(m["cpu"].asDouble(), 0.0, 100.0);
    s.memUsed = i64(m["mem"]["used"]);
    s.memTotal = i64(m["mem"]["total"]);
    s.swapUsed = i64(m["swap"]["used"]);
    s.swapTotal = i64(m["swap"]["total"]);
    if (m["disks"].isArray()) {
        for (const auto& d : m["disks"]) {
            if (!d.isObject() || !d["mount"].isString())
                continue;
            s.disks.push_back(
                {d["mount"].asString().substr(0, 128), i64(d["used"]), i64(d["total"])});
            if (s.disks.size() >= 16)
                break;
        }
    }
    s.netRx = num(m["net"]["rx"]) ? std::max(0.0, m["net"]["rx"].asDouble()) : 0;
    s.netTx = num(m["net"]["tx"]) ? std::max(0.0, m["net"]["tx"].asDouble()) : 0;
    if (m["load"].isArray() && m["load"].size() == 3) {
        s.load1 = m["load"][0].asDouble();
        s.load5 = m["load"][1].asDouble();
        s.load15 = m["load"][2].asDouble();
    }
    s.uptime = i64(m["uptime"]);
    return s;
}

Json::Value sampleToJson(const Sample& s) {
    Json::Value v;
    v["ts"] = Json::Int64(s.ts);
    v["cpu"] = s.cpu;
    v["mem"]["used"] = Json::Int64(s.memUsed);
    v["mem"]["total"] = Json::Int64(s.memTotal);
    v["swap"]["used"] = Json::Int64(s.swapUsed);
    v["swap"]["total"] = Json::Int64(s.swapTotal);
    v["disks"] = Json::Value(Json::arrayValue);
    for (const auto& d : s.disks) {
        Json::Value dv;
        dv["mount"] = d.mount;
        dv["used"] = Json::Int64(d.used);
        dv["total"] = Json::Int64(d.total);
        v["disks"].append(dv);
    }
    v["net"]["rx"] = s.netRx;
    v["net"]["tx"] = s.netTx;
    v["load"].append(s.load1);
    v["load"].append(s.load5);
    v["load"].append(s.load15);
    v["uptime"] = Json::Int64(s.uptime);
    return v;
}

void LiveState::setConnected(std::int64_t nodeId, bool connected, std::int64_t now) {
    std::lock_guard lk(mu_);
    auto& e = nodes_[nodeId];
    if (e.connected != connected)
        e.changedAt = now;
    e.connected = connected;
}

bool LiveState::connected(std::int64_t nodeId) const {
    std::lock_guard lk(mu_);
    auto it = nodes_.find(nodeId);
    return it != nodes_.end() && it->second.connected;
}

void LiveState::addSample(std::int64_t nodeId, const Sample& s) {
    std::lock_guard lk(mu_);
    auto& e = nodes_[nodeId];
    e.recent.push_back(s);
    while (e.recent.size() > kRecent)
        e.recent.pop_front();
    if (e.pending.size() < 64) // 비정상적으로 많이 보내도 메모리 제한
        e.pending.push_back(s);
}

void LiveState::setInventory(std::int64_t nodeId, Json::Value inv) {
    std::lock_guard lk(mu_);
    nodes_[nodeId].inventory = std::move(inv);
}

void LiveState::forget(std::int64_t nodeId) {
    std::lock_guard lk(mu_);
    nodes_.erase(nodeId);
}

std::optional<Sample> LiveState::latest(std::int64_t nodeId) const {
    std::lock_guard lk(mu_);
    auto it = nodes_.find(nodeId);
    if (it == nodes_.end() || it->second.recent.empty())
        return std::nullopt;
    return it->second.recent.back();
}

std::vector<Sample> LiveState::recent(std::int64_t nodeId) const {
    std::lock_guard lk(mu_);
    auto it = nodes_.find(nodeId);
    if (it == nodes_.end())
        return {};
    return {it->second.recent.begin(), it->second.recent.end()};
}

std::optional<Json::Value> LiveState::inventory(std::int64_t nodeId) const {
    std::lock_guard lk(mu_);
    auto it = nodes_.find(nodeId);
    if (it == nodes_.end())
        return std::nullopt;
    return it->second.inventory;
}

std::optional<std::int64_t> LiveState::changedAt(std::int64_t nodeId) const {
    std::lock_guard lk(mu_);
    auto it = nodes_.find(nodeId);
    if (it == nodes_.end() || it->second.changedAt == 0)
        return std::nullopt;
    return it->second.changedAt;
}

std::vector<std::pair<std::int64_t, MetricRow>> LiveState::drainMinute(std::int64_t minuteTs) {
    std::lock_guard lk(mu_);
    std::vector<std::pair<std::int64_t, MetricRow>> out;
    for (auto& [id, e] : nodes_) {
        if (e.pending.empty())
            continue;
        const double n = static_cast<double>(e.pending.size());
        MetricRow r;
        r.ts = minuteTs;
        double memUsed = 0, swapUsed = 0, diskUsed = 0;
        for (const auto& s : e.pending) {
            r.cpu += s.cpu / n;
            memUsed += static_cast<double>(s.memUsed) / n;
            swapUsed += static_cast<double>(s.swapUsed) / n;
            if (!s.disks.empty())
                diskUsed += static_cast<double>(s.disks.front().used) / n;
            r.netRx += s.netRx / n;
            r.netTx += s.netTx / n;
            r.load1 += s.load1 / n;
        }
        const auto& last = e.pending.back();
        r.memUsed = static_cast<std::int64_t>(memUsed);
        r.swapUsed = static_cast<std::int64_t>(swapUsed);
        r.diskUsed = static_cast<std::int64_t>(diskUsed);
        r.memTotal = last.memTotal;
        r.swapTotal = last.swapTotal;
        r.diskTotal = last.disks.empty() ? 0 : last.disks.front().total;
        out.emplace_back(id, r);
        e.pending.clear();
    }
    return out;
}

} // namespace douve
