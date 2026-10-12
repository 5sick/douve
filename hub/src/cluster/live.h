#pragma once
// 노드 실시간 상태(메모리). Agent가 10초마다 보내는 샘플을 보관하고 1분 평균을 만든다.
// Drogon과 무관한 순수 로직이라 단위 테스트한다. 모든 메서드는 스레드 안전.

#include "store/nodes.h"

#include <json/json.h>

#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace douve {

struct Disk {
    std::string mount;
    std::int64_t used = 0, total = 0;
};

struct Sample {
    std::int64_t ts = 0;
    double cpu = 0;
    std::int64_t memUsed = 0, memTotal = 0, swapUsed = 0, swapTotal = 0;
    std::vector<Disk> disks; // 첫 번째가 루트(/)
    double netRx = 0, netTx = 0;
    double load1 = 0, load5 = 0, load15 = 0;
    std::int64_t uptime = 0;
};

// Agent metrics 메시지 → Sample. 형식이 틀리면 nullopt.
std::optional<Sample> parseSample(const Json::Value& msg, std::int64_t now);
Json::Value sampleToJson(const Sample& s);

class LiveState {
  public:
    static constexpr std::size_t kRecent = 180; // 10초 × 180 = 30분

    void setConnected(std::int64_t nodeId, bool connected, std::int64_t now);
    bool connected(std::int64_t nodeId) const;
    void addSample(std::int64_t nodeId, const Sample& s);
    void setInventory(std::int64_t nodeId, Json::Value inv);
    void forget(std::int64_t nodeId);

    std::optional<Sample> latest(std::int64_t nodeId) const;
    std::vector<Sample> recent(std::int64_t nodeId) const;
    std::optional<Json::Value> inventory(std::int64_t nodeId) const;
    // 마지막으로 접속이 바뀐 시각 (연결/끊김)
    std::optional<std::int64_t> changedAt(std::int64_t nodeId) const;

    // 지난 flush 이후 샘플을 노드별 평균으로 만들어 돌려주고 비운다. ts는 minuteTs.
    std::vector<std::pair<std::int64_t, MetricRow>> drainMinute(std::int64_t minuteTs);

  private:
    struct Entry {
        bool connected = false;
        std::int64_t changedAt = 0;
        std::deque<Sample> recent;
        std::vector<Sample> pending; // 1분 평균용
        std::optional<Json::Value> inventory;
    };
    mutable std::mutex mu_;
    std::map<std::int64_t, Entry> nodes_;
};

} // namespace douve
