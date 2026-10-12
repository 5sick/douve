#include "cluster/alerts.h"
#include "cluster/live.h"
#include "testing.h"

using namespace douve;

namespace {

Json::Value metricsMsg(double cpu, std::int64_t memUsed, std::int64_t diskUsed) {
    Json::Value m;
    m["type"] = "metrics";
    m["cpu"] = cpu;
    m["mem"]["used"] = Json::Int64(memUsed);
    m["mem"]["total"] = 1000;
    Json::Value d;
    d["mount"] = "/";
    d["used"] = Json::Int64(diskUsed);
    d["total"] = 1000;
    m["disks"].append(d);
    m["net"]["rx"] = 10.0;
    m["net"]["tx"] = 20.0;
    m["load"].append(0.5);
    m["load"].append(0.4);
    m["load"].append(0.3);
    return m;
}

} // namespace

TEST(parse_sample_validates_and_clamps) {
    auto s = parseSample(metricsMsg(150, 100, 200), 42);
    CHECK(s.has_value());
    CHECK_EQ(s->ts, 42);
    CHECK_EQ(s->cpu, 100.0);
    CHECK_EQ(s->disks.size(), std::size_t{1});
    CHECK_EQ(s->load5, 0.4);
    Json::Value bad;
    bad["cpu"] = "x";
    CHECK(!parseSample(bad, 1).has_value());
    auto neg = metricsMsg(10, -5, 0);
    CHECK_EQ(parseSample(neg, 1)->memUsed, 0);
}

TEST(live_state_minute_average_and_recent_cap) {
    LiveState live;
    live.addSample(1, *parseSample(metricsMsg(10, 100, 500), 1));
    live.addSample(1, *parseSample(metricsMsg(30, 300, 500), 2));
    auto rows = live.drainMinute(60);
    CHECK_EQ(rows.size(), std::size_t{1});
    CHECK_EQ(rows[0].second.cpu, 20.0);
    CHECK_EQ(rows[0].second.memUsed, 200);
    CHECK_EQ(rows[0].second.diskTotal, 1000);
    CHECK(live.drainMinute(120).empty()); // 비워졌는지
    for (int i = 0; i < 300; ++i)
        live.addSample(2, *parseSample(metricsMsg(1, 1, 1), i));
    CHECK_EQ(live.recent(2).size(), LiveState::kRecent);
    CHECK_EQ(live.latest(2)->ts, 299);
}

TEST(alerts_offline_after_grace) {
    NodeView n;
    n.id = 1;
    n.connected = false;
    n.lastSeenAt = 1000;
    CHECK(evaluateNode(n, 1100).rules.empty());
    auto c = evaluateNode(n, 1200);
    CHECK(c.rules.count("offline") == 1);
    CHECK(c.stale);
}

TEST(alerts_thresholds_units_containers) {
    NodeView n;
    n.id = 1;
    n.connected = true;
    n.latest = parseSample(metricsMsg(50, 960, 950), 1);
    Json::Value inv;
    inv["failed_units"].append("nginx.service");
    Json::Value ok, bad, exited0, exited1;
    ok["name"] = "web";
    ok["state"] = "running";
    bad["name"] = "db";
    bad["state"] = "running";
    bad["health"] = "unhealthy";
    exited0["name"] = "job";
    exited0["state"] = "exited";
    exited0["exit_code"] = 0;
    exited1["name"] = "crash";
    exited1["state"] = "exited";
    exited1["exit_code"] = 137;
    for (auto* c : {&ok, &bad, &exited0, &exited1})
        inv["containers"].append(*c);
    n.inventory = inv;
    auto c = evaluateNode(n, 10);
    CHECK(c.rules.count("disk:/") == 1);
    CHECK(c.rules.count("mem") == 1);
    CHECK(c.rules.count("unit:nginx.service") == 1);
    CHECK(c.rules.count("container:db") == 1);
    CHECK(c.rules.count("container:crash") == 1);
    CHECK(c.rules.count("container:web") == 0);
    CHECK(c.rules.count("container:job") == 0);
    CHECK(!c.stale);
}

TEST(alerts_reconcile_opens_resolves_and_holds_when_stale) {
    std::map<std::int64_t, Conditions> desired;
    desired[1].rules["disk:/"] = "디스크";
    auto a = reconcile({}, desired);
    CHECK_EQ(a.open.size(), std::size_t{1});
    CHECK(a.resolve.empty());

    OpenAlert open{10, 1, "disk:/", "디스크", 100};
    // 같은 조건 유지 → 아무것도 안 함 (반복 알림 없음)
    a = reconcile({open}, desired);
    CHECK(a.open.empty() && a.resolve.empty());
    // 조건 사라짐 → 해소
    a = reconcile({open}, {{1, Conditions{}}});
    CHECK_EQ(a.resolve.size(), std::size_t{1});
    // 노드가 응답 없음 → 디스크 알림은 유지, offline만 새로
    Conditions stale;
    stale.stale = true;
    stale.rules["offline"] = "응답 없음";
    a = reconcile({open}, {{1, stale}});
    CHECK(a.resolve.empty());
    CHECK_EQ(a.open.size(), std::size_t{1});
    CHECK_EQ(a.open[0].rule, "offline");
    // 다시 접속 → offline 해소
    OpenAlert off{11, 1, "offline", "응답 없음", 200};
    a = reconcile({open, off}, desired);
    CHECK_EQ(a.resolve.size(), std::size_t{1});
    CHECK_EQ(a.resolve[0].rule, "offline");
    // 평가 대상이 아닌 노드의 알림은 그대로
    a = reconcile({OpenAlert{12, 2, "mem", "m", 1}}, desired);
    CHECK(a.resolve.empty());
}
