// 연결 진단 API: 서버마다 인터넷에서 보이는 주소·NAT·공유기(Agent 보고), 외부 접속 검증(다른 공인
// 서버가 그 서버의 공인 주소로 22·80·443에 접속해 본다), Douve가 지금 쓰는 길(입구 자신·직접·터널).

#include "app.h"
#include "cluster/gateway.h"
#include "http_util.h"
#include "store/nodes.h"
#include "store/repo.h"
#include "util/crypto.h"
#include "util/json.h"

#include <drogon/drogon.h>

#include <arpa/inet.h>

namespace douve {

using drogon::HttpRequestPtr;
using drogon::HttpResponsePtr;
using http::error;
using http::json;
using Callback = std::function<void(const HttpResponsePtr&)>;

namespace {

std::string compact(const Json::Value& v) {
    Json::StreamWriterBuilder w;
    w["indentation"] = "";
    return Json::writeString(w, v);
}

// 인터넷에서 닿는 IPv4인가 (사설·CGNAT·루프백 아님)
bool publicIPv4(const std::string& s) {
    in_addr a{};
    if (inet_pton(AF_INET, s.c_str(), &a) != 1)
        return false;
    const std::uint32_t ip = ntohl(a.s_addr);
    auto in = [ip](std::uint32_t net, int bits) {
        return (ip >> (32 - bits)) == (net >> (32 - bits));
    };
    return !(in(0x0A000000, 8) || in(0xAC100000, 12) || in(0xC0A80000, 16) || in(0x64400000, 10) ||
             in(0x7F000000, 8) || in(0xA9FE0000, 16) || ip == 0 || in(0xE0000000, 3));
}

struct ReachRow {
    Json::Value report, verify;
    std::int64_t at = 0, verifiedAt = 0;
};

std::optional<ReachRow> loadReach(Database& db, std::int64_t nodeId) {
    auto guard = db.lock();
    Statement q(db, "SELECT report, at, verify, verified_at FROM reach WHERE node_id = ?");
    q.bind(1, nodeId);
    if (!q.step())
        return std::nullopt;
    ReachRow r;
    parseJson(q.text(0), r.report);
    r.at = q.int64(1);
    parseJson(q.text(2), r.verify);
    r.verifiedAt = q.int64(3);
    return r;
}

} // namespace

std::string HubApp::nodePublicIp(const Node& n) {
    if (auto r = loadReach(*db_, n.id)) {
        const auto ip = r->report["stun"].get("public_ip", "").asString();
        if (publicIPv4(ip))
            return ip;
    }
    return publicIPv4(n.lastIp) ? n.lastIp : "";
}

void HubApp::ingestReach(std::int64_t nodeId, const Json::Value& msg) {
    Json::Value r;
    r["outbound_ip"] = jsonStr(msg, "outbound_ip").substr(0, 45);
    const auto& st = msg["stun"];
    r["stun"]["ok"] = st.get("ok", false).asBool();
    r["stun"]["public_ip"] = jsonStr(st, "public_ip").substr(0, 45);
    r["stun"]["nat"] = jsonStr(st, "nat").substr(0, 12);
    r["stun"]["error"] = jsonStr(st, "error").substr(0, 200);
    r["stun"]["mapped"] = Json::Value(Json::arrayValue);
    for (const auto& m : st["mapped"])
        if (r["stun"]["mapped"].size() < 4)
            r["stun"]["mapped"].append(m.asString().substr(0, 60));
    const auto& rt = msg["router"];
    r["router"]["kind"] = jsonStr(rt, "kind").substr(0, 10);
    r["router"]["external_ip"] = jsonStr(rt, "external_ip").substr(0, 45);
    r["router"]["error"] = jsonStr(rt, "error").substr(0, 200);
    {
        std::lock_guard lk(reachMu_);
        if (msg.isMember("tunnels")) {
            auto& set = edgeTunnels_[nodeId];
            set.clear();
            for (const auto& id : msg["tunnels"])
                set.insert(id.asInt64());
        }
    }
    auto guard = db_->lock();
    Statement(*db_, "INSERT INTO reach (node_id, report, at) VALUES (?, ?, ?) ON CONFLICT(node_id) "
                    "DO UPDATE SET report = excluded.report, at = excluded.at")
        .bind(1, nodeId)
        .bind(2, compact(r))
        .bind(3, now())
        .run();
}

void HubApp::verifyReach(std::int64_t nodeId, std::function<void(const Json::Value&)> done) {
    auto target = findNode(*db_, nodeId);
    Json::Value result;
    result["tested"] = false;
    if (!target)
        return done(result);
    const std::string host = nodePublicIp(*target);
    if (host.empty()) {
        result["reason"] = "no_public_ip";
        return done(result);
    }
    // 시험할 쪽: 접속 중이고 공인 주소가 대상과 다른 서버 (같은 공유기 안이면 밖이 아니다). 입구
    // 먼저.
    std::optional<Node> tester;
    for (const auto& n : listNodes(*db_)) {
        if (n.id == nodeId || !live_.connected(n.id))
            continue;
        const auto ip = nodePublicIp(n);
        if (ip.empty() || ip == host)
            continue;
        if (!tester || (n.edge && !tester->edge))
            tester = n;
    }
    if (!tester) {
        result["reason"] = "no_tester";
        return done(result);
    }
    const std::string rid = randomToken(9);
    Json::Value m;
    m["type"] = "reach_probe";
    m["rid"] = rid;
    m["host"] = host;
    m["ports"] = Json::Value(Json::arrayValue);
    for (int p : {22, 80, 443})
        m["ports"].append(p);
    result["host"] = host;
    result["tester"] = tester->name;
    {
        std::lock_guard lk(reachMu_);
        probes_[rid] = ProbeWait{nodeId, result, std::move(done)};
    }
    if (!gateway_->send(tester->id, m)) {
        finishProbe(rid, Json::Value());
        return;
    }
    // 답이 없으면 12초 뒤 시험 못 함으로
    drogon::app().getLoop()->runAfter(12.0, [this, rid]() { finishProbe(rid, Json::Value()); });
}

void HubApp::finishProbe(const std::string& rid, const Json::Value& msg) {
    ProbeWait w;
    {
        std::lock_guard lk(reachMu_);
        auto it = probes_.find(rid);
        if (it == probes_.end())
            return;
        w = std::move(it->second);
        probes_.erase(it);
    }
    Json::Value r = w.result;
    if (msg.isMember("results")) {
        r["tested"] = true;
        r["ports"] = Json::Value(Json::arrayValue);
        for (const auto& p : msg["results"]) {
            Json::Value x;
            x["port"] = p.get("port", 0).asInt();
            x["open"] = p.get("open", false).asBool();
            x["error"] = jsonStr(p, "error").substr(0, 20);
            r["ports"].append(x);
        }
    } else {
        r["reason"] = msg.isMember("error") ? "probe_error" : "no_answer";
    }
    r["at"] = Json::Int64(now());
    {
        auto guard = db_->lock();
        Statement(*db_,
                  "INSERT INTO reach (node_id, report, at, verify, verified_at) VALUES (?, '{}', "
                  "0, ?, ?) ON CONFLICT(node_id) DO UPDATE SET verify = excluded.verify, "
                  "verified_at = excluded.verified_at")
            .bind(1, w.nodeId)
            .bind(2, compact(r))
            .bind(3, now())
            .run();
    }
    alertReach(w.nodeId, r);
    if (w.done)
        w.done(r);
}

void HubApp::ingestReachProbe(std::int64_t nodeId, const Json::Value& msg) {
    (void)nodeId;
    finishProbe(jsonStr(msg, "rid"), msg);
}

// 상태가 바뀔 때만 알린다: 입구에 밖에서 443이 안 열림(두 번 연속), 밖에서 SSH(22)가 열림.
void HubApp::alertReach(std::int64_t nodeId, const Json::Value& r) {
    if (!r.get("tested", false).asBool())
        return;
    auto n = findNode(*db_, nodeId);
    if (!n)
        return;
    bool open22 = false, open443 = false;
    for (const auto& p : r["ports"]) {
        open22 = open22 || (p["port"].asInt() == 22 && p["open"].asBool());
        open443 = open443 || (p["port"].asInt() == 443 && p["open"].asBool());
    }
    std::string msg;
    {
        std::lock_guard lk(reachMu_);
        auto& st = reachAlerts_[nodeId];
        if (open22 && !st.ssh)
            msg = "보안: " + n->name + "의 SSH(22번)에 인터넷에서 접속할 수 있습니다 (" +
                  r["host"].asString() + ")";
        else if (!open22 && st.ssh)
            msg = n->name + "의 SSH(22번)가 인터넷에서 다시 닫혔습니다";
        st.ssh = open22;
        if (n->edge) {
            st.edgeFails = open443 ? 0 : st.edgeFails + 1;
            if (st.edgeFails == 2)
                msg = "입구 서버 " + n->name + "에 인터넷에서 HTTPS(443)로 접속할 수 없습니다 (" +
                      r["host"].asString() + ", " + r["tester"].asString() + "에서 시험)";
            else if (open443 && st.edgeDown)
                msg = "입구 서버 " + n->name + "에 인터넷에서 다시 접속됩니다";
            st.edgeDown = st.edgeFails >= 2;
        }
    }
    if (!msg.empty())
        notify(msg);
}

void HubApp::registerReachRoutes() {
    auto& app = drogon::app();

    app.registerHandler("/api/reach",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            auto s = currentSession(req, now());
                            if (!s)
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            const auto acc = access(*s);
                            const auto nodes = listNodes(*db_);
                            bool hasEdge = false;
                            std::set<std::int64_t> tunneled;
                            for (const auto& n : nodes)
                                hasEdge = hasEdge || n.edge;
                            {
                                std::lock_guard lk(reachMu_);
                                for (const auto& [edge, set] : edgeTunnels_)
                                    tunneled.insert(set.begin(), set.end());
                            }
                            Json::Value arr(Json::arrayValue);
                            for (const auto& n : nodes) {
                                if (!acc.node(n.id))
                                    continue;
                                Json::Value v;
                                v["id"] = Json::Int64(n.id);
                                v["name"] = n.name;
                                v["edge"] = n.edge;
                                v["connected"] = live_.connected(n.id);
                                v["last_ip"] = n.lastIp;
                                Json::Value inv;
                                if (parseJson(n.inventory, inv))
                                    v["cloud"] = inv["system"].get("cloud", "");
                                // Douve가 이 서버의 앱에 닿는 길
                                v["path"] = n.edge                    ? "edge"
                                            : !hasEdge                ? "none"
                                            : tunneled.contains(n.id) ? "tunnel"
                                                                      : "direct";
                                if (auto r = loadReach(*db_, n.id)) {
                                    if (r->at)
                                        v["report"] = r->report,
                                        v["report_at"] = Json::Int64(r->at);
                                    if (r->verifiedAt)
                                        v["verify"] = r->verify;
                                }
                                arr.append(v);
                            }
                            Json::Value out;
                            out["nodes"] = arr;
                            cb(json(out));
                        },
                        {drogon::Get});

    // 다시 진단: Agent에 진단을 시키고 외부 접속 검증을 한다 (검증 결과까지 기다려 답한다)
    app.registerHandler("/api/reach/run",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            if (!sameOrigin(req))
                                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
                            auto s = currentSession(req, now());
                            if (!s)
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            auto body = req->getJsonObject();
                            const std::int64_t nodeId = body ? jsonInt(*body, "node_id") : 0;
                            if (!access(*s).node(nodeId) || !findNode(*db_, nodeId))
                                return cb(error(drogon::k404NotFound, "노드를 찾을 수 없습니다"));
                            Json::Value m;
                            m["type"] = "reach_run";
                            gateway_->send(nodeId, m);
                            verifyReach(nodeId, [cb = std::move(cb)](const Json::Value& r) {
                                Json::Value v;
                                v["verify"] = r;
                                cb(json(v));
                            });
                        },
                        {drogon::Post});
}

} // namespace douve
