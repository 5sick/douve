// 공유기 포트 자동 열기 (UPnP/NAT-PMP). 켠 노드가 입구면 80/443을 공유기에 요청하게 하고,
// Agent가 보낸 결과(공유기 종류·외부 주소·CGNAT·포트별 성공 여부)를 보여 준다.

#include "app.h"
#include "cluster/gateway.h"
#include "http_util.h"
#include "store/nodes.h"
#include "store/repo.h"

#include <drogon/drogon.h>

namespace douve {

using drogon::HttpRequestPtr;
using drogon::HttpResponsePtr;
using http::error;
using http::json;
using Callback = std::function<void(const HttpResponsePtr&)>;

Json::Value HubApp::buildPortmap(const Node& n) {
    Json::Value v;
    v["type"] = "portmap";
    v["mappings"] = Json::Value(Json::arrayValue);
    if (n.portForward && n.edge) {
        for (int port : {80, 443}) {
            Json::Value m;
            m["proto"] = "tcp";
            m["port"] = port;
            v["mappings"].append(m);
        }
    }
    return v;
}

void HubApp::ingestPortmap(std::int64_t nodeId, const Json::Value& status) {
    if (!status.isObject())
        return;
    // 포트별 성공 여부가 바뀌면 알린다 (처음 열림, 실패, 다시 열림)
    auto okSet = [](const Json::Value& s) {
        std::string out;
        for (const auto& m : s["mappings"])
            if (m.get("ok", false).asBool())
                out += m.get("proto", "").asString() + "/" +
                       std::to_string(m.get("port", 0).asInt()) + " ";
        return out;
    };
    std::string before;
    bool had = false;
    {
        std::lock_guard lk(portmapMu_);
        if (auto it = portmap_.find(nodeId); it != portmap_.end()) {
            had = true;
            before = okSet(it->second);
        }
        portmap_[nodeId] = status;
    }
    const std::string after = okSet(status);
    if (had && before == after)
        return;
    auto n = findNode(*db_, nodeId);
    if (!n || status["mappings"].empty())
        return;
    if (!after.empty() && before != after)
        notify("🔓 [" + n->name + "] 공유기 포트 열림: " + after + "(" +
               status.get("gateway", "").asString() + ", 외부 주소 " +
               status.get("external_ip", "").asString() + ")");
    else if (after.empty())
        notify("⚠️ [" + n->name + "] 공유기 포트를 열지 못했습니다: " +
               (status.get("error", "").asString().empty()
                    ? status["mappings"][0].get("error", "").asString()
                    : status.get("error", "").asString()));
}

Json::Value HubApp::portmapJson(std::int64_t nodeId) {
    std::lock_guard lk(portmapMu_);
    auto it = portmap_.find(nodeId);
    return it == portmap_.end() ? Json::Value() : it->second;
}

void HubApp::registerPortmapRoutes() {
    // 켜기/끄기: 공유기에 공개 포트를 여는 일이라 패스키 재확인
    drogon::app().registerHandler(
        "/api/nodes/portforward",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            const auto t = now();
            auto sess = currentSession(req, t);
            if (!sess)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            if (!sessions_->reauthFresh(*sess, t))
                return cb(error(drogon::k403Forbidden, "reauth_required"));
            auto body = req->getJsonObject();
            const std::int64_t id = body ? (*body).get("id", 0).asInt64() : 0;
            const bool on = body && (*body).get("on", false).asBool();
            auto n = findNode(*db_, id);
            if (!n || !setNodePortForward(*db_, id, on))
                return cb(error(drogon::k404NotFound, "노드를 찾을 수 없습니다"));
            audit(*db_, sess->userId, on ? "port_forward_on" : "port_forward_off", clientIp(req),
                  n->name, t);
            n->portForward = on;
            agents().send(id, buildPortmap(*n));
            Json::Value v;
            v["ok"] = true;
            cb(json(v));
        },
        {drogon::Post});
}

} // namespace douve
