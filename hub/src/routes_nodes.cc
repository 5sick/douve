// 노드(서버) 관리 API, Agent 등록, join.sh·Agent 바이너리 배포.

#include "app.h"
#include "assets.h"
#include "cluster/gateway.h"
#include "http_util.h"
#include "store/nodes.h"
#include "store/repo.h"
#include "util/json.h"

#include <drogon/drogon.h>

#include <filesystem>
#include <sstream>

namespace douve {

using drogon::HttpRequestPtr;
using drogon::HttpResponse;
using drogon::HttpResponsePtr;
using http::error;
using http::json;
using Callback = std::function<void(const HttpResponsePtr&)>;

namespace {

constexpr int kJoinTokenTtl = 15 * 60;

Json::Value parseJson(const std::string& s) {
    Json::Value v;
    if (!douve::parseJson(s, v))
        return Json::Value(Json::objectValue);
    return v;
}

Json::Value optInt(const std::optional<std::int64_t>& v) {
    return v ? Json::Value(Json::Int64(*v)) : Json::Value();
}

} // namespace

void HubApp::registerNodeRoutes() {
    auto& app = drogon::app();
    gateway_ = std::make_shared<AgentGateway>(*this);
    app.registerController(gateway_);

    auto nodeJson = [this](const Node& n, const std::vector<OpenAlert>& alerts) {
        Json::Value v;
        v["id"] = Json::Int64(n.id);
        v["name"] = n.name;
        v["hostname"] = n.hostname;
        v["os"] = n.os;
        v["arch"] = n.arch;
        v["agent_version"] = n.agentVersion;
        v["created_at"] = Json::Int64(n.createdAt);
        v["last_seen_at"] = optInt(n.lastSeenAt);
        v["last_ip"] = n.lastIp;
        v["connected"] = live_.connected(n.id);
        v["edge"] = n.edge;
        v["mesh_address"] = n.meshAddress;
        v["port_forward"] = n.portForward;
        v["portmap"] = portmapJson(n.id);
        auto s = live_.latest(n.id);
        v["latest"] = s ? sampleToJson(*s) : Json::Value();
        v["alerts"] = Json::Value(Json::arrayValue);
        for (const auto& a : alerts) {
            if (a.nodeId && *a.nodeId == n.id) {
                Json::Value av;
                av["rule"] = a.rule;
                av["message"] = a.message;
                av["started_at"] = Json::Int64(a.startedAt);
                v["alerts"].append(av);
            }
        }
        return v;
    };

    app.registerHandler(
        "/api/nodes",
        [this, nodeJson](const HttpRequestPtr& req, Callback&& cb) {
            auto s = currentSession(req, now());
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            const auto a = access(*s);
            const auto alerts = openAlerts(*db_);
            Json::Value arr(Json::arrayValue);
            for (const auto& n : listNodes(*db_))
                if (a.node(n.id))
                    arr.append(nodeJson(n, alerts));
            Json::Value out;
            out["nodes"] = arr;
            out["now"] = Json::Int64(now());
            if (a.admin()) {
                Statement sc(*db_, "SELECT count(*) FROM security_issues WHERE status = 'open'");
                out["security_open"] = Json::Int64(sc.step() ? sc.int64(0) : 0);
            }
            cb(json(out));
        },
        {drogon::Get});

    app.registerHandler(
        "/api/nodes/{id}",
        [this, nodeJson](const HttpRequestPtr& req, Callback&& cb, std::int64_t id) {
            auto s = currentSession(req, now());
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            auto n = access(*s).node(id) ? findNode(*db_, id) : std::nullopt;
            if (!n)
                return cb(error(drogon::k404NotFound, "노드를 찾을 수 없습니다"));
            Json::Value v = nodeJson(*n, openAlerts(*db_));
            auto inv = live_.inventory(id);
            v["inventory"] = inv ? *inv : parseJson(n->inventory);
            v["recent"] = Json::Value(Json::arrayValue);
            for (const auto& s : live_.recent(id))
                v["recent"].append(sampleToJson(s));
            v["now"] = Json::Int64(now());
            cb(json(v));
        },
        {drogon::Get});

    app.registerHandler(
        "/api/nodes/{id}/metrics",
        [this](const HttpRequestPtr& req, Callback&& cb, std::int64_t id) {
            const auto t = now();
            auto s = currentSession(req, t);
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            if (!access(*s).node(id))
                return cb(error(drogon::k404NotFound, "노드를 찾을 수 없습니다"));
            static const std::map<std::string, std::pair<std::int64_t, std::int64_t>> ranges = {
                {"1h", {3600, 60}},        {"6h", {6 * 3600, 120}},     {"24h", {86400, 300}},
                {"7d", {7 * 86400, 1800}}, {"30d", {30 * 86400, 7200}},
            };
            auto it = ranges.find(req->getParameter("range"));
            if (it == ranges.end())
                it = ranges.find("24h");
            Json::Value arr(Json::arrayValue);
            for (const auto& m : queryMetrics(*db_, id, t - it->second.first, it->second.second)) {
                Json::Value v(Json::arrayValue);
                v.append(Json::Int64(m.ts));
                v.append(m.cpu);
                v.append(Json::Int64(m.memUsed));
                v.append(Json::Int64(m.memTotal));
                v.append(Json::Int64(m.diskUsed));
                v.append(Json::Int64(m.diskTotal));
                v.append(m.netRx);
                v.append(m.netTx);
                v.append(m.load1);
                arr.append(v);
            }
            Json::Value out;
            out["columns"] = Json::Value(Json::arrayValue);
            for (const char* c : {"ts", "cpu", "mem_used", "mem_total", "disk_used", "disk_total",
                                  "net_rx", "net_tx", "load1"})
                out["columns"].append(c);
            out["rows"] = arr;
            cb(json(out));
        },
        {drogon::Get});

    // 서버 추가: 일회용 토큰 발급 (패스키 재확인 필요)
    app.registerHandler(
        "/api/nodes/join-token",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            const auto t = now();
            auto s = currentSession(req, t);
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            if (!sessions_->reauthFresh(*s, t))
                return cb(error(drogon::k403Forbidden, "reauth_required"));
            auto body = req->getJsonObject();
            const std::string name = body ? (*body).get("name", "").asString() : "";
            auto tok = createJoinToken(*db_, s->userId, name, kJoinTokenTtl, t);
            audit(*db_, s->userId, "join_token_created", clientIp(req), sanitizeNodeName(name), t);
            Json::Value v;
            v["token"] = tok.token;
            v["expires_at"] = Json::Int64(tok.expiresAt);
            v["command"] = "curl -fsSL " + cfg_.publicUrl + "/join.sh | sudo sh -s -- " + tok.token;
            cb(json(v));
        },
        {drogon::Post});

    app.registerHandler("/api/nodes/delete",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            if (!sameOrigin(req))
                                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
                            const auto t = now();
                            auto s = currentSession(req, t);
                            if (!s)
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            if (!sessions_->reauthFresh(*s, t))
                                return cb(error(drogon::k403Forbidden, "reauth_required"));
                            auto body = req->getJsonObject();
                            const std::int64_t id = body ? (*body).get("id", 0).asInt64() : 0;
                            auto n = findNode(*db_, id);
                            if (!n || !deleteNode(*db_, id))
                                return cb(error(drogon::k404NotFound, "노드를 찾을 수 없습니다"));
                            gateway_->disconnect(id);
                            live_.forget(id);
                            audit(*db_, s->userId, "node_deleted", clientIp(req), n->name, t);
                            Json::Value v;
                            v["ok"] = true;
                            cb(json(v));
                        },
                        {drogon::Post});

    app.registerHandler(
        "/api/nodes/rename",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            if (!currentSession(req, now()))
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            auto body = req->getJsonObject();
            if (!body || !renameNode(*db_, (*body).get("id", 0).asInt64(),
                                     (*body).get("name", "").asString()))
                return cb(error(drogon::k400BadRequest,
                                "이름을 바꿀 수 없습니다 (영문 소문자·숫자·하이픈, 중복 불가)"));
            Json::Value v;
            v["ok"] = true;
            cb(json(v));
        },
        {drogon::Post});

    // Agent 등록 (join.sh → douve-agent join). 세션 대신 일회용 토큰으로 인증.
    app.registerHandler(
        "/api/agent/enroll",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            const auto t = now();
            const std::string ip = clientIp(req);
            if (!enrollLimiter_.allow(ip, t)) {
                audit(*db_, std::nullopt, "rate_limited", ip, "enroll", t);
                return cb(error(drogon::k429TooManyRequests, "요청이 너무 많습니다"));
            }
            auto body = req->getJsonObject();
            if (!body)
                return cb(error(drogon::k400BadRequest, "JSON 본문이 필요합니다"));
            EnrollRequest er;
            er.token = (*body).get("token", "").asString();
            auto pk = base64UrlDecode((*body).get("pubkey", "").asString());
            er.pubkey = pk ? *pk : Bytes{};
            er.hostname = (*body).get("hostname", "").asString();
            er.os = (*body).get("os", "").asString();
            er.arch = (*body).get("arch", "").asString();
            er.agentVersion = (*body).get("version", "").asString();
            er.ip = ip;
            std::string err;
            auto node = enrollNode(*db_, er, t, err);
            if (!node) {
                audit(*db_, std::nullopt, "enroll_failed", ip, err, t);
                return cb(error(drogon::k403Forbidden, err));
            }
            audit(*db_, std::nullopt, "node_enrolled", ip, node->name, t);
            notify("🆕 서버 추가됨: " + node->name + " (" + node->hostname + ", " + ip + ")");
            Json::Value v;
            v["node_id"] = Json::Int64(node->id);
            v["name"] = node->name;
            cb(json(v));
        },
        {drogon::Post});

    app.registerHandler("/join.sh",
                        [this](const HttpRequestPtr&, Callback&& cb) {
                            const auto* a = assets::find("join.sh");
                            std::string body(reinterpret_cast<const char*>(a->data), a->size);
                            const std::string key = "__DOUVE_HUB__";
                            for (auto p = body.find(key); p != std::string::npos;
                                 p = body.find(key, p))
                                body.replace(p, key.size(), cfg_.publicUrl);
                            auto r = HttpResponse::newHttpResponse();
                            r->setBody(std::move(body));
                            r->setContentTypeString("text/plain; charset=utf-8");
                            r->addHeader("Cache-Control", "no-store");
                            cb(r);
                        },
                        {drogon::Get});

    app.registerHandler("/dl/{file}",
                        [this](const HttpRequestPtr&, Callback&& cb, const std::string& file) {
                            static const std::set<std::string> allowed = {
                                "douve-agent-linux-amd64", "douve-agent-linux-arm64", "SHA256SUMS",
                                "SHA256SUMS.minisig"};
                            if (!allowed.count(file))
                                return cb(HttpResponse::newNotFoundResponse());
                            const auto path = std::filesystem::path(cfg_.agentDir) / file;
                            std::error_code ec;
                            if (!std::filesystem::is_regular_file(path, ec))
                                return cb(error(drogon::k404NotFound,
                                                "Hub에 Agent 바이너리가 설치되어 있지 않습니다"));
                            auto r = HttpResponse::newFileResponse(
                                path.string(), "", drogon::CT_APPLICATION_OCTET_STREAM);
                            r->addHeader("Cache-Control", "no-store");
                            cb(r);
                        },
                        {drogon::Get});
}

} // namespace douve
