// 서비스(공개 도메인) 관리 API, 입구(edge) 지정, 라우팅 표 전송.

#include "app.h"
#include "cluster/apps.h"
#include "cluster/gateway.h"
#include "http_util.h"
#include "store/devnet.h"
#include "store/nodes.h"
#include "store/repo.h"
#include "store/services.h"
#include "util/encoding.h"
#include "util/json.h"

#include <drogon/drogon.h>

#include <set>
#include <sstream>

namespace douve {

using drogon::HttpRequestPtr;
using drogon::HttpResponsePtr;
using http::error;
using http::json;
using Callback = std::function<void(const HttpResponsePtr&)>;

namespace {

std::string hostOfUrl(const std::string& url) {
    auto start = url.find("://");
    start = start == std::string::npos ? 0 : start + 3;
    auto end = url.find_first_of(":/", start);
    return url.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

// "http://10.200.0.2:8700" → "10.200.0.2:8700"
std::string hostPortOfUrl(const std::string& url) {
    auto start = url.find("://");
    start = start == std::string::npos ? 0 : start + 3;
    auto end = url.find('/', start);
    return url.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

Json::Value parse(const std::string& s) {
    Json::Value v;
    douve::parseJson(s, v);
    return v;
}

// 업스트림이 그 노드 자신(메시 주소:포트)인가
bool upstreamOnNode(const std::string& upstream, const Node& n) {
    if (n.meshAddress.empty() || upstream.rfind(n.meshAddress + ":", 0) != 0)
        return false;
    const std::string port = upstream.substr(n.meshAddress.size() + 1);
    return !port.empty() && port.size() <= 5 &&
           std::all_of(port.begin(), port.end(), [](unsigned char c) { return std::isdigit(c); });
}

} // namespace

Json::Value HubApp::buildRoutes() {
    Json::Value r;
    r["type"] = "routes";
    r["verify_url"] = cfg_.effectiveInternalUrl() + "/auth/verify";
    r["login_url"] = cfg_.publicUrl + "/login";
    r["acme_email"] = cfg_.allowedEmails.empty() ? "" : cfg_.allowedEmails.front();
    r["routes"] = Json::Value(Json::arrayValue);
    // Hub 자신 (로그인 화면). 쿠키를 그대로 전달하고 Douve 검사는 하지 않는다.
    Json::Value hub;
    hub["host"] = hostOfUrl(cfg_.publicUrl);
    hub["upstream"] = hostPortOfUrl(cfg_.effectiveInternalUrl());
    hub["auth"] = "hub";
    hub["public_paths"] = Json::Value(Json::arrayValue);
    r["routes"].append(hub);
    for (const auto& s : listServices(*db_)) {
        if (!s.external)
            continue; // 내부 길 전용: 공개 입구에는 없다 (그 도메인은 404)
        r["routes"].append(routeJson(s));
    }
    // 터널 인증·연결 방식 선택용 노드 정보
    r["nodes"] = Json::Value(Json::arrayValue);
    for (const auto& n : listNodes(*db_)) {
        Json::Value v;
        v["id"] = Json::Int64(n.id);
        v["pubkey"] = base64UrlEncode(n.pubkey);
        v["mode"] = n.connectMode;
        r["nodes"].append(v);
    }
    return r;
}

Json::Value HubApp::routeJson(const Service& s) {
    Json::Value v;
    v["id"] = Json::Int64(s.id); // 입구가 /auth/verify?service=로 앱별 권한을 묻는다
    v["host"] = s.host;
    v["upstream"] = s.upstream;
    v["auth"] = s.auth;
    v["path_prefix"] = s.pathPrefix;
    v["strip_prefix"] = s.stripPrefix;
    v["kind"] = s.kind;
    v["redirect_to"] = s.redirectTo;
    v["upstream_tls"] = s.upstreamTls;
    v["host_header"] = s.hostHeader;
    v["timeout"] = s.timeout;
    v["node_id"] = s.nodeId ? Json::Int64(*s.nodeId) : Json::Int64(0);
    v["public_paths"] = Json::Value(Json::arrayValue);
    for (const auto& p : s.publicPaths)
        v["public_paths"].append(p);
    return v;
}

std::string HubApp::tunnelUrl() const {
    if (!cfg_.tunnelUrl.empty())
        return cfg_.tunnelUrl;
    // https://host → wss://host/_douve/tunnel (입구가 모든 도메인에서 이 경로를 받는다)
    std::string u = cfg_.publicUrl;
    if (u.rfind("https://", 0) == 0)
        u = "wss://" + u.substr(8);
    else if (u.rfind("http://", 0) == 0)
        u = "ws://" + u.substr(7);
    return u + "/_douve/tunnel";
}

Json::Value HubApp::buildTunnelConfig(const Node& n) {
    Json::Value t;
    t["type"] = "tunnel";
    t["allow"] = Json::Value(Json::arrayValue);
    t["checks"] = Json::Value(Json::arrayValue);
    bool any = false, loopback = false;
    for (const auto& s : listServices(*db_)) {
        if (!s.nodeId || *s.nodeId != n.id || s.kind != "proxy" || s.upstream.empty())
            continue;
        any = true;
        loopback = loopback || isLoopbackUpstream(s.upstream);
        t["allow"].append(s.upstream);
        Json::Value c;
        c["upstream"] = s.upstream;
        c["tls"] = s.upstreamTls;
        c["path"] = s.stripPrefix ? "/" : s.pathPrefix;
        t["checks"].append(c);
    }
    // 입구 자신이거나 서비스가 없으면 터널을 열지 않는다.
    // 직통(direct)이어도 127.0.0.1 업스트림은 그 노드 안에서만 닿으니 터널이 필요하다.
    t["url"] = (!n.edge && any && (n.connectMode != "direct" || loopback)) ? tunnelUrl() : "";
    return t;
}

void HubApp::pushRoutes(std::int64_t nodeId) {
    auto routes = buildRoutes();
    for (const auto& n : listNodes(*db_)) {
        if (nodeId != 0 && n.id != nodeId)
            continue;
        if (n.edge) {
            routes["self_node"] = Json::Int64(n.id);
            // 내부 길(기기 WireGuard)은 입구 하나(가장 먼저 만든 입구)가 맡는다
            if (auto gw = devnetGateway(); gw && gw->id == n.id)
                routes["devnet"] = buildDevnet();
            else
                routes.removeMember("devnet");
            gateway_->send(n.id, routes);
        }
        gateway_->send(n.id, buildTunnelConfig(n)); // 모든 노드: 터널 주소·허용 목록·상태 확인 대상
        gateway_->send(n.id, buildPortmap(n));      // 공유기 포트 (입구이고 켰을 때만 80/443)
    }
}

void HubApp::refreshEdgeAddresses() {
    std::set<std::string> addrs;
    for (const auto& n : listNodes(*db_))
        if (n.edge && !n.meshAddress.empty())
            addrs.insert(n.meshAddress);
    std::lock_guard lk(edgeMu_);
    edgeAddresses_ = std::move(addrs);
}

void HubApp::updateMeshAddress(std::int64_t nodeId, const std::string& address) {
    auto n = findNode(*db_, nodeId);
    if (!n || n->meshAddress == address)
        return;
    setMeshAddress(*db_, nodeId, address);
    if (n->edge)
        refreshEdgeAddresses();
}

void HubApp::registerServiceRoutes() {
    auto& app = drogon::app();
    refreshEdgeAddresses();

    auto serviceJson = [this](const Service& s, const std::map<std::int64_t, std::string>& names) {
        Json::Value v;
        v["id"] = Json::Int64(s.id);
        v["name"] = s.name;
        v["host"] = s.host;
        v["node_id"] = s.nodeId ? Json::Value(Json::Int64(*s.nodeId)) : Json::Value();
        auto it = s.nodeId ? names.find(*s.nodeId) : names.end();
        v["node_name"] = it != names.end() ? it->second : "";
        v["upstream"] = s.upstream;
        v["auth"] = s.auth;
        v["public_paths"] = Json::Value(Json::arrayValue);
        for (const auto& p : s.publicPaths)
            v["public_paths"].append(p);
        v["group"] = s.group;
        v["description"] = s.description;
        v["icon"] = s.icon;
        v["on_home"] = s.onHome;
        v["position"] = s.position;
        v["path_prefix"] = s.pathPrefix;
        v["strip_prefix"] = s.stripPrefix;
        v["kind"] = s.kind;
        v["redirect_to"] = s.redirectTo;
        v["upstream_tls"] = s.upstreamTls;
        v["host_header"] = s.hostHeader;
        v["timeout"] = s.timeout;
        v["origin"] = s.origin;
        v["internal"] = s.internal;
        v["external"] = s.external;
        v["icon_url"] = "/api/icons/service/" + std::to_string(s.id) + "?v=" + s.icon;
        std::lock_guard lk(healthMu_);
        auto h = health_.find(s.id);
        if (h != health_.end() && h->second.checkedAt > 0) {
            v["health"]["ok"] = h->second.fails == 0;
            v["health"]["status"] = Json::Int64(h->second.status);
            v["health"]["error"] = h->second.error;
            v["health"]["checked_at"] = Json::Int64(h->second.checkedAt);
            v["health"]["latency_ms"] = h->second.latencyMs;
        } else {
            v["health"] = Json::Value();
        }
        return v;
    };

    app.registerHandler("/api/services",
                        [this, serviceJson](const HttpRequestPtr& req, Callback&& cb) {
                            auto sess = currentSession(req, now());
                            if (!sess)
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            const auto acc = access(*sess);
                            std::map<std::int64_t, std::string> names;
                            Json::Value edges(Json::arrayValue);
                            for (const auto& n : listNodes(*db_)) {
                                names[n.id] = n.name;
                                if (n.edge) {
                                    Json::Value e;
                                    e["id"] = Json::Int64(n.id);
                                    e["name"] = n.name;
                                    e["connected"] = live_.connected(n.id);
                                    edges.append(e);
                                }
                            }
                            Json::Value arr(Json::arrayValue);
                            for (const auto& s : listServices(*db_))
                                if (acc.service(s.id, s.nodeId))
                                    arr.append(serviceJson(s, names));
                            Json::Value out;
                            out["services"] = arr;
                            out["edges"] = edges;
                            out["base_domain"] = cfg_.cookieDomain;
                            out["hub_host"] = hostOfUrl(cfg_.publicUrl);
                            out["devnet"] = loadDevnet(*db_).enabled; // 내부 길을 고를 수 있는지
                            cb(json(out));
                        },
                        {drogon::Get});

    // 노드에서 발견한 공개 가능 포트 (열린 포트 + 컨테이너 이름)
    app.registerHandler(
        "/api/services/suggest",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            auto sess = currentSession(req, now());
            if (!sess)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            const std::int64_t nodeId = std::atoll(req->getParameter("node_id").c_str());
            auto n = access(*sess).node(nodeId) ? findNode(*db_, nodeId) : std::nullopt;
            if (!n)
                return cb(error(drogon::k404NotFound, "노드를 찾을 수 없습니다"));
            auto live = live_.inventory(n->id);
            const Json::Value inv = live ? *live : parse(n->inventory);
            std::set<std::string> used;
            for (const auto& s : listServices(*db_))
                used.insert(s.upstream);
            std::map<int, std::string> containerByPort;
            for (const auto& c : inv["containers"])
                for (const auto& p : c["ports"])
                    containerByPort[p.asInt()] = c.get("name", "").asString();
            static const std::set<int> skip = {22, 25, 53, 111, 323, 631, 51820};
            const std::string hubHostPort = hostPortOfUrl(cfg_.effectiveInternalUrl());
            Json::Value arr(Json::arrayValue);
            std::set<int> seen;
            for (const auto& p : inv["ports"]) {
                const int port = p.get("port", 0).asInt();
                const std::string addr = p.get("address", "").asString();
                // 다른 노드(입구)에서 닿을 수 있는 주소만: 0.0.0.0 / :: / 메시 주소
                const bool reachable = addr == "0.0.0.0" || addr == "::" ||
                                       (!n->meshAddress.empty() && addr == n->meshAddress);
                if (!reachable || skip.count(port) || seen.count(port) || port <= 0)
                    continue;
                seen.insert(port);
                const std::string upstream = n->meshAddress + ":" + std::to_string(port);
                if (upstream == hubHostPort)
                    continue;
                Json::Value v;
                v["port"] = port;
                v["upstream"] = upstream;
                v["label"] = containerByPort.count(port) ? containerByPort[port]
                                                         : p.get("process", "").asString();
                v["registered"] = used.count(upstream) > 0;
                arr.append(v);
            }
            Json::Value out;
            out["node_id"] = Json::Int64(n->id);
            out["mesh_address"] = n->meshAddress;
            out["candidates"] = arr;
            cb(json(out));
        },
        {drogon::Get});

    // 실행 중인 앱 (모든 노드): 컨테이너·열린 포트 + 공개 여부
    app.registerHandler("/api/apps",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            auto sess = currentSession(req, now());
                            if (!sess)
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            const auto acc = access(*sess);
                            const auto services = listServices(*db_);
                            const std::string hubHostPort =
                                hostPortOfUrl(cfg_.effectiveInternalUrl());
                            Json::Value apps(Json::arrayValue);
                            bool hasEdge = false;
                            for (const auto& n : listNodes(*db_)) {
                                hasEdge = hasEdge || n.edge;
                                if (!acc.node(n.id))
                                    continue;
                                auto live = live_.inventory(n.id);
                                const Json::Value inv = live ? *live : parse(n.inventory);
                                for (auto& a : discoverApps(n, inv, services)) {
                                    if (a.get("upstream", "").asString() == hubHostPort)
                                        continue; // Hub 자신
                                    apps.append(a);
                                }
                            }
                            Json::Value out;
                            out["apps"] = apps;
                            out["base_domain"] = cfg_.cookieDomain;
                            out["has_edge"] = hasEdge;
                            cb(json(out));
                        },
                        {drogon::Get});

    // 서비스 생성·수정 공통 처리. 공개 범위를 바꾸는 작업이라 패스키 재확인이 필요하다.
    auto upsert = [this](const HttpRequestPtr& req, Callback&& cb, bool create) {
        if (!sameOrigin(req))
            return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
        const auto t = now();
        auto sess = currentSession(req, t);
        if (!sess)
            return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
        if (!sessions_->reauthFresh(*sess, t))
            return cb(error(drogon::k403Forbidden, "reauth_required"));
        auto body = req->getJsonObject();
        if (!body)
            return cb(error(drogon::k400BadRequest, "JSON 본문이 필요합니다"));
        const auto& b = *body;
        const auto acc = access(*sess);
        Service s;
        if (!create) {
            auto cur = findService(*db_, b.get("id", 0).asInt64());
            if (cur && !acc.admin() && !(cur->nodeId && acc.node(*cur->nodeId)))
                cur.reset(); // 운영자: 허락된 서버의 서비스만
            if (!cur)
                return cb(error(drogon::k404NotFound, "서비스를 찾을 수 없습니다"));
            s = *cur;
        }
        s.name = b.get("name", s.name).asString();
        s.host = b.get("host", s.host).asString();
        s.auth = b.get("auth", s.auth).asString();
        s.group = b.get("group", s.group).asString();
        s.description = b.get("description", s.description).asString();
        s.icon = b.get("icon", s.icon).asString();
        s.onHome = b.get("on_home", s.onHome).asBool();
        s.position = b.get("position", s.position).asInt();
        s.pathPrefix = b.get("path_prefix", s.pathPrefix).asString();
        s.stripPrefix = b.get("strip_prefix", s.stripPrefix).asBool();
        s.kind = b.get("kind", s.kind).asString();
        s.redirectTo = b.get("redirect_to", s.redirectTo).asString();
        s.upstreamTls = b.get("upstream_tls", s.upstreamTls).asInt();
        s.hostHeader = b.get("host_header", s.hostHeader).asString();
        s.timeout = b.get("timeout", s.timeout).asInt();
        s.internal = b.get("internal", s.internal).asBool();
        s.external = b.get("external", s.external).asBool();
        if (b.isMember("public_paths")) {
            s.publicPaths.clear();
            for (const auto& p : b["public_paths"])
                if (!p.asString().empty())
                    s.publicPaths.push_back(p.asString());
        }
        if (b.isMember("node_id")) {
            const auto nid = b["node_id"].asInt64();
            s.nodeId = nid > 0 ? std::optional<std::int64_t>(nid) : std::nullopt;
        }
        std::string upstream = b.get("upstream", "").asString();
        if (upstream.empty() && b.isMember("port") && s.nodeId) {
            auto n = findNode(*db_, *s.nodeId);
            if (!n || n->meshAddress.empty())
                return cb(
                    error(drogon::k400BadRequest,
                          "노드의 메시 주소를 아직 모릅니다. 업스트림 주소를 직접 입력하세요"));
            upstream = n->meshAddress + ":" + std::to_string(b["port"].asInt());
        }
        if (!upstream.empty())
            s.upstream = upstream;
        if (s.nodeId && !findNode(*db_, *s.nodeId))
            return cb(error(drogon::k400BadRequest, "노드를 찾을 수 없습니다"));
        if (!acc.admin()) {
            // 운영자는 허락된 서버 자신의 포트만 연결할 수 있다 (다른 서버·Hub·외부 주소를
            // 업스트림으로 지정해 공개하는 것을 막는다)
            auto n = s.nodeId && acc.node(*s.nodeId) ? findNode(*db_, *s.nodeId) : std::nullopt;
            if (!n)
                return cb(
                    error(drogon::k403Forbidden, "허락된 서버의 서비스만 관리할 수 있습니다"));
            if (s.kind != "proxy")
                return cb(
                    error(drogon::k403Forbidden, "운영자는 프록시 서비스만 만들 수 있습니다"));
            if (!upstreamOnNode(s.upstream, *n))
                return cb(error(drogon::k403Forbidden,
                                "운영자는 이 서버의 포트만 연결할 수 있습니다 (메시 주소:포트)"));
        }
        if (auto err = validateService(s, hostOfUrl(cfg_.publicUrl)); !err.empty())
            return cb(error(drogon::k400BadRequest, err));
        std::string err;
        if (create) {
            auto c = createService(*db_, s, t, err);
            if (!c)
                return cb(error(drogon::k409Conflict, err));
            s = *c;
        } else if (!updateService(*db_, s, t, err)) {
            return cb(error(drogon::k409Conflict, err));
        }
        audit(*db_, sess->userId, create ? "service_created" : "service_updated", clientIp(req),
              s.name + " " + s.host + " → " + s.upstream + " (" + s.auth +
                  (s.internal ? ", 내부" : "") + (s.external ? ", 외부" : "") + ")",
              t);
        pushRoutes();
        Json::Value v;
        v["ok"] = true;
        v["id"] = Json::Int64(s.id);
        cb(json(v));
    };
    app.registerHandler(
        "/api/services/create",
        [upsert](const HttpRequestPtr& req, Callback&& cb) { upsert(req, std::move(cb), true); },
        {drogon::Post});
    app.registerHandler(
        "/api/services/update",
        [upsert](const HttpRequestPtr& req, Callback&& cb) { upsert(req, std::move(cb), false); },
        {drogon::Post});

    app.registerHandler(
        "/api/services/delete",
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
            auto s = body ? findService(*db_, (*body).get("id", 0).asInt64()) : std::nullopt;
            // 지우는 것은 관리자나 그 서버의 운영자만 (따로 허락된 앱 사용자는 못 지움)
            if (s && !access(*sess).admin() && !(s->nodeId && access(*sess).node(*s->nodeId)))
                s.reset();
            if (!s || !deleteService(*db_, s->id))
                return cb(error(drogon::k404NotFound, "서비스를 찾을 수 없습니다"));
            {
                std::lock_guard lk(healthMu_);
                health_.erase(s->id);
            }
            audit(*db_, sess->userId, "service_deleted", clientIp(req), s->name + " " + s->host, t);
            pushRoutes();
            Json::Value v;
            v["ok"] = true;
            cb(json(v));
        },
        {drogon::Post});

    // 서버 연결 방식 (auto | direct | tunnel)
    app.registerHandler(
        "/api/nodes/connect",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            const auto t = now();
            auto sess = currentSession(req, t);
            if (!sess)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            auto body = req->getJsonObject();
            const std::int64_t id = body ? (*body).get("id", 0).asInt64() : 0;
            const std::string mode = body ? (*body).get("mode", "").asString() : "";
            auto n = findNode(*db_, id);
            if (!n || !setNodeConnectMode(*db_, id, mode))
                return cb(error(drogon::k400BadRequest, "노드 또는 연결 방식이 올바르지 않습니다"));
            audit(*db_, sess->userId, "node_connect_mode", clientIp(req), n->name + " " + mode, t);
            pushRoutes();
            Json::Value v;
            v["ok"] = true;
            cb(json(v));
        },
        {drogon::Post});

    // 입구(edge) 역할 지정/해제
    app.registerHandler("/api/nodes/edge",
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
                            const bool edge = body && (*body).get("edge", false).asBool();
                            auto n = findNode(*db_, id);
                            if (!n || !setNodeEdge(*db_, id, edge))
                                return cb(error(drogon::k404NotFound, "노드를 찾을 수 없습니다"));
                            refreshEdgeAddresses();
                            audit(*db_, sess->userId, edge ? "edge_enabled" : "edge_disabled",
                                  clientIp(req), n->name, t);
                            if (edge) {
                                pushRoutes(id);
                            } else {
                                Json::Value off;
                                off["type"] = "routes";
                                off["disabled"] = true;
                                off["routes"] = Json::Value(Json::arrayValue);
                                gateway_->send(id, off);
                            }
                            Json::Value v;
                            v["ok"] = true;
                            cb(json(v));
                        },
                        {drogon::Post});
}

} // namespace douve
