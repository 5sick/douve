// 내부 길(기기 WireGuard) API: 내 기기 등록·삭제, 설정(관리자), 입구로 보낼 설정 만들기.

#include "app.h"
#include "cluster/gateway.h"
#include "http_util.h"
#include "store/devnet.h"
#include "store/nodes.h"
#include "store/repo.h"
#include "store/services.h"
#include "util/json.h"

#include <drogon/drogon.h>

#include <algorithm>

namespace douve {

using drogon::HttpRequestPtr;
using drogon::HttpResponsePtr;
using http::error;
using http::json;
using Callback = std::function<void(const HttpResponsePtr&)>;

namespace {

std::string hostOf(const std::string& url) {
    auto start = url.find("://");
    start = start == std::string::npos ? 0 : start + 3;
    auto end = url.find_first_of(":/", start);
    return url.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

std::string hostPortOf(const std::string& url) {
    auto start = url.find("://");
    start = start == std::string::npos ? 0 : start + 3;
    auto end = url.find('/', start);
    return url.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

} // namespace

std::optional<Node> HubApp::devnetGateway() {
    std::optional<Node> best;
    for (const auto& n : listNodes(*db_))
        if (n.edge && (!best || n.id < best->id))
            best = n;
    return best;
}

Json::Value HubApp::buildDevnet() {
    const auto st = loadDevnet(*db_);
    if (!st.enabled)
        return Json::Value();
    Json::Value d;
    d["listen_port"] = st.port;
    d["address"] = kDevnetAddress;
    d["routes"] = Json::Value(Json::arrayValue);
    // Hub 자신도 내부 길로 (연결된 기기에서 Douve 화면이 입구 내부 주소로 열린다. 로그인은 그대로)
    Json::Value hub;
    hub["host"] = hostOf(cfg_.publicUrl);
    hub["upstream"] = hostPortOf(cfg_.effectiveInternalUrl());
    hub["auth"] = "hub";
    hub["public_paths"] = Json::Value(Json::arrayValue);
    d["routes"].append(hub);
    std::vector<Service> internal;
    for (const auto& s : listServices(*db_))
        if (s.internal) {
            internal.push_back(s);
            d["routes"].append(routeJson(s));
        }
    d["peers"] = Json::Value(Json::arrayValue);
    std::map<std::int64_t, Json::Value> byUser; // 사용자별 권한 (기기마다 다시 계산하지 않게)
    for (const auto& dev : listDevices(*db_)) {
        auto it = byUser.find(dev.userId);
        if (it == byUser.end()) {
            auto u = findUserById(*db_, dev.userId);
            if (!u)
                continue;
            auto acc = loadAccess(*db_, u->id);
            const bool admin =
                acc.admin() || std::find(cfg_.allowedEmails.begin(), cfg_.allowedEmails.end(),
                                         u->email) != cfg_.allowedEmails.end();
            Json::Value p;
            p["user"] = u->email;
            if (admin) {
                p["all"] = true;
            } else {
                p["services"] = Json::Value(Json::arrayValue);
                for (const auto& s : internal)
                    if (acc.service(s.id, s.nodeId))
                        p["services"].append(Json::Int64(s.id));
            }
            it = byUser.emplace(dev.userId, p).first;
        }
        Json::Value p = it->second;
        p["pubkey"] = dev.pubkey;
        p["ip"] = dev.ip;
        d["peers"].append(p);
    }
    return d;
}

void HubApp::ingestDevnetStatus(std::int64_t nodeId, const Json::Value& msg) {
    auto gw = devnetGateway();
    if (!gw || gw->id != nodeId)
        return;
    const std::string key = jsonStr(msg, "pubkey");
    auto st = loadDevnet(*db_);
    if (validWgKey(key) && (key != st.gatewayKey || st.gatewayNode != nodeId)) {
        if (!st.gatewayKey.empty() && key != st.gatewayKey)
            LOG_WARN << "내부 길 입구 키가 바뀜 — 이미 등록한 기기는 다시 등록해야 합니다";
        st.gatewayKey = key;
        st.gatewayNode = nodeId;
        saveDevnet(*db_, st, now());
    }
    std::lock_guard lk(devnetMu_);
    devnetRunning_ = msg.get("running", false).asBool();
    devnetPeers_.clear();
    for (const auto& p : msg["peers"])
        devnetPeers_[p.get("pubkey", "").asString()] = p;
}

void HubApp::registerDevnetRoutes() {
    auto& app = drogon::app();

    auto deviceJson = [this](const Device& d, const std::string& email) {
        Json::Value v;
        v["id"] = Json::Int64(d.id);
        v["name"] = d.name;
        v["ip"] = d.ip;
        v["user"] = email;
        v["created_at"] = Json::Int64(d.createdAt);
        std::lock_guard lk(devnetMu_);
        if (auto it = devnetPeers_.find(d.pubkey); it != devnetPeers_.end()) {
            v["last_handshake"] = it->second.get("last_handshake", 0);
            v["rx"] = it->second.get("rx", 0);
            v["tx"] = it->second.get("tx", 0);
        }
        return v;
    };

    auto status = [this]() {
        const auto st = loadDevnet(*db_);
        auto gw = devnetGateway();
        Json::Value v;
        v["enabled"] = st.enabled;
        v["port"] = st.port;
        v["endpoint"] = st.endpoint;
        v["endpoint_default"] = hostOf(cfg_.publicUrl);
        v["gateway"] = gw ? Json::Value(gw->name) : Json::Value();
        v["gateway_connected"] = gw && live_.connected(gw->id);
        v["ready"] = st.enabled && gw && !st.gatewayKey.empty() && st.gatewayNode == gw->id;
        {
            std::lock_guard lk(devnetMu_);
            v["running"] = devnetRunning_;
        }
        v["address"] = kDevnetAddress;
        return v;
    };

    app.registerHandler("/api/devices",
                        [this, deviceJson, status](const HttpRequestPtr& req, Callback&& cb) {
                            auto s = currentSession(req, now());
                            if (!s)
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            const bool admin = access(*s).admin();
                            std::map<std::int64_t, std::string> emails;
                            Json::Value arr(Json::arrayValue);
                            for (const auto& d :
                                 admin ? listDevices(*db_) : listDevicesOf(*db_, s->userId)) {
                                if (!emails.contains(d.userId)) {
                                    auto u = findUserById(*db_, d.userId);
                                    emails[d.userId] = u ? u->email : "";
                                }
                                auto v = deviceJson(d, emails[d.userId]);
                                v["mine"] = d.userId == s->userId;
                                arr.append(v);
                            }
                            Json::Value out;
                            out["devices"] = arr;
                            out["devnet"] = status();
                            out["admin"] = admin;
                            cb(json(out));
                        },
                        {drogon::Get});

    // 기기 추가: 키를 여기서 만들고 설정(개인키 포함)은 이 응답에서 한 번만 보여 준다. DB에는
    // 공개키만.
    app.registerHandler(
        "/api/devices/create",
        [this, deviceJson](const HttpRequestPtr& req, Callback&& cb) {
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            const auto t = now();
            auto s = currentSession(req, t);
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            if (!sessions_->reauthFresh(*s, t))
                return cb(error(drogon::k403Forbidden, "reauth_required"));
            auto body = req->getJsonObject();
            if (!body)
                return cb(error(drogon::k400BadRequest, "JSON 본문이 필요합니다"));
            const auto st = loadDevnet(*db_);
            auto gw = devnetGateway();
            if (!st.enabled || !gw || st.gatewayKey.empty() || st.gatewayNode != gw->id)
                return cb(error(drogon::k409Conflict, "내부 길이 아직 준비되지 않았습니다 (설정 → "
                                                      "내부 길)"));
            const auto keys = generateWgKeyPair();
            std::string err;
            auto d = createDevice(*db_, s->userId, (*body).get("name", "").asString(),
                                  keys.publicKey, t, err);
            if (!d)
                return cb(error(drogon::k400BadRequest, err));
            audit(*db_, s->userId, "device_added", clientIp(req), d->name + " " + d->ip, t);
            pushRoutes(gw->id);
            Json::Value v;
            v["device"] = deviceJson(*d, s->email);
            v["config"] = deviceConfig(st, hostOf(cfg_.publicUrl), keys.privateKey, d->ip);
            cb(json(v));
        },
        {drogon::Post});

    app.registerHandler(
        "/api/devices/delete",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            const auto t = now();
            auto s = currentSession(req, t);
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            auto body = req->getJsonObject();
            auto d = body ? findDevice(*db_, (*body).get("id", 0).asInt64()) : std::nullopt;
            if (d && d->userId != s->userId && !access(*s).admin())
                d.reset();
            if (!d)
                return cb(error(drogon::k404NotFound, "기기를 찾을 수 없습니다"));
            deleteDevice(*db_, d->id);
            audit(*db_, s->userId, "device_removed", clientIp(req), d->name + " " + d->ip, t);
            pushRoutes();
            Json::Value v;
            v["ok"] = true;
            cb(json(v));
        },
        {drogon::Post});

    // 설정 (관리자): 켜기, UDP 포트, 기기가 접속할 주소
    app.registerHandler("/api/devnet",
                        [this, status](const HttpRequestPtr& req, Callback&& cb) {
                            if (!currentSession(req, now()))
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            Json::Value v = status();
                            v["devices"] = Json::UInt64(listDevices(*db_).size());
                            cb(json(v));
                        },
                        {drogon::Get});

    app.registerHandler("/api/devnet/update",
                        [this, status](const HttpRequestPtr& req, Callback&& cb) {
                            if (!sameOrigin(req))
                                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
                            const auto t = now();
                            auto s = currentSession(req, t);
                            if (!s)
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            if (!sessions_->reauthFresh(*s, t))
                                return cb(error(drogon::k403Forbidden, "reauth_required"));
                            auto body = req->getJsonObject();
                            if (!body)
                                return cb(error(drogon::k400BadRequest, "JSON 본문이 필요합니다"));
                            auto st = loadDevnet(*db_);
                            st.enabled = (*body).get("enabled", st.enabled).asBool();
                            st.port = (*body).get("port", st.port).asInt();
                            st.endpoint = (*body).get("endpoint", st.endpoint).asString();
                            if (auto err = validateDevnet(st); !err.empty())
                                return cb(error(drogon::k400BadRequest, err));
                            saveDevnet(*db_, st, t);
                            audit(*db_, s->userId, "devnet_updated", clientIp(req),
                                  std::string(st.enabled ? "켬" : "끔") + " udp " +
                                      std::to_string(st.port) +
                                      (st.endpoint.empty() ? "" : " " + st.endpoint),
                                  t);
                            pushRoutes();
                            cb(json(status()));
                        },
                        {drogon::Post});
}

} // namespace douve
