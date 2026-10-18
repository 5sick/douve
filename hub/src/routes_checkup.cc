// 보안 점검표 API: 서버별 마지막 점검 결과, 다시 점검, 고치기(패스키 서명 → Agent가 직접 확인 후
// 실행).

#include "app.h"
#include "cluster/gateway.h"
#include "cluster/term_trust.h"
#include "http_util.h"
#include "store/nodes.h"
#include "store/passkeys.h"
#include "store/repo.h"
#include "util/crypto.h"
#include "util/encoding.h"
#include "util/json.h"
#include "webauthn/webauthn.h"

#include <drogon/drogon.h>

#include <set>

namespace douve {

using drogon::HttpRequestPtr;
using drogon::HttpResponsePtr;
using http::error;
using http::json;
using Callback = std::function<void(const HttpResponsePtr&)>;

namespace {

// Agent의 checkup.Fixable과 같아야 한다
const std::set<std::string> kFixable = {"ssh_password", "ssh_root", "auto_updates", "time_sync"};

std::string compact(const Json::Value& v) {
    Json::StreamWriterBuilder w;
    w["indentation"] = "";
    return Json::writeString(w, v);
}

std::optional<Json::Value> loadCheckup(Database& db, std::int64_t nodeId) {
    auto guard = db.lock();
    Statement q(db, "SELECT results, checked_at FROM checkups WHERE node_id = ?");
    q.bind(1, nodeId);
    if (!q.step())
        return std::nullopt;
    Json::Value v;
    if (!parseJson(q.text(0), v["results"]))
        v["results"] = Json::Value(Json::arrayValue);
    v["checked_at"] = Json::Int64(q.int64(1));
    return v;
}

} // namespace

void HubApp::ingestCheckup(std::int64_t nodeId, const Json::Value& msg) {
    Json::Value results(Json::arrayValue);
    for (const auto& r : msg["results"]) {
        if (!r.isObject() || results.size() >= 50)
            continue;
        Json::Value v;
        v["id"] = jsonStr(r, "id").substr(0, 40);
        v["status"] = jsonStr(r, "status").substr(0, 10);
        v["fixable"] = r.get("fixable", false).asBool() && kFixable.contains(v["id"].asString());
        if (r["facts"].isObject())
            for (const auto& k : r["facts"].getMemberNames())
                if (k.size() <= 40)
                    v["facts"][k] = r["facts"][k].asString().substr(0, 500);
        if (r.isMember("error"))
            v["error"] = jsonStr(r, "error").substr(0, 300);
        results.append(v);
    }
    auto guard = db_->lock();
    Statement(*db_, "INSERT INTO checkups (node_id, results, checked_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(node_id) DO UPDATE SET results = excluded.results, checked_at = "
                    "excluded.checked_at")
        .bind(1, nodeId)
        .bind(2, compact(results))
        .bind(3, now())
        .run();
}

void HubApp::ingestCheckupFixed(std::int64_t nodeId, const Json::Value& msg) {
    const std::string rid = jsonStr(msg, "rid");
    std::optional<std::int64_t> userId;
    std::string check;
    {
        std::lock_guard lk(fixMu_);
        auto it = fixes_.find(rid);
        if (it == fixes_.end() || jsonInt(it->second, "node_id") != nodeId)
            return; // 이 노드에 보낸 요청이 아니다
        auto& f = it->second;
        f["done"] = true;
        f["ok"] = msg.get("ok", false).asBool();
        f["message"] = jsonStr(msg, "message").substr(0, 300);
        f["error"] = jsonStr(msg, "error").substr(0, 300);
        userId = jsonInt(f, "user_id");
        check = jsonStr(f, "check");
    }
    auto n = findNode(*db_, nodeId);
    const bool ok = msg.get("ok", false).asBool();
    audit(*db_, userId, ok ? "checkup_fixed" : "checkup_fix_failed", "",
          (n ? n->name : std::to_string(nodeId)) + " " + check + " " +
              (ok ? jsonStr(msg, "message") : jsonStr(msg, "error")).substr(0, 200),
          now());
}

void HubApp::registerCheckupRoutes() {
    auto& app = drogon::app();

    app.registerHandler("/api/checkup",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            auto s = currentSession(req, now());
                            if (!s)
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            const auto acc = access(*s);
                            Json::Value arr(Json::arrayValue);
                            for (const auto& n : listNodes(*db_)) {
                                if (!acc.node(n.id))
                                    continue;
                                Json::Value v;
                                v["id"] = Json::Int64(n.id);
                                v["name"] = n.name;
                                v["connected"] = live_.connected(n.id);
                                if (auto c = loadCheckup(*db_, n.id)) {
                                    v["results"] = (*c)["results"];
                                    v["checked_at"] = (*c)["checked_at"];
                                }
                                arr.append(v);
                            }
                            Json::Value out;
                            out["nodes"] = arr;
                            cb(json(out));
                        },
                        {drogon::Get});

    app.registerHandler(
        "/api/checkup/run",
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
            m["type"] = "checkup_run";
            if (!gateway_->send(nodeId, m))
                return cb(error(drogon::k409Conflict, "서버가 Douve에 접속해 있지 않습니다"));
            Json::Value v;
            v["ok"] = true;
            cb(json(v));
        },
        {drogon::Post});

    // 고치기 1) 서명할 문장 (이 서버, 이 항목, 지금) — 터미널처럼 이 서버가 믿는 내 패스키만
    app.registerHandler(
        "/api/checkup/fix/options",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            const auto t = now();
            auto s = currentSession(req, t);
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            auto body = req->getJsonObject();
            if (!body)
                return cb(error(drogon::k400BadRequest, "JSON 본문이 필요합니다"));
            const std::int64_t nodeId = jsonInt(*body, "node_id");
            const std::string check = jsonStr(*body, "check");
            auto n = access(*s).node(nodeId) ? findNode(*db_, nodeId) : std::nullopt;
            if (!n)
                return cb(error(drogon::k404NotFound, "노드를 찾을 수 없습니다"));
            if (!kFixable.contains(check))
                return cb(error(drogon::k400BadRequest, "고칠 수 없는 항목입니다"));
            if (!live_.connected(n->id))
                return cb(error(drogon::k409Conflict, "서버가 Douve에 접속해 있지 않습니다"));
            const auto mine = listPasskeys(*db_, s->userId);
            if (mine.empty())
                return cb(error(drogon::k409Conflict, "passkey_required"));
            const auto trusted = trustKeyIds(trustState().snapshot, false, n->id);
            Json::Value creds(Json::arrayValue);
            for (const auto& k : mine) {
                const auto id = base64UrlEncode(k.credentialId);
                if (!trusted.contains(id))
                    continue;
                Json::Value d;
                d["type"] = "public-key";
                d["id"] = id;
                creds.append(d);
            }
            if (creds.empty())
                return cb(error(drogon::k409Conflict, "term_trust_missing"));
            Json::Value p;
            p["node_id"] = Json::Int64(n->id);
            p["check"] = check;
            p["user_id"] = Json::Int64(s->userId);
            p["ts"] = Json::Int64(t);
            p["nonce"] = randomToken(18);
            Json::Value v;
            v["pending"] = putPending(*db_, "checkfix", compact(p), 120, t);
            auto& pk = v["publicKey"];
            pk["challenge"] = base64UrlEncode(
                sha256(serverActionStatement(n->id, "fix:" + check, t, p["nonce"].asString())));
            pk["rpId"] = cfg_.effectiveRpId();
            pk["timeout"] = 60000;
            pk["userVerification"] = "required";
            pk["allowCredentials"] = creds;
            cb(json(v));
        },
        {drogon::Post});

    // 고치기 2) Hub도 서명을 확인하고 Agent에 그대로 넘긴다. 결과는 /api/checkup/fix/status로.
    app.registerHandler(
        "/api/checkup/fix",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!loginAllowed(req))
                return cb(error(drogon::k429TooManyRequests,
                                "요청이 너무 많습니다. 잠시 후 다시 시도하세요"));
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            const auto t = now();
            auto s = currentSession(req, t);
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            auto body = req->getJsonObject();
            if (!body)
                return cb(error(drogon::k400BadRequest, "JSON 본문이 필요합니다"));
            auto payload = takePending(*db_, (*body).get("pending", "").asString(), "checkfix", t);
            Json::Value p;
            if (!payload || !parseJson(*payload, p) || jsonInt(p, "user_id") != s->userId)
                return cb(error(drogon::k400BadRequest, "만료된 요청입니다. 다시 시도하세요"));
            const std::int64_t nodeId = jsonInt(p, "node_id");
            auto n = access(*s).node(nodeId) ? findNode(*db_, nodeId) : std::nullopt;
            if (!n)
                return cb(error(drogon::k404NotFound, "노드를 찾을 수 없습니다"));
            const auto& cred = (*body)["credential"];
            const auto& resp = cred["response"];
            auto dec = [](const Json::Value& v) {
                return v.isString() ? base64UrlDecode(v.asString()) : std::nullopt;
            };
            auto credId = dec(cred["id"]);
            auto clientData = dec(resp["clientDataJSON"]);
            auto authData = dec(resp["authenticatorData"]);
            auto sig = dec(resp["signature"]);
            if (!credId || !clientData || !authData || !sig)
                return cb(error(drogon::k400BadRequest, "잘못된 응답 형식"));
            auto key = findPasskeyByCredentialId(*db_, *credId);
            if (!key || key->userId != s->userId)
                return cb(error(drogon::k401Unauthorized, "내 패스키가 아닙니다"));
            const std::string check = jsonStr(p, "check");
            const std::string nonce = jsonStr(p, "nonce");
            webauthn::Expectations exp{
                sha256(serverActionStatement(nodeId, "fix:" + check, jsonInt(p, "ts"), nonce)),
                cfg_.origin(), cfg_.effectiveRpId(), true};
            std::string err;
            auto res = webauthn::verifyAssertion(*clientData, *authData, *sig, key->publicKeyCose,
                                                 key->signCount, exp, err);
            if (!res) {
                audit(*db_, s->userId, "reauth_failed", clientIp(req), "checkup fix: " + err, t);
                return cb(error(drogon::k401Unauthorized, "패스키 확인 실패"));
            }
            updatePasskeyUse(*db_, key->id, res->signCount, t);
            const std::string rid = randomToken(12);
            Json::Value m;
            m["type"] = "checkup_fix";
            m["rid"] = rid;
            m["check"] = check;
            m["auth"]["ts"] = p["ts"];
            m["auth"]["nonce"] = nonce;
            m["auth"]["id"] = base64UrlEncode(*credId);
            m["auth"]["client_data"] = base64UrlEncode(*clientData);
            m["auth"]["auth_data"] = base64UrlEncode(*authData);
            m["auth"]["sig"] = base64UrlEncode(*sig);
            {
                std::lock_guard lk(fixMu_);
                if (fixes_.size() > 500)
                    fixes_.clear();
                Json::Value f;
                f["node_id"] = Json::Int64(nodeId);
                f["user_id"] = Json::Int64(s->userId);
                f["check"] = check;
                f["done"] = false;
                fixes_[rid] = f;
            }
            if (!gateway_->send(nodeId, m))
                return cb(error(drogon::k409Conflict, "서버가 Douve에 접속해 있지 않습니다"));
            audit(*db_, s->userId, "checkup_fix_requested", clientIp(req), n->name + " " + check,
                  t);
            Json::Value v;
            v["rid"] = rid;
            cb(json(v));
        },
        {drogon::Post});

    app.registerHandler("/api/checkup/fix/status",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            auto s = currentSession(req, now());
                            if (!s)
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            std::lock_guard lk(fixMu_);
                            auto it = fixes_.find(req->getParameter("rid"));
                            if (it == fixes_.end() || jsonInt(it->second, "user_id") != s->userId)
                                return cb(error(drogon::k404NotFound, "요청을 찾을 수 없습니다"));
                            Json::Value v = it->second;
                            v.removeMember("user_id");
                            cb(json(v));
                        },
                        {drogon::Get});
}

} // namespace douve
