// 파일 올리기·내려받기 API: 서명할 작업 → 패스키 서명 확인 → 1회용 티켓 → /api/files/ws
// (cluster/files.h).

#include "app.h"
#include "cluster/files.h"
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

namespace douve {

using drogon::HttpRequestPtr;
using drogon::HttpResponsePtr;
using http::error;
using http::json;
using Callback = std::function<void(const HttpResponsePtr&)>;

namespace {

constexpr std::int64_t kMaxFile = 100LL * 1024 * 1024; // Agent files.MaxSize와 같다

std::string compact(const Json::Value& v) {
    Json::StreamWriterBuilder w;
    w["indentation"] = "";
    return Json::writeString(w, v);
}

bool lowerHex64(const std::string& s) {
    if (s.size() != 64)
        return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    return true;
}

} // namespace

void HubApp::registerFileRoutes() {
    auto& app = drogon::app();
    files_ = std::make_shared<FileGateway>(*this);
    app.registerController(files_);

    // 1) 서명할 작업 (이 서버·계정·경로, 올리기면 크기·SHA-256까지). 터미널과 같은 권한·패스키.
    app.registerHandler(
        "/api/files/options",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            const auto t = now();
            auto s = currentSession(req, t);
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            if (!settings_.features().terminal)
                return cb(error(drogon::k403Forbidden, "웹 터미널이 꺼져 있습니다 (설정 → 기능)"));
            auto body = req->getJsonObject();
            if (!body)
                return cb(error(drogon::k400BadRequest, "JSON 본문이 필요합니다"));
            const std::int64_t nodeId = jsonInt(*body, "node_id");
            auto n = access(*s).node(nodeId) ? findNode(*db_, nodeId) : std::nullopt;
            if (!n)
                return cb(error(drogon::k404NotFound, "노드를 찾을 수 없습니다"));
            if (!live_.connected(n->id))
                return cb(error(drogon::k409Conflict, "서버가 Douve에 접속해 있지 않습니다"));
            const std::string op = jsonStr(*body, "op");
            const std::string user = jsonStr(*body, "user");
            const std::string path = jsonStr(*body, "path");
            if (op != "put" && op != "get")
                return cb(error(drogon::k400BadRequest, "잘못된 요청"));
            if (!validTransferPath(path))
                return cb(error(drogon::k400BadRequest, "잘못된 경로"));
            auto inv = live_.inventory(n->id);
            bool allowed = false;
            if (inv)
                for (const auto& u : (*inv)["terminal_users"])
                    allowed = allowed || u.asString() == user;
            if (!allowed)
                return cb(
                    error(drogon::k403Forbidden, "이 서버에서 터미널을 열 수 없는 계정입니다"));
            Json::Value p;
            std::string action = fileGetAction(user, path);
            if (op == "put") {
                const std::int64_t size = jsonInt(*body, "size", -1);
                const std::string sha = jsonStr(*body, "sha256");
                if (size < 0 || size > kMaxFile)
                    return cb(error(drogon::k400BadRequest, "파일은 100MB까지입니다"));
                if (!lowerHex64(sha))
                    return cb(error(drogon::k400BadRequest, "잘못된 SHA-256"));
                action = filePutAction(user, size, sha, path);
                p["size"] = Json::Int64(size);
                p["sha256"] = sha;
            }
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
            p["node_id"] = Json::Int64(n->id);
            p["node_name"] = n->name;
            p["op"] = op;
            p["user"] = user;
            p["path"] = path;
            p["user_id"] = Json::Int64(s->userId);
            p["ts"] = Json::Int64(t);
            p["nonce"] = randomToken(18);
            p["action"] = action;
            Json::Value v;
            v["pending"] = putPending(*db_, "fileauth", compact(p), 120, t);
            auto& pk = v["publicKey"];
            pk["challenge"] = base64UrlEncode(
                sha256(serverActionStatement(n->id, action, t, p["nonce"].asString())));
            pk["rpId"] = cfg_.effectiveRpId();
            pk["timeout"] = 60000;
            pk["userVerification"] = "required";
            pk["allowCredentials"] = creds;
            cb(json(v));
        },
        {drogon::Post});

    // 2) 서명 확인 → 1회용 티켓 (서명은 Agent에 그대로 전달)
    app.registerHandler(
        "/api/files/ticket",
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
            auto payload = takePending(*db_, (*body).get("pending", "").asString(), "fileauth", t);
            Json::Value p;
            if (!payload || !parseJson(*payload, p) || jsonInt(p, "user_id") != s->userId)
                return cb(error(drogon::k400BadRequest, "만료된 요청입니다. 다시 시도하세요"));
            if (!access(*s).node(jsonInt(p, "node_id")))
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
            const std::string nonce = jsonStr(p, "nonce");
            webauthn::Expectations exp{
                sha256(serverActionStatement(jsonInt(p, "node_id"), jsonStr(p, "action"),
                                             jsonInt(p, "ts"), nonce)),
                cfg_.origin(), cfg_.effectiveRpId(), true};
            std::string err;
            auto res = webauthn::verifyAssertion(*clientData, *authData, *sig, key->publicKeyCose,
                                                 key->signCount, exp, err);
            if (!res) {
                audit(*db_, s->userId, "reauth_failed", clientIp(req), "file: " + err, t);
                return cb(error(drogon::k401Unauthorized, "패스키 확인 실패"));
            }
            updatePasskeyUse(*db_, key->id, res->signCount, t);
            Json::Value& a = p["auth"];
            a["ts"] = p["ts"];
            a["nonce"] = nonce;
            a["id"] = base64UrlEncode(*credId);
            a["client_data"] = base64UrlEncode(*clientData);
            a["auth_data"] = base64UrlEncode(*authData);
            a["sig"] = base64UrlEncode(*sig);
            Json::Value v;
            v["ticket"] = putPending(*db_, "file", compact(p), 60, t);
            cb(json(v));
        },
        {drogon::Post});
}

} // namespace douve
