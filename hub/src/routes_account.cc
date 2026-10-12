// 계정 관리 API: 내 패스키·세션 목록과 삭제. 삭제는 최근 재인증이 필요하다.

#include "app.h"
#include "http_util.h"
#include "store/passkeys.h"
#include "store/recovery.h"
#include "store/repo.h"

#include <drogon/drogon.h>

namespace douve {

using drogon::HttpRequestPtr;
using drogon::HttpResponsePtr;
using http::error;
using http::json;
using Callback = std::function<void(const HttpResponsePtr&)>;

void HubApp::registerAccountRoutes() {
    auto& app = drogon::app();

    // ---- 복구 코드 ----
    // 패스키·기기를 모두 잃었을 때: 코드 하나로 로그인 → (재인증 상태로) 새 패스키 등록
    app.registerHandler(
        "/auth/recovery",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            if (!loginAllowed(req))
                return cb(error(drogon::k429TooManyRequests,
                                "요청이 너무 많습니다. 잠시 후 다시 시도하세요"));
            auto body = req->getJsonObject();
            if (!body)
                return cb(error(drogon::k400BadRequest, "잘못된 요청"));
            const auto t = now();
            const std::string ip = clientIp(req);
            auto userId = useRecoveryCode(*db_, (*body).get("code", "").asString(), t);
            auto user = userId ? findUserById(*db_, *userId) : std::nullopt;
            if (!user || !emailAllowed(user->email)) {
                audit(*db_, userId, "recovery_failed", ip, "", t);
                return cb(
                    error(drogon::k401Unauthorized, "복구 코드가 맞지 않거나 이미 사용되었습니다"));
            }
            const int left = recoveryStatus(*db_, user->id).remaining;
            audit(*db_, user->id, "recovery_login", ip, "남은 코드 " + std::to_string(left), t);
            notify("🔑 복구 코드로 로그인: " + user->email + " (" + ip + ", 남은 코드 " +
                   std::to_string(left) +
                   "개). 본인이 아니면 즉시 복구 코드를 새로 만들고 "
                   "세션을 정리하세요.");
            Json::Value v;
            v["ok"] = true;
            v["remaining"] = left;
            auto r = json(v);
            startSession(req, r, user->id, "recovery");
            r->addHeader("Cache-Control", "no-store");
            cb(r);
        },
        {drogon::Post});

    app.registerHandler("/api/account/recovery",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            auto s = currentSession(req, now());
                            if (!s)
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            const auto st = recoveryStatus(*db_, s->userId);
                            Json::Value v;
                            v["remaining"] = st.remaining;
                            v["created_at"] = Json::Int64(st.createdAt);
                            v["total"] = kRecoveryCodeCount;
                            cb(json(v));
                        },
                        {drogon::Get});

    // 새로 만들기: 기존 코드는 모두 무효. 비상 로그인 수단을 바꾸는 일이라 재인증 필요.
    app.registerHandler("/api/account/recovery/generate",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            if (!sameOrigin(req))
                                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
                            const auto t = now();
                            auto s = currentSession(req, t);
                            if (!s)
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            if (!sessions_->reauthFresh(*s, t))
                                return cb(error(drogon::k403Forbidden, "reauth_required"));
                            auto codes = generateRecoveryCodes(*db_, s->userId, t);
                            audit(*db_, s->userId, "recovery_codes_created", clientIp(req), "web",
                                  t);
                            Json::Value v;
                            v["codes"] = Json::Value(Json::arrayValue);
                            for (const auto& c : codes)
                                v["codes"].append(c);
                            auto r = json(v);
                            r->addHeader("Cache-Control", "no-store");
                            cb(r);
                        },
                        {drogon::Post});

    app.registerHandler("/api/passkeys",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            auto s = currentSession(req, now());
                            if (!s)
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            Json::Value arr(Json::arrayValue);
                            for (const auto& k : listPasskeys(*db_, s->userId)) {
                                Json::Value v;
                                v["id"] = Json::Int64(k.id);
                                v["name"] = k.name;
                                v["created_at"] = Json::Int64(k.createdAt);
                                v["last_used_at"] = k.lastUsedAt
                                                        ? Json::Value(Json::Int64(*k.lastUsedAt))
                                                        : Json::Value();
                                v["transports"] = k.transports;
                                arr.append(v);
                            }
                            Json::Value out;
                            out["passkeys"] = arr;
                            cb(json(out));
                        },
                        {drogon::Get});

    app.registerHandler("/api/passkeys/delete",
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
                            if (!body ||
                                !deletePasskey(*db_, s->userId, (*body).get("id", 0).asInt64()))
                                return cb(error(drogon::k404NotFound, "패스키를 찾을 수 없습니다"));
                            audit(*db_, s->userId, "passkey_deleted", clientIp(req),
                                  std::to_string((*body)["id"].asInt64()), t);
                            Json::Value v;
                            v["ok"] = true;
                            cb(json(v));
                        },
                        {drogon::Post});

    app.registerHandler(
        "/api/passkeys/rename",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            auto s = currentSession(req, now());
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            auto body = req->getJsonObject();
            std::string name = body ? (*body).get("name", "").asString().substr(0, 60) : "";
            if (name.empty() ||
                !renamePasskey(*db_, s->userId, (*body).get("id", 0).asInt64(), name))
                return cb(error(drogon::k400BadRequest, "이름을 바꿀 수 없습니다"));
            Json::Value v;
            v["ok"] = true;
            cb(json(v));
        },
        {drogon::Post});

    app.registerHandler("/api/sessions",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            const auto t = now();
                            auto s = currentSession(req, t);
                            if (!s)
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            const auto currentHint = s->idHint;
                            Json::Value arr(Json::arrayValue);
                            for (const auto& x : sessions_->listForUser(s->userId, t)) {
                                Json::Value v;
                                v["hint"] = x.idHint;
                                v["current"] = x.idHint == currentHint;
                                v["auth_method"] = x.authMethod;
                                v["created_at"] = Json::Int64(x.createdAt);
                                v["last_seen_at"] = Json::Int64(x.lastSeenAt);
                                v["ip"] = x.ip;
                                v["user_agent"] = x.userAgent;
                                arr.append(v);
                            }
                            Json::Value out;
                            out["sessions"] = arr;
                            cb(json(out));
                        },
                        {drogon::Get});

    app.registerHandler("/api/sessions/revoke",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            if (!sameOrigin(req))
                                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
                            const auto t = now();
                            auto s = currentSession(req, t);
                            if (!s)
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            auto body = req->getJsonObject();
                            const std::string hint = body ? (*body).get("hint", "").asString() : "";
                            if (hint == "all") {
                                sessions_->revokeAllForUser(s->userId);
                            } else {
                                sessions_->revokeByHint(s->userId, hint);
                            }
                            audit(*db_, s->userId, "session_revoked", clientIp(req), hint, t);
                            Json::Value v;
                            v["ok"] = true;
                            cb(json(v));
                        },
                        {drogon::Post});
}

} // namespace douve
