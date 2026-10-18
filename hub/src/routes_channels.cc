// 알림 채널 API: 목록(비밀은 일부만), 추가·삭제·켜고 끄기(패스키 재확인), 테스트 발송.

#include "app.h"
#include "cluster/channels.h"
#include "http_util.h"
#include "store/repo.h"
#include "util/i18n.h"

#include <drogon/drogon.h>

namespace douve {

using drogon::HttpRequestPtr;
using drogon::HttpResponsePtr;
using http::error;
using http::json;
using Callback = std::function<void(const HttpResponsePtr&)>;

void HubApp::registerChannelRoutes() {
    auto& app = drogon::app();

    app.registerHandler("/api/channels",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            if (!currentSession(req, now()))
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            Json::Value arr(Json::arrayValue);
                            for (const auto& c : listChannels(*db_))
                                arr.append(channelJson(c));
                            Json::Value v;
                            v["channels"] = arr;
                            cb(json(v));
                        },
                        {drogon::Get});

    // 바꾸는 요청 공통: 출처·로그인·재확인
    auto guard = [this](const HttpRequestPtr& req, std::optional<SessionInfo>& sess,
                        std::string& err) -> drogon::HttpStatusCode {
        if (!sameOrigin(req)) {
            err = "잘못된 요청 출처";
            return drogon::k403Forbidden;
        }
        sess = currentSession(req, now());
        if (!sess) {
            err = "로그인이 필요합니다";
            return drogon::k401Unauthorized;
        }
        if (!sessions_->reauthFresh(*sess, now())) {
            err = "reauth_required";
            return drogon::k403Forbidden;
        }
        return drogon::k200OK;
    };

    app.registerHandler("/api/channels/create",
                        [this, guard](const HttpRequestPtr& req, Callback&& cb) {
                            std::optional<SessionInfo> sess;
                            std::string err;
                            if (auto code = guard(req, sess, err); code != drogon::k200OK)
                                return cb(error(code, err));
                            auto body = req->getJsonObject();
                            if (!body)
                                return cb(error(drogon::k400BadRequest, "JSON 본문이 필요합니다"));
                            Channel c;
                            c.kind = (*body).get("kind", "").asString();
                            c.name = (*body).get("name", "").asString();
                            c.config = (*body)["config"];
                            if (auto why = validateChannel(c); !why.empty())
                                return cb(error(drogon::k400BadRequest, why));
                            const auto t = now();
                            c.id = createChannel(*db_, c, t);
                            audit(*db_, sess->userId, "channel_created", clientIp(req),
                                  c.kind + " " + c.name, t);
                            Json::Value v;
                            v["ok"] = true;
                            v["channel"] = channelJson(c);
                            cb(json(v));
                            if (sendsAudit(c)) // 밀린 기록을 30초 기다리지 않고 바로
                                sendAuditBatch(c.id);
                        },
                        {drogon::Post});

    app.registerHandler(
        "/api/channels/delete",
        [this, guard](const HttpRequestPtr& req, Callback&& cb) {
            std::optional<SessionInfo> sess;
            std::string err;
            if (auto code = guard(req, sess, err); code != drogon::k200OK)
                return cb(error(code, err));
            auto body = req->getJsonObject();
            auto c = body ? findChannel(*db_, (*body).get("id", 0).asInt64()) : std::nullopt;
            if (!c || !deleteChannel(*db_, c->id))
                return cb(error(drogon::k404NotFound, "알림 채널을 찾을 수 없습니다"));
            audit(*db_, sess->userId, "channel_deleted", clientIp(req), c->kind + " " + c->name,
                  now());
            Json::Value v;
            v["ok"] = true;
            cb(json(v));
        },
        {drogon::Post});

    app.registerHandler(
        "/api/channels/toggle",
        [this, guard](const HttpRequestPtr& req, Callback&& cb) {
            std::optional<SessionInfo> sess;
            std::string err;
            if (auto code = guard(req, sess, err); code != drogon::k200OK)
                return cb(error(code, err));
            auto body = req->getJsonObject();
            auto c = body ? findChannel(*db_, (*body).get("id", 0).asInt64()) : std::nullopt;
            const bool on = body && (*body).get("enabled", false).asBool();
            if (!c || !setChannelEnabled(*db_, c->id, on))
                return cb(error(drogon::k404NotFound, "알림 채널을 찾을 수 없습니다"));
            audit(*db_, sess->userId, on ? "channel_enabled" : "channel_disabled", clientIp(req),
                  c->kind + " " + c->name, now());
            Json::Value v;
            v["ok"] = true;
            cb(json(v));
        },
        {drogon::Post});

    // 테스트 발송: 결과(상태 코드)를 그대로 알려 준다
    app.registerHandler(
        "/api/channels/test",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            if (!currentSession(req, now()))
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            auto body = req->getJsonObject();
            auto c = body ? findChannel(*db_, (*body).get("id", 0).asInt64()) : std::nullopt;
            if (!c)
                return cb(error(drogon::k404NotFound, "알림 채널을 찾을 수 없습니다"));
            const std::string text =
                i18n::translate("✅ 테스트 알림입니다. 알림이 잘 연결되었습니다.", language());
            httpPostAsync(channelRequest(*c, text, now()), [cb = std::move(cb)](HttpResult r) {
                if (r.ok && r.status >= 200 && r.status < 300) {
                    Json::Value v;
                    v["ok"] = true;
                    return cb(json(v));
                }
                cb(error(drogon::k502BadGateway,
                         "발송 실패: " + (r.ok ? "HTTP " + std::to_string(r.status) : r.error)));
            });
        },
        {drogon::Post});
}

} // namespace douve
