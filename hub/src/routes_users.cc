// 사용자·역할 API와 /api/* 공통 권한 검사.
// 경로별로 필요한 역할(store/access.h apiNeed)을 핸들러보다 먼저 확인한다. 서버·앱 단위 확인은
// 각 핸들러가 Access로 한다.

#include "app.h"
#include "http_util.h"
#include "store/access.h"
#include "store/nodes.h"
#include "store/repo.h"
#include "store/services.h"
#include "util/json.h"

#include <drogon/drogon.h>

namespace douve {

using drogon::HttpRequestPtr;
using drogon::HttpResponsePtr;
using http::error;
using http::json;
using Callback = std::function<void(const HttpResponsePtr&)>;

namespace {

std::set<std::int64_t> idSet(const Json::Value& a) {
    std::set<std::int64_t> out;
    if (a.isArray())
        for (const auto& v : a)
            if (v.isInt64() && out.size() < 1000)
                out.insert(v.asInt64());
    return out;
}

Json::Value idArray(const std::set<std::int64_t>& s) {
    Json::Value a(Json::arrayValue);
    for (auto id : s)
        a.append(Json::Int64(id));
    return a;
}

} // namespace

void HubApp::registerUserRoutes() {
    auto& app = drogon::app();

    app.registerPreHandlingAdvice([this](const HttpRequestPtr& req, drogon::AdviceCallback&& stop,
                                         drogon::AdviceChainCallback&& pass) {
        const std::string& path = req->path();
        if (path.rfind("/api/", 0) != 0)
            return pass();
        const auto need = apiNeed(path);
        if (!need)
            return pass();
        try {
            auto s = currentSession(req, now());
            if (!s)
                return pass(); // 핸들러가 401
            if (!satisfies(access(*s), *need))
                return stop(error(drogon::k403Forbidden, "권한이 없습니다"));
        } catch (const std::exception& e) {
            LOG_ERROR << "권한 확인 실패 " << path << ": " << e.what();
            return stop(error(drogon::k500InternalServerError, "서버 오류"));
        }
        pass();
    });

    // 바꾸는 요청 공통: 출처·로그인·재확인 (관리자 여부는 위 검사가 이미 함)
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

    app.registerHandler("/api/users",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            auto s = currentSession(req, now());
                            if (!s)
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            Json::Value arr(Json::arrayValue);
                            for (const auto& u : listUsers(*db_)) {
                                Json::Value v;
                                v["id"] = Json::Int64(u.id);
                                v["email"] = u.email;
                                v["role"] = roleName(u.access.role);
                                v["nodes"] = idArray(u.access.nodes);
                                v["services"] = idArray(u.access.services);
                                v["created_at"] = Json::Int64(u.createdAt);
                                v["last_login_at"] = u.lastLoginAt
                                                         ? Json::Value(Json::Int64(*u.lastLoginAt))
                                                         : Json::Value();
                                v["passkeys"] = u.passkeys;
                                v["me"] = u.id == s->userId;
                                arr.append(v);
                            }
                            Json::Value v;
                            v["users"] = arr;
                            cb(json(v));
                        },
                        {drogon::Get});

    app.registerHandler(
        "/api/users/update",
        [this, guard](const HttpRequestPtr& req, Callback&& cb) {
            std::optional<SessionInfo> sess;
            std::string err;
            if (auto code = guard(req, sess, err); code != drogon::k200OK)
                return cb(error(code, err));
            auto body = req->getJsonObject();
            if (!body || !body->isObject())
                return cb(error(drogon::k400BadRequest, "JSON 본문이 필요합니다"));
            const std::int64_t id = jsonInt(*body, "id");
            auto user = findUserById(*db_, id);
            if (!user)
                return cb(error(drogon::k404NotFound, "사용자를 찾을 수 없습니다"));
            auto role = parseRole(jsonStr(*body, "role"));
            if (!role)
                return cb(
                    error(drogon::k400BadRequest, "역할은 admin, operator, app 중 하나입니다"));
            // 없는 서버·서비스 id는 버린다
            std::set<std::int64_t> nodes, services;
            for (auto n : idSet((*body)["nodes"]))
                if (findNode(*db_, n))
                    nodes.insert(n);
            for (auto sv : idSet((*body)["services"]))
                if (findService(*db_, sv))
                    services.insert(sv);
            {
                auto lk = db_->lock();
                if (loadAccess(*db_, id).admin() && *role != Role::Admin && countAdmins(*db_) <= 1)
                    return cb(error(drogon::k409Conflict,
                                    "마지막 관리자는 바꿀 수 없습니다. 다른 관리자를 먼저 두세요"));
                setAccess(*db_, id, *role, nodes, services);
            }
            const auto a = loadAccess(*db_, id);
            std::string detail = user->email + " role=" + roleName(a.role);
            for (auto n : a.nodes)
                detail += " node:" + std::to_string(n);
            for (auto sv : a.services)
                detail += " service:" + std::to_string(sv);
            audit(*db_, sess->userId, "user_access_changed", clientIp(req), detail, now());
            pushRoutes(); // 내부 길의 기기 권한도 바뀐다
            Json::Value v;
            v["ok"] = true;
            v["role"] = roleName(a.role);
            v["nodes"] = idArray(a.nodes);
            v["services"] = idArray(a.services);
            cb(json(v));
        },
        {drogon::Post});

    app.registerHandler(
        "/api/users/delete",
        [this, guard](const HttpRequestPtr& req, Callback&& cb) {
            std::optional<SessionInfo> sess;
            std::string err;
            if (auto code = guard(req, sess, err); code != drogon::k200OK)
                return cb(error(code, err));
            auto body = req->getJsonObject();
            const std::int64_t id = body ? jsonInt(*body, "id") : 0;
            auto user = findUserById(*db_, id);
            if (!user)
                return cb(error(drogon::k404NotFound, "사용자를 찾을 수 없습니다"));
            if (id == sess->userId)
                return cb(error(drogon::k409Conflict, "자기 자신은 지울 수 없습니다"));
            {
                auto lk = db_->lock();
                if (loadAccess(*db_, id).admin() && countAdmins(*db_) <= 1)
                    return cb(error(drogon::k409Conflict, "마지막 관리자는 지울 수 없습니다"));
                deleteUser(*db_, id);
            }
            audit(*db_, sess->userId, "user_deleted", clientIp(req), user->email, now());
            pushRoutes(); // 그 사람 기기를 내부 길에서 뺀다
            Json::Value v;
            v["ok"] = true;
            cb(json(v));
        },
        {drogon::Post});
}

} // namespace douve
