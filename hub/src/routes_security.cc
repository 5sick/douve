// 보안 감시 API: 열린 이슈·최근 사건, "확인함"·"문제 없음" 처리, 무시 해제.

#include "app.h"
#include "cluster/security.h"
#include "cluster/terminal.h"
#include "http_util.h"
#include "store/nodes.h"
#include "store/repo.h"

#include <drogon/drogon.h>

#include <sstream>

namespace douve {

using drogon::HttpRequestPtr;
using drogon::HttpResponsePtr;
using http::error;
using http::json;
using Callback = std::function<void(const HttpResponsePtr&)>;

void HubApp::ingestSecurityEvents(std::int64_t nodeId, const Json::Value& msg) {
    auto events = parseSecurityEvents(msg);
    if (events.empty())
        return;
    auto node = findNode(*db_, nodeId);
    if (!node)
        return;
    SecurityContext ctx;
    ctx.nodeId = nodeId;
    ctx.nodeName = node->name;
    if (auto inv = live_.inventory(nodeId))
        for (const auto& u : (*inv)["terminal_users"])
            ctx.adminUsers.push_back(u.asString());
    ctx.terminalUser = [this](const std::string& sid) { return terminal_->userForSid(sid); };
    ctx.terminalActiveAt = [this, nodeId](std::int64_t ts) {
        return terminal_->userActiveAt(nodeId, ts);
    };
    try {
        // 한 번에 들어온 이슈는 알림 하나로 묶는다
        auto notes = ingestSecurity(*db_, ctx, events, now());
        if (!notes.empty()) {
            std::string text = notes.size() == 1 ? notes.front()
                                                 : "🛡️ [" + node->name + "] 보안 이슈 " +
                                                       std::to_string(notes.size()) + "건";
            if (notes.size() > 1)
                for (std::size_t i = 0; i < notes.size() && i < 10; ++i)
                    text += "\n• " + notes[i];
            notify(text + "\n확인: " + cfg_.publicUrl + "/security");
        }
    } catch (const std::exception& e) {
        LOG_ERROR << "보안 사건 저장 실패: " << e.what();
    }
}

void HubApp::registerSecurityRoutes() {
    auto& app = drogon::app();

    app.registerHandler(
        "/api/security",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!currentSession(req, now()))
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            std::map<std::int64_t, std::string> names;
            for (const auto& n : listNodes(*db_))
                names[n.id] = n.name;
            Json::Value out;
            out["issues"] = Json::Value(Json::arrayValue);
            {
                Statement s(*db_, "SELECT i.fingerprint, i.node_id, i.kind, i.severity, i.summary, "
                                  "i.first_seen, i.last_seen, i.count, i.status, i.acked_at, "
                                  "COALESCE(u.email, '') FROM security_issues i "
                                  "LEFT JOIN users u ON u.id = i.acked_by "
                                  "ORDER BY (i.status = 'open') DESC, i.last_seen DESC LIMIT 300");
                while (s.step()) {
                    Json::Value v;
                    v["fingerprint"] = s.text(0);
                    v["node"] = names[s.int64(1)];
                    v["kind"] = s.text(2);
                    v["severity"] = s.text(3);
                    v["summary"] = s.text(4);
                    v["first_seen"] = Json::Int64(s.int64(5));
                    v["last_seen"] = Json::Int64(s.int64(6));
                    v["count"] = Json::Int64(s.int64(7));
                    v["status"] = s.text(8);
                    v["acked_at"] =
                        s.isNull(9) ? Json::Value() : Json::Value(Json::Int64(s.int64(9)));
                    v["acked_by"] = s.text(10);
                    out["issues"].append(v);
                }
            }
            out["events"] = Json::Value(Json::arrayValue);
            {
                const std::string kind = req->getParameter("kind");
                Statement s(*db_, "SELECT node_id, ts, kind, severity, summary, via, status "
                                  "FROM security_events WHERE (? = '' OR kind = ?) "
                                  "ORDER BY ts DESC, id DESC LIMIT 200");
                s.bind(1, kind).bind(2, kind);
                while (s.step()) {
                    Json::Value v;
                    v["node"] = names[s.int64(0)];
                    v["ts"] = Json::Int64(s.int64(1));
                    v["kind"] = s.text(2);
                    v["severity"] = s.text(3);
                    v["summary"] = s.text(4);
                    v["via"] = s.text(5);
                    v["status"] = s.text(6);
                    out["events"].append(v);
                }
            }
            cb(json(out));
        },
        {drogon::Get});

    // 이슈 처리. 알림을 끄는 일이라 패스키 재확인.
    app.registerHandler("/api/security/resolve",
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
                            if (!body)
                                return cb(error(drogon::k400BadRequest, "JSON 본문이 필요합니다"));
                            std::vector<std::string> fps;
                            for (const auto& f : (*body)["fingerprints"])
                                if (fps.size() < 500)
                                    fps.push_back(f.asString());
                            const std::string mode = (*body).get("mode", "").asString();
                            const int n = resolveSecurityIssues(*db_, fps, mode, s->userId, t);
                            if (n == 0)
                                return cb(error(drogon::k400BadRequest, "처리할 이슈가 없습니다"));
                            audit(*db_, s->userId,
                                  mode == "ignore" ? "security_ignored" : "security_acked",
                                  clientIp(req), std::to_string(n) + "건", t);
                            Json::Value v;
                            v["updated"] = n;
                            cb(json(v));
                        },
                        {drogon::Post});

    app.registerHandler(
        "/api/security/reopen",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            const auto t = now();
            auto s = currentSession(req, t);
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            auto body = req->getJsonObject();
            const std::string fp = body ? (*body).get("fingerprint", "").asString() : "";
            if (!reopenSecurityIssue(*db_, fp))
                return cb(error(drogon::k404NotFound, "무시 중인 이슈가 아닙니다"));
            audit(*db_, s->userId, "security_reopened", clientIp(req), fp.substr(0, 200), t);
            Json::Value v;
            v["ok"] = true;
            cb(json(v));
        },
        {drogon::Post});
}

} // namespace douve
