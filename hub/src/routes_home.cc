// 홈 화면: 서비스·외부 링크 바로가기(그룹·아이콘·상태), 링크 관리, 아이콘.

#include "app.h"
#include "cluster/icons.h"
#include "http_util.h"
#include "store/nodes.h"
#include "store/services.h"

#include <drogon/drogon.h>

#include <filesystem>

namespace douve {

using drogon::HttpRequestPtr;
using drogon::HttpResponse;
using drogon::HttpResponsePtr;
using http::error;
using http::json;
using Callback = std::function<void(const HttpResponsePtr&)>;

namespace {

std::string hostOfUrl(const std::string& url) {
    auto start = url.find("://");
    start = start == std::string::npos ? 0 : start + 3;
    auto end = url.find_first_of(":/?#", start);
    return url.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

std::vector<std::string> iconSources(const std::string& icon, const std::string& name,
                                     const std::string& faviconUrl) {
    std::vector<std::string> src;
    std::vector<std::string> names = icon.empty() ? iconNameGuesses(name) : std::vector{icon};
    for (const auto& n : names) {
        src.push_back(dashboardIconUrl(n, true));
        src.push_back(dashboardIconUrl(n, false));
    }
    if (icon.empty() && !faviconUrl.empty())
        src.push_back(faviconUrl);
    return src;
}

Json::Value linkJson(const Link& l) {
    Json::Value v;
    v["type"] = "link";
    v["id"] = Json::Int64(l.id);
    v["name"] = l.name;
    v["url"] = l.url;
    v["group"] = l.group;
    v["description"] = l.description;
    v["icon"] = l.icon;
    v["position"] = l.position;
    v["icon_url"] = "/api/icons/link/" + std::to_string(l.id) + "?v=" + l.icon;
    return v;
}

} // namespace

// 사이드바·홈 요약: 볼 수 있는 서버만 센다. 보안 이슈는 관리자만.
Json::Value HubApp::summaryJson(const Access& acc) {
    Json::Value v;
    int online = 0, total = 0;
    for (const auto& n : listNodes(*db_)) {
        if (!acc.node(n.id))
            continue;
        ++total;
        online += live_.connected(n.id) ? 1 : 0;
    }
    int alerts = 0;
    for (const auto& a : openAlerts(*db_))
        alerts += acc.admin() || (a.nodeId && acc.node(*a.nodeId)) ? 1 : 0;
    std::int64_t security = 0;
    if (acc.admin()) {
        Statement sc(*db_, "SELECT count(*) FROM security_issues WHERE status = 'open'");
        security = sc.step() ? sc.int64(0) : 0;
    }
    v["servers"] = total;
    v["online"] = online;
    v["alerts"] = alerts;
    v["security_open"] = Json::Int64(security);
    return v;
}

void HubApp::registerHomeRoutes() {
    auto& app = drogon::app();
    icons_ = std::make_unique<IconCache>(
        (std::filesystem::path(cfg_.databasePath).parent_path() / "icons").string());

    app.registerHandler("/api/home",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            auto s = currentSession(req, now());
                            if (!s)
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            const auto acc = access(*s);
                            Json::Value out;
                            out["email"] = s->email;
                            out["role"] = roleName(acc.role);
                            out["items"] = Json::Value(Json::arrayValue);
                            for (const auto& sv : listServices(*db_)) {
                                if (!sv.onHome || !acc.service(sv.id, sv.nodeId))
                                    continue;
                                Json::Value v;
                                v["type"] = "service";
                                v["id"] = Json::Int64(sv.id);
                                v["name"] = sv.name;
                                v["url"] = "https://" + sv.host;
                                v["group"] = sv.group;
                                v["description"] = sv.description;
                                v["icon"] = sv.icon;
                                v["position"] = sv.position;
                                v["auth"] = sv.auth;
                                v["icon_url"] =
                                    "/api/icons/service/" + std::to_string(sv.id) + "?v=" + sv.icon;
                                std::lock_guard lk(healthMu_);
                                auto h = health_.find(sv.id);
                                v["health"] =
                                    h == health_.end() || h->second.checkedAt == 0
                                        ? Json::Value()
                                        : Json::Value(h->second.fails == 0 ? "up" : "down");
                                out["items"].append(v);
                            }
                            if (acc.atLeastOperator()) // 링크는 관리자가 넣은 내부 주소일 수 있다
                                for (const auto& l : listLinks(*db_))
                                    out["items"].append(linkJson(l));
                            out["summary"] = summaryJson(acc);
                            cb(json(out));
                        },
                        {drogon::Get});

    // 사이드바 배지용 가벼운 요약
    app.registerHandler("/api/summary",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            auto s = currentSession(req, now());
                            if (!s)
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            const auto acc = access(*s);
                            Json::Value v = summaryJson(acc);
                            v["email"] = s->email;
                            v["role"] = roleName(acc.role);
                            v["features"] = settings_.features().toJson();
                            cb(json(v));
                        },
                        {drogon::Get});

    auto linkUpsert = [this](const HttpRequestPtr& req, Callback&& cb, bool create) {
        if (!sameOrigin(req))
            return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
        if (!currentSession(req, now()))
            return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
        auto body = req->getJsonObject();
        if (!body)
            return cb(error(drogon::k400BadRequest, "JSON 본문이 필요합니다"));
        Link l;
        if (!create) {
            auto cur = findLink(*db_, (*body).get("id", 0).asInt64());
            if (!cur)
                return cb(error(drogon::k404NotFound, "링크를 찾을 수 없습니다"));
            l = *cur;
        }
        l.name = (*body).get("name", l.name).asString();
        l.url = (*body).get("url", l.url).asString();
        l.group = (*body).get("group", l.group).asString();
        l.description = (*body).get("description", l.description).asString();
        l.icon = (*body).get("icon", l.icon).asString();
        l.position = (*body).get("position", l.position).asInt();
        if (auto err = validateLink(l); !err.empty())
            return cb(error(drogon::k400BadRequest, err));
        if (create)
            l.id = createLink(*db_, l, now());
        else
            updateLink(*db_, l);
        cb(json(linkJson(l)));
    };
    app.registerHandler("/api/links/create",
                        [linkUpsert](const HttpRequestPtr& req, Callback&& cb) {
                            linkUpsert(req, std::move(cb), true);
                        },
                        {drogon::Post});
    app.registerHandler("/api/links/update",
                        [linkUpsert](const HttpRequestPtr& req, Callback&& cb) {
                            linkUpsert(req, std::move(cb), false);
                        },
                        {drogon::Post});
    app.registerHandler("/api/links/delete",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            if (!sameOrigin(req))
                                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
                            if (!currentSession(req, now()))
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            auto body = req->getJsonObject();
                            if (!body || !deleteLink(*db_, (*body).get("id", 0).asInt64()))
                                return cb(error(drogon::k404NotFound, "링크를 찾을 수 없습니다"));
                            Json::Value v;
                            v["ok"] = true;
                            cb(json(v));
                        },
                        {drogon::Post});

    // 아이콘: 지정한 dashboard-icons 이름 → 이름 추정 → favicon 순서. 없으면 404 (화면은 글자
    // 아이콘).
    app.registerHandler(
        "/api/icons/{kind}/{id}",
        [this](const HttpRequestPtr& req, Callback&& cb, const std::string& kind, std::int64_t id) {
            auto sess = currentSession(req, now());
            if (!sess)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            const auto acc = access(*sess);
            if (kind != "service" && !acc.atLeastOperator())
                return cb(HttpResponse::newNotFoundResponse());
            std::string key;
            std::vector<std::string> sources;
            if (kind == "service") {
                auto s = findService(*db_, id);
                if (s && !acc.service(s->id, s->nodeId))
                    s.reset();
                if (!s)
                    return cb(HttpResponse::newNotFoundResponse());
                key = "service:" + std::to_string(id) + ":" + s->icon + ":" + s->name;
                sources = iconSources(s->icon, s->name, "http://" + s->upstream + "/favicon.ico");
            } else if (kind == "link") {
                auto l = findLink(*db_, id);
                if (!l)
                    return cb(HttpResponse::newNotFoundResponse());
                std::string guess = sanitizeNodeName(l->name);
                key = "link:" + std::to_string(id) + ":" + l->icon + ":" + l->url;
                const std::string host = hostOfUrl(l->url);
                sources = iconSources(l->icon, guess,
                                      host.empty() ? ""
                                                   : l->url.substr(0, l->url.find("://") + 3) +
                                                         host + "/favicon.ico");
            } else if (kind == "name") {
                // 아직 서비스가 아닌 앱(실행 중인 앱 목록): 아이콘 이름으로 dashboard-icons만
                const std::string n = req->getParameter("n");
                if (n.empty() || !validIconName(n))
                    return cb(HttpResponse::newNotFoundResponse());
                key = "name:" + n;
                sources = iconSources("", n, "");
            } else {
                return cb(HttpResponse::newNotFoundResponse());
            }
            icons_->get(key, sources, [cb = std::move(cb)](std::optional<IconData> icon) {
                if (!icon) {
                    auto r = HttpResponse::newHttpResponse();
                    r->setStatusCode(drogon::k404NotFound);
                    r->addHeader("Cache-Control", "private, max-age=3600");
                    return cb(r);
                }
                auto r = HttpResponse::newHttpResponse();
                r->setBody(std::move(icon->bytes));
                r->setContentTypeString(icon->contentType);
                r->addHeader("Cache-Control", "private, max-age=86400");
                // 외부에서 받은 SVG가 문서로 열려도 스크립트가 돌지 않게
                r->addHeader("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; sandbox");
                r->addHeader("X-Content-Type-Options", "nosniff");
                cb(r);
            });
        },
        {drogon::Get});
}

} // namespace douve
