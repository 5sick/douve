// 웹 터미널: 1회용 티켓 발급, 녹화 목록·내려받기.

#include "app.h"
#include "cluster/gateway.h"
#include "cluster/terminal.h"
#include "http_util.h"
#include "store/nodes.h"
#include "store/repo.h"

#include <drogon/drogon.h>

#include <algorithm>
#include <filesystem>
#include <regex>
#include <sstream>

namespace douve {

using drogon::HttpRequestPtr;
using drogon::HttpResponse;
using drogon::HttpResponsePtr;
using http::error;
using http::json;
using Callback = std::function<void(const HttpResponsePtr&)>;

namespace {
// 터미널은 열 때마다 패스키를 확인한다 (최근 60초 이내 재인증)
constexpr std::int64_t kTerminalReauthSeconds = 60;
const std::regex kRecName(R"(^(\d{8})-(\d{6})-([a-z0-9-]+)-([a-z0-9-]+)-([A-Za-z0-9_-]+)\.cast$)");
} // namespace

void HubApp::registerTerminalRoutes() {
    auto& app = drogon::app();
    terminal_ = std::make_shared<TerminalGateway>(*this);
    app.registerController(terminal_);

    app.registerHandler(
        "/api/terminal/ticket",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            const auto t = now();
            auto s = currentSession(req, t);
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            if (!settings_.features().terminal)
                return cb(error(drogon::k403Forbidden, "웹 터미널이 꺼져 있습니다 (설정 → 기능)"));
            if (t - s->reauthAt > kTerminalReauthSeconds)
                return cb(error(drogon::k403Forbidden, "reauth_required"));
            auto body = req->getJsonObject();
            if (!body)
                return cb(error(drogon::k400BadRequest, "JSON 본문이 필요합니다"));
            auto n = findNode(*db_, (*body).get("node_id", 0).asInt64());
            if (!n)
                return cb(error(drogon::k404NotFound, "노드를 찾을 수 없습니다"));
            if (!live_.connected(n->id))
                return cb(error(drogon::k409Conflict, "서버가 Douve에 접속해 있지 않습니다"));
            const std::string user = (*body).get("user", "").asString();
            auto inv = live_.inventory(n->id);
            bool allowed = false;
            if (inv)
                for (const auto& u : (*inv)["terminal_users"])
                    allowed = allowed || u.asString() == user;
            if (!allowed)
                return cb(
                    error(drogon::k403Forbidden, "이 서버에서 터미널을 열 수 없는 계정입니다"));
            Json::Value p;
            p["node_id"] = Json::Int64(n->id);
            p["node_name"] = n->name;
            p["user"] = user;
            p["user_id"] = Json::Int64(s->userId);
            p["cols"] = std::clamp((*body).get("cols", 80).asInt(), 10, 1000);
            p["rows"] = std::clamp((*body).get("rows", 24).asInt(), 3, 500);
            Json::StreamWriterBuilder w;
            w["indentation"] = "";
            Json::Value v;
            v["ticket"] = putPending(*db_, "term", Json::writeString(w, p), 60, t);
            cb(json(v));
        },
        {drogon::Post});

    app.registerHandler("/api/terminal/recordings",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            if (!currentSession(req, now()))
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            std::vector<std::pair<std::string, std::uintmax_t>> files;
                            std::error_code ec;
                            for (const auto& e : std::filesystem::directory_iterator(
                                     terminal_->recordingsDir(), ec)) {
                                const std::string name = e.path().filename().string();
                                if (std::regex_match(name, kRecName))
                                    files.emplace_back(name, e.file_size(ec));
                            }
                            std::sort(files.begin(), files.end(), std::greater<>());
                            Json::Value arr(Json::arrayValue);
                            for (std::size_t i = 0; i < files.size() && i < 200; ++i) {
                                std::smatch m;
                                std::regex_match(files[i].first, m, kRecName);
                                Json::Value v;
                                v["name"] = files[i].first;
                                v["date"] = m[1].str();
                                v["time"] = m[2].str();
                                v["node"] = m[3].str();
                                v["user"] = m[4].str();
                                v["size"] = Json::UInt64(files[i].second);
                                arr.append(v);
                            }
                            Json::Value out;
                            out["recordings"] = arr;
                            out["active"] = Json::UInt64(terminal_->activeCount());
                            cb(json(out));
                        },
                        {drogon::Get});

    // 녹화 삭제 (패스키 재확인). 지운 사실은 감사 로그에 남는다.
    app.registerHandler(
        "/api/terminal/recordings/delete",
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
            std::vector<std::string> names;
            if (body && (*body)["names"].isArray())
                for (const auto& n : (*body)["names"])
                    names.push_back(n.asString());
            if (names.empty() || names.size() > 500)
                return cb(error(drogon::k400BadRequest, "지울 녹화를 고르세요"));
            int removed = 0;
            for (const auto& name : names) {
                if (!std::regex_match(name, kRecName))
                    continue;
                std::error_code ec;
                if (std::filesystem::remove(
                        std::filesystem::path(terminal_->recordingsDir()) / name, ec)) {
                    ++removed;
                    audit(*db_, s->userId, "recording_deleted", clientIp(req), name, t);
                }
            }
            Json::Value v;
            v["removed"] = removed;
            cb(json(v));
        },
        {drogon::Post});

    // 녹화에는 화면에 출력된 비밀값이 있을 수 있어 패스키 재확인 후에만 내려준다
    app.registerHandler(
        "/api/terminal/recordings/{name}",
        [this](const HttpRequestPtr& req, Callback&& cb, const std::string& name) {
            const auto t = now();
            auto s = currentSession(req, t);
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            if (!sessions_->reauthFresh(*s, t))
                return cb(error(drogon::k403Forbidden, "reauth_required"));
            if (!std::regex_match(name, kRecName))
                return cb(error(drogon::k404NotFound, "녹화를 찾을 수 없습니다"));
            const auto path = std::filesystem::path(terminal_->recordingsDir()) / name;
            std::error_code ec;
            if (!std::filesystem::is_regular_file(path, ec))
                return cb(error(drogon::k404NotFound, "녹화를 찾을 수 없습니다"));
            audit(*db_, s->userId, "recording_viewed", clientIp(req), name, t);
            auto r = HttpResponse::newFileResponse(path.string(), "", drogon::CT_TEXT_PLAIN);
            r->addHeader("Cache-Control", "no-store");
            cb(r);
        },
        {drogon::Get});
}

} // namespace douve
