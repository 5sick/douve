// 웹 설정: Google 로그인·텔레그램 알림(비밀값은 돌려주지 않음), 텔레그램 테스트 발송, 초대 링크
// 만들기.

#include "app.h"
#include "auth/google.h"
#include "cluster/gateway.h"
#include "http_util.h"
#include "net/https_client.h"
#include "store/invites.h"
#include "store/repo.h"
#include "util/encoding.h"
#include "util/i18n.h"
#include "version.h"

#include <drogon/drogon.h>

namespace douve {

using drogon::HttpRequestPtr;
using drogon::HttpResponsePtr;
using http::error;
using http::json;
using Callback = std::function<void(const HttpResponsePtr&)>;

namespace {
// 비밀값 일부만 보여준다 (무엇이 들어 있는지 확인용)
std::string mask(const std::string& s) {
    if (s.empty())
        return "";
    return s.size() <= 8 ? "••••" : s.substr(0, 4) + "••••" + s.substr(s.size() - 2);
}
} // namespace

void HubApp::registerSettingsRoutes() {
    auto& app = drogon::app();

    app.registerHandler("/api/settings",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            if (!currentSession(req, now()))
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            const auto c = settings_.get();
                            Json::Value v;
                            v["version"] = kVersion;
                            v["public_url"] = cfg_.publicUrl;
                            v["google"]["client_id"] = c.googleClientId;
                            v["google"]["secret_hint"] = mask(c.googleClientSecret);
                            v["google"]["enabled"] = c.googleEnabled();
                            v["google"]["redirect_uri"] = googleRedirectUri(cfg_);
                            v["telegram"]["token_hint"] = mask(c.telegramBotToken);
                            v["telegram"]["chat_id"] = c.telegramChatId;
                            v["telegram"]["enabled"] = c.telegramEnabled();
                            v["agent_expose"] =
                                getSetting(*db_, "agent.expose").value_or("on") != "off";
                            v["features"] = settings_.features().toJson();
                            v["language"] = language();
                            cb(json(v));
                        },
                        {drogon::Get});

    // 저장: 비밀값 칸을 비워 보내면 기존 값 유지, clear_*가 true면 지움
    app.registerHandler(
        "/api/settings/save",
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
            const auto& b = *body;
            Credentials c = settings_.get();
            std::string changed;
            auto take = [&](const Json::Value& sec, const char* key, const char* clearKey,
                            std::string& field, const char* label) {
                if (sec.get(clearKey, false).asBool()) {
                    field.clear();
                    changed += std::string(label) + "(삭제) ";
                } else if (sec.isMember(key)) {
                    std::string v = sec[key].asString();
                    v.erase(0, v.find_first_not_of(" \t"));
                    v.erase(v.find_last_not_of(" \t") + 1);
                    if (!v.empty() && v != field) {
                        field = v;
                        changed += std::string(label) + " ";
                    }
                }
            };
            if (b.isMember("google")) {
                take(b["google"], "client_id", "clear", c.googleClientId, "google.client_id");
                take(b["google"], "client_secret", "clear", c.googleClientSecret, "google.secret");
            }
            if (b.isMember("telegram")) {
                take(b["telegram"], "bot_token", "clear", c.telegramBotToken, "telegram.token");
                take(b["telegram"], "chat_id", "clear", c.telegramChatId, "telegram.chat_id");
            }
            if (b.isMember("features")) {
                settings_.saveFeatures(*db_, Features::fromJson(b["features"]), t);
                Json::Value cfgMsg;
                cfgMsg["type"] = "config";
                cfgMsg["features"] = settings_.features().toJson();
                agents().broadcast(cfgMsg); // 접속 중인 Agent에 바로 반영
                changed += "features ";
            }
            if (b.isMember("language")) {
                const auto l = b["language"].asString();
                if (l != "ko" && l != "en")
                    return cb(error(drogon::k400BadRequest, "언어는 ko 또는 en 입니다"));
                putSetting(*db_, "language", l, t);
                changed += "language=" + l + " ";
            }
            if (b.isMember("agent_expose")) {
                putSetting(*db_, "agent.expose", b["agent_expose"].asBool() ? "on" : "off", t);
                changed +=
                    std::string("agent.expose=") + (b["agent_expose"].asBool() ? "on " : "off ");
            }
            if (auto err = validateGoogle(c.googleClientId, c.googleClientSecret); !err.empty())
                return cb(error(drogon::k400BadRequest, err));
            if (auto err = validateTelegram(c.telegramBotToken, c.telegramChatId); !err.empty())
                return cb(error(drogon::k400BadRequest, err));
            settings_.save(*db_, cfg_, c, t);
            audit(*db_, s->userId, "settings_changed", clientIp(req), changed, t);
            Json::Value v;
            v["ok"] = true;
            cb(json(v));
        },
        {drogon::Post});

    app.registerHandler(
        "/api/settings/telegram-test",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            if (!currentSession(req, now()))
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            const auto c = settings_.get();
            if (!c.telegramEnabled())
                return cb(
                    error(drogon::k400BadRequest, "텔레그램 봇 토큰과 chat id를 먼저 저장하세요"));
            const std::string url =
                cfg_.telegramApiUrl + "/bot" + c.telegramBotToken + "/sendMessage";
            const std::string form =
                "chat_id=" + urlEncode(c.telegramChatId) + "&text=" +
                urlEncode(i18n::translate("[Douve] 테스트 알림입니다. 알림이 잘 연결되었습니다.",
                                          language()));
            httpFetchAsync(url, form, [cb = std::move(cb)](HttpResult r) {
                if (r.ok && r.status == 200) {
                    Json::Value v;
                    v["ok"] = true;
                    return cb(json(v));
                }
                std::string why = r.ok ? "HTTP " + std::to_string(r.status) : r.error;
                if (r.status == 401)
                    why = "봇 토큰이 올바르지 않습니다";
                else if (r.status == 400 || r.status == 403)
                    why = "chat id가 올바르지 않거나 봇과 대화를 시작하지 않았습니다 (봇에게 먼저 "
                          "/start)";
                cb(error(drogon::k502BadGateway, "텔레그램 발송 실패: " + why));
            });
        },
        {drogon::Post});

    // 초대 링크 만들기 (다른 사람 또는 내 새 기기). 사람을 들이는 일이라 패스키 재확인.
    app.registerHandler("/api/invites/create",
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
                            std::string email = body ? (*body).get("email", "").asString() : "";
                            if (email.find('@') == std::string::npos || email.size() > 254 ||
                                email.find_first_of(" \t\r\n<>") != std::string::npos)
                                return cb(
                                    error(drogon::k400BadRequest, "이메일 주소를 확인하세요"));
                            auto inv = createInvite(*db_, email, s->userId, 24 * 3600, t);
                            audit(*db_, s->userId, "invite_created", clientIp(req), inv.email, t);
                            Json::Value v;
                            v["link"] = cfg_.publicUrl + "/invite#" + inv.token;
                            v["email"] = inv.email;
                            v["expires_at"] = Json::Int64(inv.expiresAt);
                            cb(json(v));
                        },
                        {drogon::Post});
}

} // namespace douve
