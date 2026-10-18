#include "app.h"
#include "util/json.h"

#include "assets.h"
#include "auth/redirect.h"
#include "cluster/icons.h"
#include "http_util.h"
#include "store/invites.h"
#include "store/repo.h"
#include "store/services.h"
#include "util/crypto.h"
#include "version.h"

#include <drogon/drogon.h>

#include <algorithm>
#include <ctime>

namespace douve {

using drogon::HttpRequestPtr;
using drogon::HttpResponse;
using drogon::HttpResponsePtr;
using Callback = std::function<void(const HttpResponsePtr&)>;

HubApp::HubApp(HubConfig cfg) : cfg_(std::move(cfg)) {
    db_ = std::make_unique<Database>(cfg_.databasePath);
    sealAuditLog(*db_); // 해시 체인 도입 전 기록을 봉인
    sessions_ = std::make_unique<SessionManager>(*db_, cfg_);
    google_ = std::make_unique<GoogleOidc>(cfg_);
    settings_.load(cfg_, *db_);
}

HubApp::~HubApp() = default;

bool HubApp::sameOrigin(const HttpRequestPtr& req) const {
    const auto origin = req->getHeader("Origin");
    if (!origin.empty())
        return origin == cfg_.origin();
    // Origin이 없으면(일부 구형 브라우저) Sec-Fetch-Site로 판단, 둘 다 없으면 거부
    return req->getHeader("Sec-Fetch-Site") == "same-origin";
}

bool HubApp::loginAllowed(const HttpRequestPtr& req) {
    const auto ip = clientIp(req);
    if (loginLimiter_.allow(ip, now()))
        return true;
    audit(*db_, std::nullopt, "rate_limited", ip, std::string(req->path()), now());
    return false;
}

bool HubApp::emailAllowed(const std::string& email) {
    return std::find(cfg_.allowedEmails.begin(), cfg_.allowedEmails.end(), email) !=
               cfg_.allowedEmails.end() ||
           userAllowed(*db_, email);
}

Access HubApp::access(const SessionInfo& s) {
    auto a = loadAccess(*db_, s.userId);
    if (!a.admin() && std::find(cfg_.allowedEmails.begin(), cfg_.allowedEmails.end(), s.email) !=
                          cfg_.allowedEmails.end()) {
        setAccess(*db_, s.userId, Role::Admin, {}, {});
        a = Access{Role::Admin, {}, {}};
    }
    return a;
}

void HubApp::startSession(const HttpRequestPtr& req, const HttpResponsePtr& resp,
                          std::int64_t userId, const std::string& method) {
    const auto t = now();
    const std::string ip = clientIp(req);
    // 기존 세션 쿠키가 있으면 폐기하고 새로 발급 (세션 고정 공격 방지)
    if (auto old = sessionToken(req))
        sessions_->revoke(*old);
    // 기기 쿠키: 없거나 형식이 이상하면 새로. 원문은 저장하지 않는다.
    std::string device = req->getCookie(kDeviceCookie);
    const bool validDevice = device.size() >= 22 && device.size() <= 64 &&
                             std::all_of(device.begin(), device.end(), [](unsigned char c) {
                                 return std::isalnum(c) || c == '-' || c == '_';
                             });
    if (!validDevice)
        device = randomToken(16);
    const std::string deviceHash = toHex(sha256(device));
    const int before = static_cast<int>(sessions_->listForUser(userId, t).size());
    auto token = sessions_->create(userId, method, ip, req->getHeader("User-Agent"), t, deviceHash);
    const int replaced = before + 1 - static_cast<int>(sessions_->listForUser(userId, t).size());
    touchUserLogin(*db_, userId, t);
    audit(*db_, userId, "login", ip,
          method + (replaced > 0 ? " (같은 기기 이전 세션 " + std::to_string(replaced) + "개 정리)"
                                 : ""),
          t);
    resp->addHeader("Set-Cookie", sessions_->cookieHeader(token));
    drogon::Cookie c(kDeviceCookie, device);
    c.setPath("/");
    c.setHttpOnly(true);
    c.setSecure(cfg_.publicUrl.rfind("https://", 0) == 0);
    c.setSameSite(drogon::Cookie::SameSite::kLax);
    c.setMaxAge(2 * 365 * 24 * 3600);
    resp->addCookie(std::move(c));
}

drogon::HttpResponsePtr HubApp::finishLogin(const HttpRequestPtr& req, std::int64_t userId,
                                            const std::string& method,
                                            const std::string& redirectTo) {
    auto r = HttpResponse::newRedirectionResponse(redirectTo, drogon::k303SeeOther);
    startSession(req, r, userId, method);
    r->addHeader("Cache-Control", "no-store");
    return r;
}

std::int64_t HubApp::now() {
    return static_cast<std::int64_t>(std::time(nullptr));
}

std::string HubApp::clientIp(const HttpRequestPtr& req) const {
    const std::string peer = req->peerAddr().toIp();
    bool trusted = std::find(cfg_.trustedProxies.begin(), cfg_.trustedProxies.end(), peer) !=
                   cfg_.trustedProxies.end();
    if (!trusted) {
        std::lock_guard lk(edgeMu_);
        trusted = edgeAddresses_.count(peer) > 0;
    }
    if (!trusted)
        return peer;
    if (auto real = req->getHeader("X-Real-IP"); !real.empty())
        return real.substr(0, 64);
    auto xff = req->getHeader("X-Forwarded-For");
    if (!xff.empty()) {
        // 가장 오른쪽(신뢰한 프록시가 붙인 값)을 사용
        auto comma = xff.rfind(',');
        auto ip = comma == std::string::npos ? xff : xff.substr(comma + 1);
        ip.erase(0, ip.find_first_not_of(' '));
        return ip.substr(0, 64);
    }
    return peer;
}

std::optional<std::string> HubApp::sessionToken(const HttpRequestPtr& req) const {
    auto v = req->getCookie(kSessionCookie);
    if (v.empty())
        return std::nullopt;
    return v;
}

std::optional<SessionInfo> HubApp::currentSession(const HttpRequestPtr& req, std::int64_t t) {
    if (auto tok = sessionToken(req)) {
        if (auto s = sessions_->validate(*tok, t))
            return s;
    }
    return tailscaleSession(req, t);
}

// Tailscale 내부 전용 모드: 로컬 tailscaled(`tailscale serve`)가 붙인 사용자 헤더로 로그인.
// 직접 연결된 상대가 127.0.0.1/::1일 때만 믿는다 (X-Forwarded-For 등은 보지 않음).
std::optional<SessionInfo> HubApp::tailscaleSession(const HttpRequestPtr& req, std::int64_t t) {
    if (!cfg_.tailscaleAuth)
        return std::nullopt;
    const std::string peer = req->peerAddr().toIp();
    if (peer != "127.0.0.1" && peer != "::1")
        return std::nullopt;
    std::string login = req->getHeader("Tailscale-User-Login");
    if (login.empty() || login.size() > 254)
        return std::nullopt;
    std::transform(login.begin(), login.end(), login.begin(), ::tolower);
    if (!emailAllowed(login))
        return std::nullopt;
    auto user = findOrCreateUser(*db_, login, t);
    SessionInfo s;
    s.userId = user.id;
    s.email = login;
    s.authMethod = "tailscale";
    s.createdAt = t;
    s.lastSeenAt = t;
    s.reauthAt = t; // 기기·사용자 확인은 Tailscale이 매 요청 한다
    s.ip = "tailscale";
    s.userAgent = req->getHeader("User-Agent").substr(0, 300);
    s.idHint = "tailscale";
    return s;
}

namespace {

HttpResponsePtr loginError(const std::string& code) {
    return HttpResponse::newRedirectionResponse("/login?error=" + code, drogon::k303SeeOther);
}

HttpResponsePtr json(const Json::Value& v, drogon::HttpStatusCode code = drogon::k200OK) {
    auto r = HttpResponse::newHttpJsonResponse(v);
    r->setStatusCode(code);
    r->addHeader("Cache-Control", "no-store");
    return r;
}

HttpResponsePtr error(drogon::HttpStatusCode code, const std::string& msg) {
    Json::Value v;
    v["error"] = msg;
    return json(v, code);
}

} // namespace

void HubApp::registerRoutes() {
    auto& app = drogon::app();

    // 웹 UI (바이너리 내장). 모든 페이지에 보안 헤더를 붙인다.
    // inlineStyle: xterm.js가 동적 <style>을 쓰므로 터미널 화면에서만 인라인 스타일 허용
    // (스크립트는 계속 'self')
    auto page = [](const char* name, bool inlineStyle = false) {
        return [name, inlineStyle](const HttpRequestPtr&, Callback&& cb) {
            const auto* a = assets::find(name);
            if (!a)
                return cb(HttpResponse::newNotFoundResponse());
            auto r = HttpResponse::newHttpResponse();
            r->setBody(std::string(reinterpret_cast<const char*>(a->data), a->size));
            r->setContentTypeString(a->mime);
            r->addHeader("Content-Security-Policy",
                         std::string("default-src 'self'; script-src 'self'; style-src 'self'") +
                             (inlineStyle ? " 'unsafe-inline'" : "") +
                             "; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
                             "base-uri 'none'; form-action 'self'");
            r->addHeader("X-Content-Type-Options", "nosniff");
            r->addHeader("X-Frame-Options", "DENY");
            r->addHeader("Referrer-Policy", "same-origin");
            r->addHeader("Cache-Control",
                         std::string_view(name).ends_with(".html") ? "no-store" : "no-cache");
            cb(r);
        };
    };
    app.registerHandler("/login", page("login.html"), {drogon::Get});
    app.registerHandler("/account", page("account.html"), {drogon::Get});
    app.registerHandler("/privacy", page("privacy.html"), {drogon::Get});
    app.registerHandler("/invite", page("invite.html"), {drogon::Get});
    app.registerHandler("/dashboard", page("dashboard.html"), {drogon::Get});
    app.registerHandler("/node", page("node.html"), {drogon::Get});
    app.registerHandler("/services", page("services.html"), {drogon::Get});
    app.registerHandler("/settings", page("settings.html"), {drogon::Get});
    app.registerHandler("/security", page("security.html"), {drogon::Get});
    app.registerHandler("/terminal", page("terminal.html", true), {drogon::Get});
    app.registerHandler("/static/terminal.js", page("terminal.js"), {drogon::Get});
    app.registerHandler("/static/xterm.js", page("xterm.js"), {drogon::Get});
    app.registerHandler("/static/xterm.css", page("xterm.css"), {drogon::Get});
    app.registerHandler("/static/addon-fit.js", page("addon-fit.js"), {drogon::Get});
    app.registerHandler("/static/qrcode.js", page("qrcode.js"), {drogon::Get});
    app.registerHandler("/static/dashboard.js", page("dashboard.js"), {drogon::Get});
    app.registerHandler("/static/app.js", page("app.js"), {drogon::Get});
    app.registerHandler("/static/style.css", page("style.css"), {drogon::Get});
    app.registerHandler("/", page("home.html"), {drogon::Get});
    app.registerHandler("/static/icons.js", page("icons.js"), {drogon::Get});
    app.registerHandler("/static/i18n.js", page("i18n.js"), {drogon::Get});
    // 개인정보처리방침의 운영자 연락처 (로그인 없이 공개)
    app.registerHandler("/api/privacy",
                        [this](const HttpRequestPtr&, Callback&& cb) {
                            Json::Value v;
                            v["contact"] = cfg_.privacyContact;
                            cb(json(v));
                        },
                        {drogon::Get});
    // 번역 사전: <head>에서 동기로 읽도록 JSON을 스크립트로 감싸 준다
    app.registerHandler(
        "/static/i18n-en.js",
        [](const HttpRequestPtr&, Callback&& cb) {
            const auto* a = assets::find("i18n-en.json");
            auto r = HttpResponse::newHttpResponse();
            r->setBody("window.DOUVE_I18N_EN = " +
                       std::string(reinterpret_cast<const char*>(a->data), a->size) + ";\n");
            r->setContentTypeString("text/javascript; charset=utf-8");
            r->addHeader("X-Content-Type-Options", "nosniff");
            r->addHeader("Cache-Control", "no-cache");
            cb(r);
        },
        {drogon::Get});
    // 브라우저 탭·바로가기·홈 화면 아이콘, 앱 설치(PWA) 정보
    for (const char* f : {"favicon.svg", "favicon.ico", "apple-touch-icon.png", "icon-192.png",
                          "icon-512.png", "icon-maskable-512.png", "manifest.webmanifest"})
        app.registerHandler(std::string("/") + f, page(f), {drogon::Get});
    registerPasskeyRoutes();
    registerAccountRoutes();
    registerNodeRoutes();
    registerServiceRoutes();
    registerDevnetRoutes();
    registerCheckupRoutes();
    registerReachRoutes();
    registerTerminalRoutes();
    registerFileRoutes();
    registerSettingsRoutes();
    registerSecurityRoutes();
    registerHomeRoutes();
    registerPortmapRoutes();
    registerChannelRoutes();
    registerUserRoutes();

    app.registerHandler("/healthz",
                        [](const HttpRequestPtr&, Callback&& cb) {
                            Json::Value body;
                            body["status"] = "ok";
                            body["version"] = kVersion;
                            cb(json(body));
                        },
                        {drogon::Get});

    // 입구(Agent edge)·nginx auth_request 대상. 본문 없이 상태 코드만 의미가 있다.
    //   200: 들어가도 됨 (X-Douve-User 헤더에 이메일) / 401: 로그인 필요 / 403: 이 앱 권한 없음
    // ?service=<id>: 그 서비스(앱)에 대한 권한을 본다. 없으면 관리자만 (어느 앱인지 모르는 요청).
    app.registerHandler("/auth/verify",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            auto s = currentSession(req, now());
                            auto r = HttpResponse::newHttpResponse();
                            r->addHeader("Cache-Control", "no-store");
                            if (!s) {
                                r->setStatusCode(drogon::k401Unauthorized);
                                return cb(r);
                            }
                            const auto a = access(*s);
                            bool allowed = a.admin();
                            if (!allowed) {
                                const std::string sid = req->getParameter("service");
                                std::int64_t id = 0;
                                try {
                                    id = sid.empty() || sid.size() > 18 ? 0 : std::stoll(sid);
                                } catch (const std::exception&) {
                                }
                                if (auto sv = id > 0 ? findService(*db_, id) : std::nullopt)
                                    allowed = a.service(sv->id, sv->nodeId);
                            }
                            if (!allowed) {
                                r->setStatusCode(drogon::k403Forbidden);
                                return cb(r);
                            }
                            r->setStatusCode(drogon::k200OK);
                            r->addHeader("X-Douve-User", s->email);
                            cb(r);
                        },
                        {drogon::Get, drogon::Head});

    // 로그인 화면이 보여줄 방법 (Google은 선택)
    app.registerHandler("/auth/methods",
                        [this](const HttpRequestPtr&, Callback&& cb) {
                            Json::Value v;
                            v["google"] = settings_.get().googleEnabled();
                            v["passkey"] = true;
                            cb(json(v));
                        },
                        {drogon::Get});

    app.registerHandler("/api/me",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            const auto t = now();
                            auto s = currentSession(req, t);
                            if (!s)
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            Json::Value v;
                            v["email"] = s->email;
                            v["auth_method"] = s->authMethod;
                            v["reauth_fresh"] = sessions_->reauthFresh(*s, t);
                            v["role"] = roleName(access(*s).role);
                            cb(json(v));
                        },
                        {drogon::Get});

    // Google 로그인 시작: state(=pending id), nonce, PKCE를 만들어 Google로 보낸다.
    app.registerHandler(
        "/auth/google/start",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!loginAllowed(req))
                return cb(http::error(drogon::k429TooManyRequests,
                                      "요청이 너무 많습니다. 잠시 후 다시 시도하세요"));
            const auto creds = settings_.get();
            if (!creds.googleEnabled())
                return cb(loginError("google_disabled"));
            const auto t = now();
            purgeExpiredPending(*db_, t);
            Pkce pkce = makePkce();
            Json::Value p;
            p["nonce"] = randomToken(24);
            p["verifier"] = pkce.verifier;
            p["rd"] = safeRedirect(req->getParameter("rd"), cfg_, "/");
            const std::string state = putPending(*db_, "oidc", p.toStyledString(), 600, t);
            auto r = HttpResponse::newRedirectionResponse(
                googleAuthorizeUrl(cfg_, creds.googleClientId, state, p["nonce"].asString(),
                                   pkce.challenge),
                drogon::k302Found);
            r->addHeader("Cache-Control", "no-store");
            cb(r);
        },
        {drogon::Get});

    app.registerHandler(
        "/auth/google/callback",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!loginAllowed(req))
                return cb(http::error(drogon::k429TooManyRequests,
                                      "요청이 너무 많습니다. 잠시 후 다시 시도하세요"));
            const auto t = now();
            const std::string ip = clientIp(req);
            if (!req->getParameter("error").empty())
                return cb(loginError("google_cancelled"));
            auto payload = takePending(*db_, req->getParameter("state"), "oidc", t);
            if (!payload) {
                audit(*db_, std::nullopt, "login_failed", ip, "google: invalid state", t);
                return cb(loginError("state"));
            }
            Json::Value p;
            parseJson(*payload, p);
            const std::string rd = p["rd"].asString();
            const auto creds = settings_.get();
            google_->completeLogin(
                req->getParameter("code"), p["verifier"].asString(), p["nonce"].asString(), t,
                creds.googleClientId, creds.googleClientSecret,
                [this, req, cb = std::move(cb), rd, ip, t](std::optional<GoogleIdentity> id,
                                                           std::string err) {
                    if (!id) {
                        audit(*db_, std::nullopt, "login_failed", ip, "google: " + err, t);
                        LOG_WARN << "Google 로그인 실패: " << err;
                        return cb(loginError("google"));
                    }
                    if (!emailAllowed(id->email)) {
                        audit(*db_, std::nullopt, "login_denied", ip, "google: " + id->email, t);
                        return cb(loginError("not_allowed"));
                    }
                    auto user = findOrCreateUser(*db_, id->email, t);
                    // 패스키가 아직 없으면 등록 화면으로 안내
                    const std::string next =
                        countPasskeys(*db_, user.id) == 0 ? "/account?setup=passkey" : rd;
                    cb(finishLogin(req, user.id, "google", next));
                });
        },
        {drogon::Get});

    app.registerHandler("/auth/logout",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            if (!sameOrigin(req))
                                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
                            if (auto tok = sessionToken(req)) {
                                if (auto s = sessions_->validate(*tok, now()))
                                    audit(*db_, s->userId, "logout", clientIp(req), "", now());
                                sessions_->revoke(*tok);
                            }
                            auto r = HttpResponse::newRedirectionResponse(
                                safeRedirect(req->getParameter("rd"), cfg_, "/login"),
                                drogon::k303SeeOther);
                            r->addHeader("Set-Cookie", sessions_->clearCookieHeader());
                            cb(r);
                        },
                        {drogon::Post});
}

} // namespace douve
