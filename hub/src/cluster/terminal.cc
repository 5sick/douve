#include "cluster/terminal.h"
#include "util/json.h"

#include "app.h"
#include "cluster/gateway.h"
#include "store/repo.h"
#include "util/crypto.h"
#include "util/encoding.h"

#include <drogon/drogon.h>

#include <chrono>
#include <ctime>
#include <filesystem>
#include <sstream>

namespace douve {

using drogon::WebSocketConnectionPtr;

namespace {

double monoSeconds() {
    return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

std::string compact(const Json::Value& v) {
    Json::StreamWriterBuilder w;
    w["indentation"] = "";
    return Json::writeString(w, v);
}

void sendBrowser(const WebSocketConnectionPtr& c, const Json::Value& v) {
    if (c && c->connected())
        c->send(compact(v));
}

void rejectBrowser(const WebSocketConnectionPtr& c, const std::string& why) {
    Json::Value v;
    v["t"] = "exit";
    v["code"] = -1;
    v["error"] = why;
    sendBrowser(c, v);
    c->shutdown(drogon::CloseCode::kViolation, "rejected");
}

// 파일 이름에 넣을 수 있게 영문 소문자·숫자·하이픈만
std::string slug(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        if (std::isalnum(c))
            out += static_cast<char>(std::tolower(c));
        else if (!out.empty() && out.back() != '-')
            out += '-';
        if (out.size() >= 32)
            break;
    }
    return out.empty() ? "x" : out;
}

} // namespace

TerminalGateway::TerminalGateway(HubApp& hub) : hub_(hub) {
    recordingsDir_ =
        (std::filesystem::path(hub_.config().databasePath).parent_path() / "recordings").string();
    std::error_code ec;
    std::filesystem::create_directories(recordingsDir_, ec);
    std::filesystem::permissions(recordingsDir_, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
}

double TerminalGateway::elapsed(const Session& s) const {
    return monoSeconds() - s.startedMono;
}

TerminalGateway::SessionPtr TerminalGateway::find(const std::string& sid) {
    std::lock_guard lk(mu_);
    auto it = sessions_.find(sid);
    return it == sessions_.end() ? nullptr : it->second;
}

std::size_t TerminalGateway::activeCount() {
    std::lock_guard lk(mu_);
    return sessions_.size();
}

void TerminalGateway::onConnect(const drogon::HttpRequestPtr& req,
                                const WebSocketConnectionPtr& conn) {
    const auto t = HubApp::now();
    // CSRF: 다른 사이트가 사용자의 쿠키로 터미널 WebSocket을 열지 못하게
    if (req->getHeader("Origin") != hub_.config().origin())
        return rejectBrowser(conn, "잘못된 요청 출처");
    auto sess = hub_.currentSession(req, t);
    if (!sess)
        return rejectBrowser(conn, "로그인이 필요합니다");
    auto payload = takePending(hub_.db(), req->getParameter("ticket"), "term", t);
    if (!payload)
        return rejectBrowser(conn, "터미널 티켓이 없거나 만료되었습니다. 다시 여세요");
    Json::Value p;
    if (!parseJson(*payload, p) || jsonInt(p, "user_id") != sess->userId)
        return rejectBrowser(conn, "다른 사용자의 티켓입니다");
    // 티켓을 받은 뒤 권한이 바뀌었을 수 있다
    if (!hub_.access(*sess).node(jsonInt(p, "node_id")))
        return rejectBrowser(conn, "이 서버의 권한이 없습니다");

    auto s = std::make_shared<Session>();
    s->sid = randomToken(12);
    s->nodeId = p["node_id"].asInt64();
    s->nodeName = p["node_name"].asString();
    s->user = p["user"].asString();
    s->userId = sess->userId;
    s->ip = hub_.clientIp(req);
    s->browser = conn;
    s->startedAt = t;
    s->startedMono = monoSeconds();
    const int cols = p.get("cols", 80).asInt(), rows = p.get("rows", 24).asInt();

    char stamp[32];
    std::tm tm{};
    const std::time_t tt = static_cast<std::time_t>(t);
    gmtime_r(&tt, &tm);
    std::strftime(stamp, sizeof stamp, "%Y%m%d-%H%M%S", &tm);
    s->recName =
        std::string(stamp) + "-" + slug(s->nodeName) + "-" + slug(s->user) + "-" + s->sid + ".cast";
    s->rec = std::make_unique<Recorder>(recordingsDir_ + "/" + s->recName, cols, rows, t,
                                        s->nodeName + " " + s->user);
    if (!s->rec->ok())
        LOG_WARN << "터미널 녹화 파일을 만들 수 없음: " << s->recName;

    {
        auto u = findUserById(hub_.db(), s->userId);
        std::lock_guard lk(mu_);
        sessions_[s->sid] = s;
        history_.push_back({s->sid, s->nodeId, u ? u->email : "", t, 0});
        if (history_.size() > 500)
            history_.pop_front();
    }
    conn->setContext(s);

    Json::Value open;
    open["type"] = "term_open";
    open["sid"] = s->sid;
    open["user"] = s->user;
    open["cols"] = cols;
    open["rows"] = rows;
    // 사용자의 패스키 서명 (Agent가 신뢰 목록으로 직접 확인한 뒤에만 셸을 띄운다)
    open["auth"] = p["auth"];
    if (!hub_.agents().send(s->nodeId, open))
        return finish(s, -1, "서버가 Douve에 접속해 있지 않습니다");
    audit(hub_.db(), s->userId, "terminal_opened", s->ip,
          s->nodeName + " " + s->user + " " + s->sid, t);

    std::weak_ptr<Session> weak = s;
    drogon::app().getLoop()->runAfter(15.0, [this, weak]() {
        if (auto x = weak.lock(); x && !x->opened && !x->done)
            finish(x, -1, "서버에서 터미널이 열리지 않았습니다 (시간 초과)");
    });
}

void TerminalGateway::onMessage(const WebSocketConnectionPtr& conn, std::string&& message,
                                const drogon::WebSocketMessageType& type) {
    if (type != drogon::WebSocketMessageType::Text || message.size() > 128 * 1024)
        return;
    auto s = conn->getContext<Session>();
    if (!s || s->done)
        return;
    Json::Value m;
    if (!parseJson(message, m) || !m.isObject())
        return;
    const std::string kind = jsonStr(m, "t");
    Json::Value out;
    out["sid"] = s->sid;
    if (kind == "in") {
        out["type"] = "term_in";
        out["data"] = jsonStr(m, "d");
    } else if (kind == "resize") {
        out["type"] = "term_resize";
        out["cols"] = static_cast<int>(std::clamp<std::int64_t>(jsonInt(m, "c", 80), 1, 1000));
        out["rows"] = static_cast<int>(std::clamp<std::int64_t>(jsonInt(m, "r", 24), 1, 1000));
        if (s->rec)
            s->rec->resize(out["cols"].asInt(), out["rows"].asInt(), elapsed(*s));
    } else {
        return;
    }
    hub_.agents().send(s->nodeId, out);
}

void TerminalGateway::onClosed(const WebSocketConnectionPtr& conn) {
    auto s = conn->getContext<Session>();
    if (!s || s->done)
        return;
    Json::Value close;
    close["type"] = "term_close";
    close["sid"] = s->sid;
    hub_.agents().send(s->nodeId, close);
    finish(s, 0, "");
}

void TerminalGateway::fromAgent(std::int64_t nodeId, const Json::Value& msg) {
    auto s = find(msg.get("sid", "").asString());
    // 다른 노드의 세션에 끼어들 수 없도록 노드 일치 확인
    if (!s || s->nodeId != nodeId || s->done)
        return;
    const std::string kind = msg.get("type", "").asString();
    auto browser = s->browser.lock();
    if (kind == "term_opened") {
        s->opened = true;
        Json::Value v;
        v["t"] = "opened";
        sendBrowser(browser, v);
    } else if (kind == "term_out") {
        const std::string b64 = msg.get("data", "").asString();
        if (s->rec) {
            // Agent는 표준 base64를 쓴다
            std::string std64 = b64;
            for (auto& c : std64)
                c = c == '+' ? '-' : c == '/' ? '_' : c;
            while (!std64.empty() && std64.back() == '=')
                std64.pop_back();
            if (auto raw = base64UrlDecode(std64)) {
                s->outBytes += raw->size();
                s->rec->output(std::string(raw->begin(), raw->end()), elapsed(*s));
            }
        }
        Json::Value v;
        v["t"] = "out";
        v["d"] = b64;
        sendBrowser(browser, v);
    } else if (kind == "term_exit") {
        finish(s, msg.get("code", 0).asInt(), msg.get("error", "").asString());
    }
}

void TerminalGateway::nodeDisconnected(std::int64_t nodeId) {
    std::vector<SessionPtr> victims;
    {
        std::lock_guard lk(mu_);
        for (auto& [sid, s] : sessions_)
            if (s->nodeId == nodeId)
                victims.push_back(s);
    }
    for (auto& s : victims)
        finish(s, -1, "서버와의 연결이 끊겼습니다");
}

void TerminalGateway::finish(const SessionPtr& s, int code, const std::string& error) {
    {
        std::lock_guard lk(mu_);
        if (s->done)
            return;
        s->done = true;
        sessions_.erase(s->sid);
        for (auto& r : history_)
            if (r.sid == s->sid)
                r.end = HubApp::now();
    }
    const auto t = HubApp::now();
    std::ostringstream detail;
    detail << s->nodeName << " " << s->user << " " << s->sid << " " << (t - s->startedAt) << "초 "
           << s->outBytes << "B";
    if (!error.empty())
        detail << " (" << error << ")";
    audit(hub_.db(), s->userId, "terminal_closed", s->ip, detail.str(), t);
    s->rec.reset();
    if (auto browser = s->browser.lock(); browser && browser->connected()) {
        Json::Value v;
        v["t"] = "exit";
        v["code"] = code;
        v["error"] = error;
        sendBrowser(browser, v);
        browser->shutdown(drogon::CloseCode::kNormalClosure, "closed");
    }
}

std::string TerminalGateway::userForSid(const std::string& sid) {
    std::lock_guard lk(mu_);
    for (const auto& r : history_)
        if (r.sid == sid)
            return r.email;
    return {};
}

std::string TerminalGateway::userActiveAt(std::int64_t nodeId, std::int64_t ts) {
    std::lock_guard lk(mu_);
    for (const auto& r : history_) {
        // 열기 1분 전 ~ 닫은 뒤 2분 (로그·파일 감시 지연 고려)
        if (r.nodeId == nodeId && ts >= r.start - 60 && (r.end == 0 || ts <= r.end + 120))
            return r.email;
    }
    return {};
}

void TerminalGateway::purgeRecordings(std::int64_t olderThanUnix) {
    std::error_code ec;
    for (const auto& e : std::filesystem::directory_iterator(recordingsDir_, ec)) {
        if (e.path().extension() != ".cast")
            continue;
        const auto mtime = std::chrono::duration_cast<std::chrono::seconds>(
                               e.last_write_time(ec).time_since_epoch() -
                               std::filesystem::file_time_type::clock::now().time_since_epoch())
                               .count() +
                           std::time(nullptr);
        if (mtime < olderThanUnix)
            std::filesystem::remove(e.path(), ec);
    }
}

void TerminalGateway::handleNewConnection(const drogon::HttpRequestPtr& req,
                                          const WebSocketConnectionPtr& conn) {
    try {
        onConnect(req, conn);
    } catch (const std::exception& e) {
        LOG_WARN << "WebSocket 접속 처리 실패 terminal: " << e.what();
        conn->forceClose();
    }
}

void TerminalGateway::handleNewMessage(const WebSocketConnectionPtr& conn, std::string&& message,
                                       const drogon::WebSocketMessageType& type) {
    try {
        onMessage(conn, std::move(message), type);
    } catch (const std::exception& e) {
        LOG_WARN << "WebSocket 메시지 처리 실패 terminal: " << e.what();
        conn->forceClose();
    }
}

void TerminalGateway::handleConnectionClosed(const WebSocketConnectionPtr& conn) {
    try {
        onClosed(conn);
    } catch (const std::exception& e) {
        LOG_WARN << "WebSocket 종료 처리 실패 terminal: " << e.what();
    }
}

} // namespace douve
