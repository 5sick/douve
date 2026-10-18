#include "cluster/files.h"

#include "app.h"
#include "cluster/gateway.h"
#include "store/repo.h"
#include "util/crypto.h"
#include "util/json.h"

#include <drogon/drogon.h>

namespace douve {

using drogon::WebSocketConnectionPtr;

namespace {

std::string compact(const Json::Value& v) {
    Json::StreamWriterBuilder w;
    w["indentation"] = "";
    return Json::writeString(w, v);
}

void toBrowser(const WebSocketConnectionPtr& c, const Json::Value& v) {
    if (c && c->connected())
        c->send(compact(v));
}

void reject(const WebSocketConnectionPtr& c, const std::string& why) {
    Json::Value v;
    v["t"] = "error";
    v["error"] = why;
    toBrowser(c, v);
    c->shutdown(drogon::CloseCode::kViolation, "rejected");
}

bool endsWith(const std::string& s, const std::string& suf) {
    return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

} // namespace

bool validTransferPath(const std::string& p) {
    if (p.empty() || p.size() > 4096 || p.front() == '~' || p.back() == '/' || p == "." ||
        p == ".." || endsWith(p, "/.") || endsWith(p, "/.."))
        return false;
    for (unsigned char c : p)
        if (c < 0x20 || c == 0x7f)
            return false;
    return true;
}

std::string filePutAction(const std::string& user, std::int64_t size, const std::string& sha256,
                          const std::string& path) {
    return "file-put:" + user + ":" + std::to_string(size) + ":" + sha256 + ":" + path;
}

std::string fileGetAction(const std::string& user, const std::string& path) {
    return "file-get:" + user + ":" + path;
}

void FileGateway::onConnect(const drogon::HttpRequestPtr& req, const WebSocketConnectionPtr& conn) {
    const auto t = HubApp::now();
    if (req->getHeader("Origin") != hub_.config().origin())
        return reject(conn, "잘못된 요청 출처");
    auto sess = hub_.currentSession(req, t);
    if (!sess)
        return reject(conn, "로그인이 필요합니다");
    auto payload = takePending(hub_.db(), req->getParameter("ticket"), "file", t);
    Json::Value p;
    if (!payload || !parseJson(*payload, p) || jsonInt(p, "user_id") != sess->userId)
        return reject(conn, "티켓이 없거나 만료되었습니다. 다시 시도하세요");
    if (!hub_.access(*sess).node(jsonInt(p, "node_id")))
        return reject(conn, "이 서버의 권한이 없습니다");
    auto s = std::make_shared<Session>();
    s->sid = randomToken(12);
    s->op = jsonStr(p, "op");
    s->user = jsonStr(p, "user");
    s->path = jsonStr(p, "path");
    s->size = jsonInt(p, "size");
    s->nodeId = jsonInt(p, "node_id");
    s->nodeName = jsonStr(p, "node_name");
    s->userId = sess->userId;
    s->ip = hub_.clientIp(req);
    s->browser = conn;
    {
        std::lock_guard lk(mu_);
        sessions_[s->sid] = s;
    }
    conn->setContext(s);
    Json::Value m;
    m["type"] = s->op == "put" ? "file_put" : "file_get";
    m["sid"] = s->sid;
    m["user"] = s->user;
    m["path"] = s->path;
    if (s->op == "put") {
        m["size"] = Json::Int64(s->size);
        m["sha256"] = p["sha256"];
    }
    m["auth"] = p["auth"];
    if (!hub_.agents().send(s->nodeId, m)) {
        Json::Value e;
        e["error"] = "서버가 Douve에 접속해 있지 않습니다";
        return finish(s, e);
    }
}

void FileGateway::handleNewConnection(const drogon::HttpRequestPtr& req,
                                      const WebSocketConnectionPtr& conn) {
    try {
        onConnect(req, conn);
    } catch (const std::exception& e) {
        LOG_WARN << "WebSocket 접속 처리 실패 files: " << e.what();
        conn->forceClose();
    }
}

void FileGateway::handleNewMessage(const WebSocketConnectionPtr& conn, std::string&& message,
                                   const drogon::WebSocketMessageType& type) {
    try {
        if (type != drogon::WebSocketMessageType::Text || message.size() > 512 * 1024)
            return;
        auto s = conn->getContext<Session>();
        if (!s || s->done || s->op != "put")
            return;
        Json::Value m;
        if (!parseJson(message, m) || !m.isObject())
            return;
        const std::string kind = jsonStr(m, "t");
        Json::Value out;
        out["sid"] = s->sid;
        if (kind == "chunk") {
            out["type"] = "file_chunk";
            out["data"] = jsonStr(m, "d");
        } else if (kind == "end") {
            out["type"] = "file_end";
        } else {
            return;
        }
        hub_.agents().send(s->nodeId, out);
    } catch (const std::exception& e) {
        LOG_WARN << "WebSocket 메시지 처리 실패 files: " << e.what();
        conn->forceClose();
    }
}

void FileGateway::handleConnectionClosed(const WebSocketConnectionPtr& conn) {
    try {
        auto s = conn->getContext<Session>();
        if (!s || s->done)
            return;
        Json::Value c;
        c["type"] = "file_cancel";
        c["sid"] = s->sid;
        hub_.agents().send(s->nodeId, c);
        Json::Value e;
        e["error"] = "브라우저 연결이 끊겼습니다";
        finish(s, e);
    } catch (const std::exception& e) {
        LOG_WARN << "WebSocket 종료 처리 실패 files: " << e.what();
    }
}

void FileGateway::fromAgent(std::int64_t nodeId, const Json::Value& msg) {
    SessionPtr s;
    {
        std::lock_guard lk(mu_);
        auto it = sessions_.find(jsonStr(msg, "sid"));
        if (it != sessions_.end())
            s = it->second;
    }
    if (!s || s->nodeId != nodeId || s->done) // 다른 노드의 전송에 끼어들 수 없다
        return;
    const std::string kind = jsonStr(msg, "type");
    auto browser = s->browser.lock();
    Json::Value v;
    if (kind == "file_ready") {
        v["t"] = "ready";
    } else if (kind == "file_ack") {
        v["t"] = "ack";
        v["n"] = Json::Int64(jsonInt(msg, "bytes"));
    } else if (kind == "file_data" && s->op == "get") {
        v["t"] = "data";
        v["d"] = jsonStr(msg, "data");
    } else if (kind == "file_done") {
        Json::Value r;
        r["size"] = Json::Int64(jsonInt(msg, "size"));
        r["sha256"] = jsonStr(msg, "sha256").substr(0, 64);
        return finish(s, r);
    } else if (kind == "file_error") {
        Json::Value r;
        r["error"] = jsonStr(msg, "error").substr(0, 300);
        return finish(s, r);
    } else {
        return;
    }
    toBrowser(browser, v);
}

void FileGateway::nodeDisconnected(std::int64_t nodeId) {
    std::vector<SessionPtr> victims;
    {
        std::lock_guard lk(mu_);
        for (auto& [sid, s] : sessions_)
            if (s->nodeId == nodeId)
                victims.push_back(s);
    }
    Json::Value e;
    e["error"] = "서버와의 연결이 끊겼습니다";
    for (auto& s : victims)
        finish(s, e);
}

void FileGateway::finish(const SessionPtr& s, const Json::Value& result) {
    {
        std::lock_guard lk(mu_);
        if (s->done)
            return;
        s->done = true;
        sessions_.erase(s->sid);
    }
    const bool ok = !result.isMember("error");
    std::string detail = s->nodeName + " " + s->user + " " + s->path;
    if (ok)
        detail += " " + std::to_string(result["size"].asInt64()) +
                  "B sha256:" + result["sha256"].asString().substr(0, 16);
    else
        detail += " (" + result["error"].asString() + ")";
    audit(hub_.db(), s->userId,
          ok ? (s->op == "put" ? "file_uploaded" : "file_downloaded") : "file_transfer_failed",
          s->ip, detail, HubApp::now());
    if (auto b = s->browser.lock(); b && b->connected()) {
        Json::Value v = result;
        v["t"] = ok ? "done" : "error";
        toBrowser(b, v);
        b->shutdown(drogon::CloseCode::kNormalClosure, "done");
    }
}

} // namespace douve
