#include "cluster/gateway.h"
#include "util/i18n.h"

#include "app.h"
#include "cluster/live.h"
#include "cluster/release.h"
#include "cluster/security.h"
#include "cluster/terminal.h"
#include "store/nodes.h"
#include "store/repo.h"
#include "util/crypto.h"

#include <drogon/drogon.h>

namespace douve {

using drogon::WebSocketConnectionPtr;

std::string agentAuthMessage(const std::string& nonce, std::int64_t nodeId) {
    return "douve-agent-auth:v1:" + nonce + ":" + std::to_string(nodeId);
}

namespace {

void sendJson(const WebSocketConnectionPtr& conn, const Json::Value& v) {
    Json::StreamWriterBuilder w;
    w["indentation"] = "";
    conn->send(Json::writeString(w, v));
}

void reject(const WebSocketConnectionPtr& conn, const std::string& why) {
    Json::Value v;
    v["type"] = "error";
    v["error"] = why;
    sendJson(conn, v);
    conn->shutdown(drogon::CloseCode::kViolation, why);
}

} // namespace

void AgentGateway::handleNewConnection(const drogon::HttpRequestPtr& req,
                                       const WebSocketConnectionPtr& conn) {
    auto ctx = std::make_shared<Ctx>();
    ctx->nonce = randomToken(32);
    ctx->ip = hub_.clientIp(req);
    conn->setContext(ctx);
    conn->setPingMessage("", std::chrono::seconds(30));

    Json::Value v;
    v["type"] = "challenge";
    v["nonce"] = ctx->nonce;
    sendJson(conn, v);

    std::weak_ptr<drogon::WebSocketConnection> weak = conn;
    drogon::app().getLoop()->runAfter(10.0, [weak]() {
        auto c = weak.lock();
        if (c && c->connected() && c->getContextRef<Ctx>().nodeId == 0)
            reject(c, "인증 시간 초과");
    });
}

void AgentGateway::onAuth(const WebSocketConnectionPtr& conn, Ctx& ctx, const Json::Value& msg) {
    const auto t = HubApp::now();
    const std::int64_t nodeId = msg.get("node_id", 0).asInt64();
    auto sig = base64UrlDecode(msg.get("sig", "").asString());
    auto node = nodeId > 0 ? findNode(hub_.db(), nodeId) : std::nullopt;
    if (!node || !sig || !ed25519Verify(node->pubkey, agentAuthMessage(ctx.nonce, nodeId), *sig)) {
        audit(hub_.db(), std::nullopt, "agent_auth_failed", ctx.ip, std::to_string(nodeId), t);
        return reject(conn, "인증 실패");
    }
    ctx.nodeId = nodeId;
    ctx.lastTouch = t;
    WebSocketConnectionPtr old;
    {
        std::lock_guard lk(mu_);
        auto& slot = conns_[nodeId];
        old = slot;
        slot = conn;
    }
    if (old && old != conn)
        old->shutdown(drogon::CloseCode::kNormalClosure, "새 접속으로 대체됨");
    touchNode(hub_.db(), nodeId, ctx.ip, msg.get("version", "").asString().substr(0, 32), t);
    hub_.live().setConnected(nodeId, true, t);
    LOG_INFO << "Agent 접속: " << node->name << " (" << ctx.ip << ")";

    Json::Value v;
    v["type"] = "welcome";
    v["name"] = node->name;
    v["metrics_interval"] = 10;
    v["inventory_interval"] = 60;
    v["features"] = hub_.settings().features().toJson();
    sendJson(conn, v);

    hub_.pushRoutes(nodeId); // 입구면 라우팅 표, 모든 노드에 터널·상태 확인 설정

    // Hub가 가진 Agent와 버전이 다르면 업데이트 지시 (Agent가 체크섬 확인 후 교체·재시작)
    const std::string agentVersion = msg.get("version", "").asString();
    if (auto rel = loadAgentRelease(hub_.config().agentDir);
        rel && !agentVersion.empty() && agentVersion != rel->version) {
        auto it = rel->sha256.find(node->arch);
        if (it != rel->sha256.end()) {
            Json::Value u;
            u["type"] = "update";
            u["version"] = rel->version;
            u["path"] = "/dl/douve-agent-linux-" + node->arch;
            u["sha256"] = it->second;
            sendJson(conn, u);
            LOG_INFO << "Agent 업데이트 지시: " << node->name << " " << agentVersion << " → "
                     << rel->version;
        }
    }
}

void AgentGateway::handleNewMessage(const WebSocketConnectionPtr& conn, std::string&& message,
                                    const drogon::WebSocketMessageType& type) {
    if (type != drogon::WebSocketMessageType::Text)
        return;
    auto ctxp = conn->getContext<Ctx>();
    if (!ctxp)
        return;
    Ctx& ctx = *ctxp;

    Json::Value msg;
    Json::CharReaderBuilder rb;
    std::string err;
    std::unique_ptr<Json::CharReader> reader(rb.newCharReader());
    if (!reader->parse(message.data(), message.data() + message.size(), &msg, &err) ||
        !msg.isObject())
        return reject(conn, "잘못된 메시지");
    const std::string kind = msg.get("type", "").asString();

    if (ctx.nodeId == 0) {
        if (kind != "auth")
            return reject(conn, "인증이 필요합니다");
        return onAuth(conn, ctx, msg);
    }

    // 메시지 하나의 처리 실패(DB 오류 등)가 Hub 전체를 죽이지 않도록
    try {
        dispatch(conn, ctx, kind, msg);
    } catch (const std::exception& e) {
        LOG_ERROR << "Agent 메시지 처리 실패 (node " << ctx.nodeId << ", " << kind
                  << "): " << e.what();
    }
}

void AgentGateway::dispatch(const WebSocketConnectionPtr& conn, Ctx& ctx, const std::string& kind,
                            Json::Value& msg) {
    if (kind.rfind("term_", 0) == 0)
        return hub_.terminals().fromAgent(ctx.nodeId, msg);
    if (kind == "security")
        return hub_.ingestSecurityEvents(ctx.nodeId, msg);
    if (kind == "service_health")
        return hub_.ingestServiceHealth(ctx.nodeId, msg);
    if (kind == "portmap_status")
        return hub_.ingestPortmap(ctx.nodeId, msg["status"]);
    if (kind == "expose_req") {
        Json::Value res = hub_.handleExpose(ctx.nodeId, msg);
        // CLI 언어로 (douve-agent expose를 실행한 터미널의 LANG)
        const std::string lang = msg.get("lang", "").asString();
        for (const char* k : {"error", "warning"})
            if (res.isMember(k))
                res[k] = i18n::translate(res[k].asString(), lang);
        res["type"] = "expose_res";
        res["rid"] = msg.get("rid", "").asString().substr(0, 40);
        return sendJson(conn, res);
    }
    const auto t = HubApp::now();
    if (kind == "metrics") {
        if (auto s = parseSample(msg, t))
            hub_.live().addSample(ctx.nodeId, *s);
    } else if (kind == "inventory") {
        Json::StreamWriterBuilder w;
        w["indentation"] = "";
        msg.removeMember("type");
        const std::string invJson = Json::writeString(w, msg);
        saveInventory(hub_.db(), ctx.nodeId, invJson);
        hub_.live().setInventory(ctx.nodeId, msg);
        if (auto mesh = pickMeshAddress(invJson); !mesh.empty())
            hub_.updateMeshAddress(ctx.nodeId, mesh);
    }
    // 접속 유지 기록은 1분에 한 번만 DB에
    if (t - ctx.lastTouch >= 60) {
        touchNode(hub_.db(), ctx.nodeId, ctx.ip, "", t);
        ctx.lastTouch = t;
    }
}

void AgentGateway::handleConnectionClosed(const WebSocketConnectionPtr& conn) {
    auto ctxp = conn->getContext<Ctx>();
    if (!ctxp || ctxp->nodeId == 0)
        return;
    bool current = false;
    {
        std::lock_guard lk(mu_);
        auto it = conns_.find(ctxp->nodeId);
        if (it != conns_.end() && it->second == conn) {
            conns_.erase(it);
            current = true;
        }
    }
    if (current) {
        const auto t = HubApp::now();
        touchNode(hub_.db(), ctxp->nodeId, ctxp->ip, "", t);
        hub_.live().setConnected(ctxp->nodeId, false, t);
        hub_.terminals().nodeDisconnected(ctxp->nodeId);
        LOG_INFO << "Agent 접속 종료: node " << ctxp->nodeId;
    }
}

void AgentGateway::broadcast(const Json::Value& msg) {
    std::vector<WebSocketConnectionPtr> all;
    {
        std::lock_guard lk(mu_);
        for (auto& [id, c] : conns_)
            all.push_back(c);
    }
    for (auto& c : all)
        sendJson(c, msg);
}

bool AgentGateway::send(std::int64_t nodeId, const Json::Value& msg) {
    WebSocketConnectionPtr c;
    {
        std::lock_guard lk(mu_);
        auto it = conns_.find(nodeId);
        if (it == conns_.end())
            return false;
        c = it->second;
    }
    sendJson(c, msg);
    return true;
}

void AgentGateway::disconnect(std::int64_t nodeId) {
    WebSocketConnectionPtr c;
    {
        std::lock_guard lk(mu_);
        auto it = conns_.find(nodeId);
        if (it == conns_.end())
            return;
        c = it->second;
        conns_.erase(it);
    }
    c->shutdown(drogon::CloseCode::kNormalClosure, "노드 삭제됨");
}

} // namespace douve
