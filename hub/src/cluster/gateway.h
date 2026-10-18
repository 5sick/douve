#pragma once
// Agent WebSocket 게이트웨이 (/api/agent/connect).
//   1) 접속 즉시 Hub가 {"type":"challenge","nonce"} 전송
//   2) Agent가 {"type":"auth","node_id","sig"} 응답.
//      sig = Ed25519(agentAuthMessage(nonce, node_id)). 10초 안에 인증하지 못하면 끊는다.
//   3) 이후 metrics(10초)·inventory(60초) 메시지 수신.

#include <drogon/WebSocketController.h>

#include <cstdint>
#include <map>
#include <mutex>
#include <string>

namespace douve {

class HubApp;

std::string agentAuthMessage(const std::string& nonce, std::int64_t nodeId);

class AgentGateway : public drogon::WebSocketController<AgentGateway, false> {
  public:
    explicit AgentGateway(HubApp& hub) : hub_(hub) {}

    void handleNewConnection(const drogon::HttpRequestPtr& req,
                             const drogon::WebSocketConnectionPtr& conn) override;
    void handleNewMessage(const drogon::WebSocketConnectionPtr& conn, std::string&& message,
                          const drogon::WebSocketMessageType& type) override;
    void handleConnectionClosed(const drogon::WebSocketConnectionPtr& conn) override;

  private:
    // 위 세 진입점은 예외를 잡아 해당 접속만 끊는다 (이벤트 루프 밖으로 새면 Hub 전체가 죽는다).
    void onConnect(const drogon::HttpRequestPtr& req, const drogon::WebSocketConnectionPtr& conn);
    void onMessage(const drogon::WebSocketConnectionPtr& conn, std::string&& message,
                   const drogon::WebSocketMessageType& type);
    void onClosed(const drogon::WebSocketConnectionPtr& conn);

  public:
    // 노드 삭제 시 접속을 끊는다.
    void disconnect(std::int64_t nodeId);
    // 인증된 Agent에 메시지 전송. 접속 중이 아니면 false.
    bool send(std::int64_t nodeId, const Json::Value& msg);
    void broadcast(const Json::Value& msg);

    WS_PATH_LIST_BEGIN
    WS_PATH_ADD("/api/agent/connect", drogon::Get);
    WS_PATH_LIST_END

  private:
    struct Ctx {
        std::string nonce;
        std::string ip;
        std::int64_t nodeId = 0; // 0 = 인증 전
        std::int64_t lastTouch = 0;
    };
    void onAuth(const drogon::WebSocketConnectionPtr& conn, Ctx& ctx, const Json::Value& msg);
    void dispatch(const drogon::WebSocketConnectionPtr& conn, Ctx& ctx, const std::string& kind,
                  Json::Value& msg);

    HubApp& hub_;
    std::mutex mu_;
    std::map<std::int64_t, drogon::WebSocketConnectionPtr> conns_;
};

} // namespace douve
