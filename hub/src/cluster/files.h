#pragma once
// 파일 올리기·내려받기 중계 (/api/files/ws). 브라우저 ⇄ Hub ⇄ Agent(기존 WebSocket에 다중화).
//   1. /api/files/options → 패스키로 "이 서버·계정·경로(·크기·SHA-256)"에 서명
//   2. /api/files/ticket (60초) → 티켓 + 세션 쿠키 + Origin으로 접속
//   3. Hub가 서명을 실어 Agent에 file_put / file_get → Agent가 신뢰 목록으로 다시 확인한 뒤
//      그 계정 권한으로 읽고 쓴다. 끝나면 감사 로그.
// 브라우저 메시지: {"t":"chunk","d":b64} {"t":"end"}
// Hub→브라우저:    {"t":"ready"} {"t":"ack","n":받은 바이트} {"t":"data","d":b64}
//                  {"t":"done","size":n,"sha256":"…"} {"t":"error","error":"…"}

#include <drogon/WebSocketController.h>
#include <json/json.h>

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>

namespace douve {

class HubApp;

// Agent의 files.ValidPath와 같은 규칙 (Agent가 다시 확인한다)
bool validTransferPath(const std::string& p);
// 패스키로 서명하는 작업 문자열 (Agent files.PutAction / GetAction과 같아야 한다)
std::string filePutAction(const std::string& user, std::int64_t size, const std::string& sha256,
                          const std::string& path);
std::string fileGetAction(const std::string& user, const std::string& path);

class FileGateway : public drogon::WebSocketController<FileGateway, false> {
  public:
    explicit FileGateway(HubApp& hub) : hub_(hub) {}

    void handleNewConnection(const drogon::HttpRequestPtr& req,
                             const drogon::WebSocketConnectionPtr& conn) override;
    void handleNewMessage(const drogon::WebSocketConnectionPtr& conn, std::string&& message,
                          const drogon::WebSocketMessageType& type) override;
    void handleConnectionClosed(const drogon::WebSocketConnectionPtr& conn) override;

    void fromAgent(std::int64_t nodeId, const Json::Value& msg);
    void nodeDisconnected(std::int64_t nodeId);

    WS_PATH_LIST_BEGIN
    WS_PATH_ADD("/api/files/ws", drogon::Get);
    WS_PATH_LIST_END

  private:
    struct Session {
        std::string sid, op, user, path, nodeName, ip;
        std::int64_t nodeId = 0, userId = 0, size = 0;
        std::weak_ptr<drogon::WebSocketConnection> browser;
        bool done = false;
    };
    using SessionPtr = std::shared_ptr<Session>;
    void onConnect(const drogon::HttpRequestPtr& req, const drogon::WebSocketConnectionPtr& conn);
    void finish(const SessionPtr& s, const Json::Value& result);

    HubApp& hub_;
    std::mutex mu_;
    std::map<std::string, SessionPtr> sessions_;
};

} // namespace douve
