#pragma once
// 웹 터미널 중계 (/api/terminal/ws). 브라우저 ⇄ Hub ⇄ Agent(기존 WebSocket에 다중화).
//   1) 브라우저가 패스키 재확인 후 /api/terminal/ticket으로 1회용 티켓을 받는다 (60초).
//   2) 티켓 + 세션 쿠키 + Origin으로 이 WebSocket에 접속 → Hub가 Agent에 term_open.
//   3) 출력은 asciicast로 녹화(입력은 기록하지 않음), 열기·닫기는 감사 로그에 남긴다.
// 브라우저 메시지: {"t":"in","d":b64} {"t":"resize","c":열,"r":행}
// Hub→브라우저:    {"t":"opened"} {"t":"out","d":b64} {"t":"exit","code":n,"error":"…"}

#include "cluster/recording.h"

#include <drogon/WebSocketController.h>
#include <json/json.h>

#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>

namespace douve {

class HubApp;

class TerminalGateway : public drogon::WebSocketController<TerminalGateway, false> {
  public:
    explicit TerminalGateway(HubApp& hub);

    void handleNewConnection(const drogon::HttpRequestPtr& req,
                             const drogon::WebSocketConnectionPtr& conn) override;
    void handleNewMessage(const drogon::WebSocketConnectionPtr& conn, std::string&& message,
                          const drogon::WebSocketMessageType& type) override;
    void handleConnectionClosed(const drogon::WebSocketConnectionPtr& conn) override;

    // Agent에서 온 term_opened / term_out / term_exit
    void fromAgent(std::int64_t nodeId, const Json::Value& msg);
    // Agent 연결이 끊기면 그 노드의 터미널을 모두 닫는다.
    void nodeDisconnected(std::int64_t nodeId);
    std::size_t activeCount();

    std::string recordingsDir() const { return recordingsDir_; }
    // 보안 감시용: 세션 ID → 사용자 이메일, 그 시각 전후로 노드에서 터미널을 쓰던 사용자
    std::string userForSid(const std::string& sid);
    std::string userActiveAt(std::int64_t nodeId, std::int64_t ts);
    void purgeRecordings(std::int64_t olderThanUnix);

    WS_PATH_LIST_BEGIN
    WS_PATH_ADD("/api/terminal/ws", drogon::Get);
    WS_PATH_LIST_END

  private:
    struct Session {
        std::string sid;
        std::int64_t nodeId = 0;
        std::string nodeName, user;
        std::int64_t userId = 0;
        std::string ip;
        std::weak_ptr<drogon::WebSocketConnection> browser;
        std::int64_t startedAt = 0;
        double startedMono = 0;
        std::unique_ptr<Recorder> rec;
        std::string recName;
        std::size_t outBytes = 0;
        bool opened = false;
        bool done = false;
    };
    using SessionPtr = std::shared_ptr<Session>;

    void finish(const SessionPtr& s, int code, const std::string& error);
    SessionPtr find(const std::string& sid);
    double elapsed(const Session& s) const;

    HubApp& hub_;
    std::string recordingsDir_;
    std::mutex mu_;
    std::map<std::string, SessionPtr> sessions_;
    struct Record {
        std::string sid;
        std::int64_t nodeId = 0;
        std::string email;
        std::int64_t start = 0, end = 0; // end 0 = 진행 중
    };
    std::deque<Record> history_; // 최근 500개
};

} // namespace douve
