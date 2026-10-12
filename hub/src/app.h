#pragma once

#include "auth/google.h"
#include "auth/ratelimit.h"
#include "auth/session.h"
#include "cluster/live.h"
#include "config.h"
#include "settings.h"
#include "store/db.h"
#include "store/nodes.h"

#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <json/json.h>

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <set>

namespace douve {

class AgentGateway;
class TerminalGateway;
class IconCache;

// Hub의 모든 상태를 묶는 객체. main에서 하나 만들어 라우트를 등록한다.
class HubApp {
  public:
    explicit HubApp(HubConfig cfg);
    ~HubApp();

    void registerRoutes();
    void registerPasskeyRoutes();
    void registerAccountRoutes();
    void registerNodeRoutes();
    void registerServiceRoutes();
    void registerTerminalRoutes();
    void registerSettingsRoutes();
    void registerSecurityRoutes();
    void registerHomeRoutes();
    void ingestSecurityEvents(std::int64_t nodeId, const Json::Value& msg);
    // 노드의 `douve-agent expose` 요청 처리 (응답 JSON)
    Json::Value handleExpose(std::int64_t nodeId, const Json::Value& req);
    AgentGateway& agents() { return *gateway_; }
    TerminalGateway& terminals() { return *terminal_; }
    // 입구(edge) Agent에 라우팅 표 전송. nodeId가 0이면 접속 중인 모든 edge에.
    void pushRoutes(std::int64_t nodeId = 0);
    Json::Value buildRoutes();
    std::string tunnelUrl() const;
    Json::Value buildTunnelConfig(const Node& n);
    // Agent가 보낸 서비스 상태 확인 결과
    void ingestServiceHealth(std::int64_t nodeId, const Json::Value& msg);
    // 공유기 포트 자동 열기: 노드에 보낼 원하는 포트, Agent가 보낸 결과, 화면용 상태
    Json::Value buildPortmap(const Node& n);
    void ingestPortmap(std::int64_t nodeId, const Json::Value& status);
    Json::Value portmapJson(std::int64_t nodeId);
    void registerPortmapRoutes();
    void registerChannelRoutes();
    // Agent 인벤토리에서 메시 주소가 바뀌면 저장하고 신뢰 프록시 목록을 갱신.
    void updateMeshAddress(std::int64_t nodeId, const std::string& address);
    void refreshEdgeAddresses();
    // 1분 메트릭 저장, 알림 평가 같은 주기 작업. drogon::app().run() 직전에 호출.
    void startBackgroundTasks();
    // 텔레그램 알림 (설정이 없으면 로그만).
    void notify(const std::string& text);
    // 알림 언어 (웹 설정 > hub.json language > ko)
    std::string language();
    LiveState& live() { return live_; }
    RuntimeSettings& settings() { return settings_; }
    const HubConfig& config() const { return cfg_; }
    Database& db() { return *db_; }
    SessionManager& sessions() { return *sessions_; }

    // 프록시를 고려한 실제 클라이언트 IP.
    std::string clientIp(const drogon::HttpRequestPtr& req) const;
    // 요청의 세션 쿠키를 검증한다.
    std::optional<SessionInfo> currentSession(const drogon::HttpRequestPtr& req, std::int64_t now);
    std::optional<std::string> sessionToken(const drogon::HttpRequestPtr& req) const;
    std::optional<SessionInfo> tailscaleSession(const drogon::HttpRequestPtr& req,
                                                std::int64_t now);

    static std::int64_t now();

    // 허용 이메일: 설정 파일 allowed_emails 또는 초대를 수락한 사용자
    bool emailAllowed(const std::string& email);
    // CSRF 방어: 상태를 바꾸는 요청은 Hub 자신의 origin에서 온 것이어야 한다.
    bool sameOrigin(const drogon::HttpRequestPtr& req) const;
    // 로그인 관련 요청 횟수 제한. 초과하면 false (감사 로그 기록).
    bool loginAllowed(const drogon::HttpRequestPtr& req);
    // 로그인 성공 처리: 세션 발급 + 감사 로그, 응답에 세션·기기 쿠키를 싣는다.
    // 같은 기기(douve_device 쿠키)에서 이전에 만든 이 사용자의 세션은 정리된다.
    void startSession(const drogon::HttpRequestPtr& req, const drogon::HttpResponsePtr& resp,
                      std::int64_t userId, const std::string& method);
    // startSession + 쿠키를 실은 리다이렉트 응답.
    drogon::HttpResponsePtr finishLogin(const drogon::HttpRequestPtr& req, std::int64_t userId,
                                        const std::string& method, const std::string& redirectTo);

  private:
    HubConfig cfg_;
    std::unique_ptr<Database> db_;
    std::unique_ptr<SessionManager> sessions_;
    std::unique_ptr<GoogleOidc> google_;
    // 로그인 시도 제한: IP당 5분에 30회 (패스키·Google 공통)
    RateLimiter loginLimiter_{30, 300};
    // Agent 등록 시도 제한: IP당 5분에 20회
    RateLimiter enrollLimiter_{20, 300};
    LiveState live_;
    RuntimeSettings settings_;
    std::shared_ptr<AgentGateway> gateway_;
    std::shared_ptr<TerminalGateway> terminal_;
    std::unique_ptr<IconCache> icons_;
    std::int64_t startedAt_ = 0;
    std::atomic<bool> backupRunning_{false};

    // 입구 노드의 메시 주소 = 신뢰 프록시 (X-Real-IP 인정)
    mutable std::mutex edgeMu_;
    std::set<std::string> edgeAddresses_;
    // 서비스 상태 확인 결과 (메모리)
    struct ServiceHealth {
        int fails = 0;
        long status = 0;
        std::string error;
        std::int64_t checkedAt = 0;
        double latencyMs = 0;
    };
    std::mutex portmapMu_;
    std::map<std::int64_t, Json::Value> portmap_; // 노드별 마지막 공유기 상태
    std::mutex healthMu_;
    std::map<std::int64_t, ServiceHealth> health_;
    void tickServices(std::int64_t now);
    std::string lastRoutes_; // 마지막으로 확인한 라우팅 표 (변경 감지용)

    void tickMinute(std::int64_t now);
    void tickAlerts(std::int64_t now);
};

} // namespace douve
