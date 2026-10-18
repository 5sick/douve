#pragma once

#include "auth/google.h"
#include "auth/ratelimit.h"
#include "auth/session.h"
#include "cluster/alerts.h"
#include "cluster/live.h"
#include "config.h"
#include "settings.h"
#include "store/access.h"
#include "store/db.h"
#include "store/nodes.h"
#include "store/services.h"

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
class FileGateway;
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
    FileGateway& files() { return *files_; }
    // 입구(edge) Agent에 라우팅 표 전송. nodeId가 0이면 접속 중인 모든 edge에.
    void pushRoutes(std::int64_t nodeId = 0);
    Json::Value buildRoutes();
    Json::Value routeJson(const Service& s);
    // 내부 길: 맡을 입구, 라우팅 표에 실을 설정(꺼져 있으면 null), Agent 상태 보고
    std::optional<Node> devnetGateway();
    Json::Value buildDevnet();
    void ingestDevnetStatus(std::int64_t nodeId, const Json::Value& msg);
    void registerDevnetRoutes();
    // 보안 점검표: Agent 결과 저장, 고치기 결과
    void ingestCheckup(std::int64_t nodeId, const Json::Value& msg);
    void ingestCheckupFixed(std::int64_t nodeId, const Json::Value& msg);
    void registerCheckupRoutes();
    void registerFileRoutes();
    // 연결 진단·외부 접속 검증 (routes_reach.cc)
    void registerReachRoutes();
    void ingestReach(std::int64_t nodeId, const Json::Value& msg);
    void ingestReachProbe(std::int64_t nodeId, const Json::Value& msg);
    void verifyReach(std::int64_t nodeId, std::function<void(const Json::Value&)> done);
    std::string nodePublicIp(const Node& n);
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
    void registerUserRoutes(); // 사용자·역할 관리 + /api/* 공통 권한 검사
    // 터미널 신뢰 목록 (cluster/term_trust.h). 첫 판이 없으면 만든다.
    std::string desiredTrust(std::int64_t version);
    struct TrustState {
        std::int64_t version = 0; // Hub의 최신 판
        bool pending = false;     // 승인(관리자 패스키 서명)을 기다리는 변경이 있음
        std::string snapshot;
    };
    TrustState trustState();
    // Agent에 신뢰 목록 전송. nodeId가 0이면 접속 중인 모든 Agent에.
    void pushTrust(std::int64_t nodeId = 0);
    void ingestTrustStatus(std::int64_t nodeId, const Json::Value& msg);
    void sendTrust(std::int64_t nodeId); // trustState() 없이 지금 판들만 보낸다
    Json::Value trustStatusJson();
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
    // 로그인한 사람의 역할·권한 (요청마다 DB에서 — 바꾸면 바로 적용)
    // hub.json allowed_emails의 사람은 서버 root가 정한 관리자라 항상 admin.
    Access access(const SessionInfo& s);
    Json::Value summaryJson(const Access& acc);
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
    std::shared_ptr<FileGateway> files_;
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
    // 노드별 유닛 연속 실패 시작 시각 (tickAlerts 전용)
    std::map<std::int64_t, UnitTracker> unitSeen_;
    void tickServices(std::int64_t now);
    std::string lastRoutes_; // 마지막으로 확인한 라우팅 표 (변경 감지용)
    // Agent가 알려 준 터미널 신뢰 목록 버전·거부 사유 (메모리)
    struct NodeTrust {
        std::int64_t version = 0;
        std::string error;
        std::int64_t at = 0;
    };
    // 내부 길 기기 연결 상태 (공개키 → 마지막 핸드셰이크 등, 입구가 30초마다 보고)
    std::mutex reachMu_;
    std::map<std::int64_t, std::set<std::int64_t>> edgeTunnels_; // 입구 → 터널이 붙은 노드
    struct ProbeWait {
        std::int64_t nodeId = 0;
        Json::Value result;
        std::function<void(const Json::Value&)> done;
    };
    std::map<std::string, ProbeWait> probes_;
    struct ReachAlert {
        bool ssh = false, edgeDown = false;
        int edgeFails = 0;
    };
    std::map<std::int64_t, ReachAlert> reachAlerts_;
    void finishProbe(const std::string& rid, const Json::Value& msg);
    void alertReach(std::int64_t nodeId, const Json::Value& r);
    std::mutex fixMu_;
    std::map<std::string, Json::Value> fixes_; // 고치기 요청 rid → 상태 (메모리)
    std::mutex devnetMu_;
    std::map<std::string, Json::Value> devnetPeers_;
    bool devnetRunning_ = false;
    std::mutex trustMu_;
    std::map<std::int64_t, NodeTrust> nodeTrust_;

    void tickMinute(std::int64_t now);
    void tickAlerts(std::int64_t now);

    // 감사 기록: 웹훅으로 내보내기 (채널별로 보낸 마지막 id는 설정 audit.fwd.<채널 id>)
    std::mutex auditMu_;
    std::set<std::int64_t> auditSending_; // 응답을 기다리는 채널
    void tickAuditExport(std::int64_t now);
    void sendAuditBatch(std::int64_t channelId);
    // 하루 한 번 체인 확인, 끊겼으면 알림 (같은 위치는 한 번만)
    void checkAuditChain();
};

} // namespace douve
