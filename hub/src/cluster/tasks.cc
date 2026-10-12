// Hub 주기 작업: 1분 메트릭 저장·보관 기간 정리, 알림 평가, 텔레그램 발송.

#include "app.h"
#include "cluster/alerts.h"
#include "cluster/channels.h"
#include "cluster/security.h"
#include "cluster/terminal.h"
#include "net/https_client.h"
#include "store/backup.h"
#include "store/invites.h"
#include "store/nodes.h"
#include "store/services.h"
#include "util/encoding.h"
#include "util/i18n.h"
#include "version.h"

#include <drogon/drogon.h>

#include <filesystem>
#include <thread>

namespace douve {

void HubApp::startBackgroundTasks() {
    startedAt_ = now();
    auto* loop = drogon::app().getLoop();
    loop->runEvery(60.0, [this]() {
        try {
            tickMinute(now());
        } catch (const std::exception& e) {
            LOG_ERROR << "메트릭 저장 실패: " << e.what();
        }
    });
    loop->runEvery(60.0, [this]() {
        try {
            tickServices(now());
        } catch (const std::exception& e) {
            LOG_ERROR << "서비스 확인 실패: " << e.what();
        }
    });
    loop->runEvery(30.0, [this]() {
        try {
            tickAlerts(now());
        } catch (const std::exception& e) {
            LOG_ERROR << "알림 평가 실패: " << e.what();
        }
    });
    // 자동 백업: 하루 하나(<상태 디렉터리>/backups/auto-YYYYMMDD.db), 7개 보관.
    // VACUUM은 DB 크기만큼 걸리니 이벤트 루프 밖에서.
    auto backup = [this]() {
        if (backupRunning_.exchange(true))
            return;
        std::thread([this]() {
            try {
                const auto dir =
                    (std::filesystem::path(cfg_.databasePath).parent_path() / "backups").string();
                std::string err;
                auto made = dailyBackup(*db_, cfg_.sourcePath, dir, kVersion, now(), 7, err);
                if (made)
                    LOG_INFO << "자동 백업: " << *made;
                else if (!err.empty())
                    LOG_ERROR << err;
            } catch (const std::exception& e) {
                LOG_ERROR << "자동 백업 실패: " << e.what();
            }
            backupRunning_ = false;
        }).detach();
    };
    if (cfg_.databasePath != ":memory:") {
        loop->runAfter(120.0, backup);
        loop->runEvery(3600.0, backup);
    }
}

void HubApp::tickMinute(std::int64_t t) {
    // CLI 등 웹 밖에서 서비스가 바뀌었으면 입구에 다시 보낸다
    {
        Json::StreamWriterBuilder w;
        w["indentation"] = "";
        const std::string routes = Json::writeString(w, buildRoutes());
        if (routes != lastRoutes_) {
            // 첫 확인 때도 보낸다: 시작 직후 기준값을 잡기 전에 바뀐 경우를 놓치지 않도록 (중복
            // 전송은 무해)
            pushRoutes();
            lastRoutes_ = routes;
        }
    }
    const std::int64_t minute = t / 60 * 60;
    auto rows = live_.drainMinute(minute);
    if (!rows.empty()) {
        Transaction tx(*db_);
        for (const auto& [nodeId, row] : rows)
            insertMetric(*db_, nodeId, row);
        tx.commit();
    }
    if (minute % 3600 == 0) {
        purgeMetrics(*db_, t - std::int64_t{cfg_.metricsRetentionDays} * 86400);
        terminal_->purgeRecordings(t - 30 * 86400);
        purgeSecurityEvents(*db_, t - 30 * 86400);
    }
}

// 서비스 업스트림을 메시 내부에서 확인한다. 응답이 있으면(5xx 제외) 정상 — 401·302도 살아 있는 것.
void HubApp::tickServices(std::int64_t t) {
    if (!settings_.features().serviceChecks) {
        std::lock_guard lk(healthMu_);
        health_.clear();
        return;
    }
    for (const auto& s : listServices(*db_)) {
        // 노드에 속한 서비스는 그 노드의 Agent가 로컬에서 확인해 보고한다 (ingestServiceHealth)
        if (s.kind != "proxy" || s.upstream.empty() || s.nodeId)
            continue;
        const std::int64_t id = s.id;
        const std::string url = std::string(s.upstreamTls ? "https://" : "http://") + s.upstream +
                                (s.stripPrefix ? "/" : s.pathPrefix);
        httpFetchAsync(
            url, std::nullopt,
            [this, id, t](HttpResult r) {
                std::lock_guard lk(healthMu_);
                auto& h = health_[id];
                const bool ok = r.ok && r.status < 500;
                h.fails = ok ? 0 : h.fails + 1;
                h.status = r.status;
                h.error = ok ? "" : (r.ok ? "HTTP " + std::to_string(r.status) : r.error);
                h.checkedAt = t;
                h.latencyMs = r.elapsedMs;
            },
            5, s.upstreamTls == 2);
    }
}

void HubApp::ingestServiceHealth(std::int64_t nodeId, const Json::Value& msg) {
    const auto t = now();
    std::map<std::string, const Json::Value*> byUpstream;
    for (const auto& r : msg["results"])
        byUpstream[r.get("upstream", "").asString()] = &r;
    std::lock_guard lk(healthMu_);
    for (const auto& s : listServices(*db_)) {
        if (!s.nodeId || *s.nodeId != nodeId)
            continue;
        auto it = byUpstream.find(s.upstream);
        if (it == byUpstream.end())
            continue;
        const auto& r = *it->second;
        auto& h = health_[s.id];
        const bool ok = r.get("ok", false).asBool();
        h.fails = ok ? 0 : h.fails + 1;
        h.status = r.get("status", 0).asInt();
        h.error = ok ? "" : r.get("error", "").asString().substr(0, 200);
        h.checkedAt = t;
        h.latencyMs = r.get("ms", 0.0).asDouble();
    }
}

void HubApp::tickAlerts(std::int64_t t) {
    // 시작 직후에는 Agent들이 다시 붙을 시간을 준다
    if (t - startedAt_ < 120)
        return;
    std::map<std::int64_t, Conditions> desired;
    std::map<std::int64_t, std::string> names;
    for (const auto& n : listNodes(*db_)) {
        NodeView v;
        v.id = n.id;
        v.name = n.name;
        v.connected = live_.connected(n.id);
        v.lastSeenAt = n.lastSeenAt;
        if (auto c = live_.changedAt(n.id); c && !v.connected)
            v.lastSeenAt = std::max(v.lastSeenAt.value_or(0), *c);
        if (settings_.features().monitoring)
            v.latest = live_.latest(n.id); // 끄면 디스크·메모리 알림도 없음
        v.inventory = live_.inventory(n.id);
        names[n.id] = n.name;
        // 한 번도 접속한 적 없는 노드는 평가하지 않음
        if (!v.connected && !v.lastSeenAt)
            continue;
        desired[n.id] = evaluateNode(v, t);
    }
    // 서비스 상태: 2회 연속 실패하면 서비스가 도는 노드의 알림으로 연다
    for (const auto& s : listServices(*db_)) {
        if (!s.nodeId || !desired.count(*s.nodeId) || desired[*s.nodeId].stale)
            continue;
        std::lock_guard lk(healthMu_);
        auto h = health_.find(s.id);
        if (h != health_.end() && h->second.fails >= 2)
            desired[*s.nodeId].rules["service:" + s.name] =
                "서비스 응답 없음: " + s.name + " (" + s.host + ", " + h->second.error + ")";
    }
    auto actions = reconcile(openAlerts(*db_), desired);
    for (const auto& o : actions.open) {
        openAlert(*db_, o.nodeId, o.rule, o.message, t);
        notify(alertOpenText(names[o.nodeId], o.message));
    }
    for (const auto& r : actions.resolve) {
        resolveAlert(*db_, r.id, t);
        notify(alertResolvedText(names[*r.nodeId], r, t));
    }
}

std::string HubApp::language() {
    auto v = getSetting(*db_, "language");
    return v ? *v : cfg_.language;
}

void HubApp::notify(const std::string& text) {
    LOG_INFO << "알림: " << text;
    const std::string msg = i18n::translate(text, language());
    const auto creds = settings_.get();
    if (creds.telegramEnabled()) {
        const std::string url =
            cfg_.telegramApiUrl + "/bot" + creds.telegramBotToken + "/sendMessage";
        const std::string form = "chat_id=" + urlEncode(creds.telegramChatId) +
                                 "&text=" + urlEncode("[Douve] " + msg) +
                                 "&disable_web_page_preview=true";
        httpFetchAsync(url, form, [](HttpResult r) {
            if (!r.ok || r.status != 200)
                LOG_WARN << "텔레그램 발송 실패: "
                         << (r.ok ? "HTTP " + std::to_string(r.status) : r.error);
        });
    }
    // 그 밖의 알림 채널 (ntfy, Discord, Slack, 웹훅)
    for (const auto& c : listChannels(*db_)) {
        if (!c.enabled)
            continue;
        httpPostAsync(channelRequest(c, msg, now()), [name = c.name](HttpResult r) {
            if (!r.ok || r.status < 200 || r.status >= 300)
                LOG_WARN << "알림 채널 발송 실패 (" << name
                         << "): " << (r.ok ? "HTTP " + std::to_string(r.status) : r.error);
        });
    }
}

} // namespace douve
