#include "cluster/security.h"

#include <algorithm>

namespace douve {
namespace {

constexpr std::int64_t kRenotifySeconds = 6 * 3600;
constexpr std::int64_t kAckQuietSeconds = 24 * 3600;

std::string compact(const Json::Value& v) {
    Json::StreamWriterBuilder w;
    w["indentation"] = "";
    w["emitUTF8"] = true;
    return Json::writeString(w, v);
}

bool contains(const std::vector<std::string>& v, const std::string& x) {
    return std::find(v.begin(), v.end(), x) != v.end();
}

bool startsWith(const std::string& s, const std::string& p) {
    return s.rfind(p, 0) == 0;
}

} // namespace

std::vector<SecurityEvent> parseSecurityEvents(const Json::Value& msg) {
    std::vector<SecurityEvent> out;
    for (const auto& e : msg["events"]) {
        if (!e.isObject() || out.size() >= 500)
            continue;
        SecurityEvent ev;
        ev.kind = e.get("kind", "").asString().substr(0, 32);
        ev.summary = e.get("summary", "").asString().substr(0, 400);
        ev.viaSid = e.get("via_sid", "").asString().substr(0, 64);
        ev.ts = e.get("ts", 0).asInt64();
        ev.fields = e["fields"].isObject() ? e["fields"] : Json::Value(Json::objectValue);
        if (!ev.kind.empty())
            out.push_back(std::move(ev));
    }
    return out;
}

Classified classifySecurity(std::int64_t nodeId, const SecurityEvent& e,
                            const std::vector<std::string>& adminUsers) {
    const std::string n = std::to_string(nodeId) + "|";
    auto f = [&](const char* k) { return e.fields.get(k, "").asString(); };
    if (e.kind == "ssh_login")
        return {"warn", "ssh_login|" + n + f("user") + "|" + f("ip")};
    if (e.kind == "ssh_fail")
        return {"warn", "ssh_fail|" + n + f("ip")};
    if (e.kind == "sudo") {
        // 실행 파일 경로까지만 지문에 (인자가 달라도 같은 이슈)
        std::string cmd = f("command");
        cmd = cmd.substr(0, cmd.find(' '));
        const bool admin = contains(adminUsers, f("user"));
        return {admin ? "info" : "warn", "sudo|" + n + f("user") + "|" + cmd};
    }
    if (e.kind == "su")
        return {"warn", "su|" + n + f("user") + "|" + f("as")};
    if (e.kind == "account")
        return {"crit", "account|" + n + f("message")};
    if (e.kind == "file_changed") {
        const std::string path = f("path");
        const bool critical = path.find("sudoers") != std::string::npos ||
                              path.find("authorized_keys") != std::string::npos ||
                              path == "/etc/passwd" || path == "/etc/shadow" ||
                              startsWith(path, "/etc/ssh/");
        // 같은 파일이라도 내용이 바뀔 때마다 새 이슈 (확인한 상태 이후의 변경도 알려야 하므로)
        return {critical ? "crit" : "warn", "file|" + n + path + "|" + f("sha256")};
    }
    if (e.kind == "port_opened")
        return {"warn", "port|" + n + f("listen")};
    return {"info", e.kind + "|" + n + e.summary};
}

std::vector<std::string> ingestSecurity(Database& db, const SecurityContext& ctx,
                                        const std::vector<SecurityEvent>& events,
                                        std::int64_t now) {
    std::vector<std::string> notes;
    Transaction tx(db);
    for (const auto& e : events) {
        auto c = classifySecurity(ctx.nodeId, e, ctx.adminUsers);
        const std::int64_t ts = e.ts > 0 && e.ts <= now + 300 ? e.ts : now;
        // 출처: Douve 터미널 세션이면 그 사용자. 파일·계정 변경은 그 시각에 터미널을 쓰던 사용자.
        std::string via;
        if (!e.viaSid.empty() && ctx.terminalUser)
            via = ctx.terminalUser(e.viaSid);
        if (via.empty() && (e.kind == "file_changed" || e.kind == "account") &&
            ctx.terminalActiveAt)
            via = ctx.terminalActiveAt(ts);

        std::string status;
        if (!via.empty())
            status = "auto"; // 내가 Douve 터미널에서 한 일
        else if (c.severity == "info")
            status = "info";

        if (status.empty()) {
            Statement q(db, "SELECT status, notified_at, acked_at FROM security_issues "
                            "WHERE fingerprint = ?");
            q.bind(1, c.fingerprint);
            if (!q.step()) {
                Statement ins(db,
                              "INSERT INTO security_issues (fingerprint, node_id, kind, severity, "
                              "summary, first_seen, last_seen, count, status, notified_at) "
                              "VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'open', ?)");
                ins.bind(1, c.fingerprint).bind(2, ctx.nodeId).bind(3, e.kind).bind(4, c.severity);
                ins.bind(5, e.summary).bind(6, ts).bind(7, ts).bind(8, now).run();
                notes.push_back((c.severity == "crit" ? "🚨 [" : "🛡️ [") + ctx.nodeName + "] " +
                                e.summary);
                status = "open";
            } else {
                const std::string cur = q.text(0);
                const std::int64_t notified = q.isNull(1) ? 0 : q.int64(1);
                const std::int64_t ackedAt = q.isNull(2) ? 0 : q.int64(2);
                // "문제 없음"은 영구히, "확인함"은 24시간 동안 조용히 (반복되는 정상 작업이 계속
                // 알리지 않게)
                const bool quiet =
                    cur == "ignored" || (cur == "acked" && now - ackedAt < kAckQuietSeconds);
                if (quiet) {
                    status = cur;
                    Statement up(db, "UPDATE security_issues SET count = count + 1, last_seen = ? "
                                     "WHERE fingerprint = ?");
                    up.bind(1, ts).bind(2, c.fingerprint).run();
                } else {
                    status = "open";
                    // 확인 후 24시간이 지나 다시 생기면 즉시, 열려 있는 이슈는 6시간에 한 번만 다시
                    // 알림
                    const bool renotify = cur == "acked" || now - notified >= kRenotifySeconds;
                    Statement up(
                        db, "UPDATE security_issues SET count = count + 1, last_seen = ?, "
                            "status = 'open', summary = ?, notified_at = ? WHERE fingerprint = ?");
                    up.bind(1, ts).bind(2, e.summary).bind(3, renotify ? now : notified);
                    up.bind(4, c.fingerprint).run();
                    if (renotify)
                        notes.push_back(
                            "🛡️ [" + ctx.nodeName + "] " + e.summary +
                            (cur == "acked" ? " (확인 후 다시 발생)" : " (계속 발생 중)"));
                }
            }
        }
        Statement ev(db, "INSERT INTO security_events (node_id, ts, kind, severity, fingerprint, "
                         "summary, fields, via, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
        ev.bind(1, ctx.nodeId)
            .bind(2, ts)
            .bind(3, e.kind)
            .bind(4, c.severity)
            .bind(5, c.fingerprint);
        ev.bind(6, e.summary).bind(7, compact(e.fields)).bind(8, via).bind(9, status).run();
    }
    tx.commit();
    return notes;
}

int resolveSecurityIssues(Database& db, const std::vector<std::string>& fingerprints,
                          const std::string& mode, std::int64_t userId, std::int64_t now) {
    if (mode != "ack" && mode != "ignore")
        return 0;
    int n = 0;
    Transaction tx(db);
    for (const auto& fp : fingerprints) {
        Statement s(db, "UPDATE security_issues SET status = ?, acked_by = ?, acked_at = ? "
                        "WHERE fingerprint = ?");
        s.bind(1, std::string(mode == "ack" ? "acked" : "ignored")).bind(2, userId).bind(3, now);
        s.bind(4, fp).run();
        n += db.changes();
    }
    tx.commit();
    return n;
}

bool reopenSecurityIssue(Database& db, const std::string& fingerprint) {
    Statement s(db, "UPDATE security_issues SET status = 'acked', acked_at = NULL WHERE "
                    "fingerprint = ? AND status = 'ignored'");
    s.bind(1, fingerprint).run();
    return db.changes() > 0;
}

void purgeSecurityEvents(Database& db, std::int64_t before) {
    Statement s(db, "DELETE FROM security_events WHERE ts < ?");
    s.bind(1, before).run();
}

} // namespace douve
