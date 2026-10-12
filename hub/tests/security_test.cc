#include "cluster/security.h"
#include "testing.h"

using namespace douve;

namespace {
SecurityEvent ev(const std::string& kind, Json::Value fields, const std::string& summary,
                 std::int64_t ts = 100, const std::string& via = "") {
    SecurityEvent e;
    e.kind = kind;
    e.fields = std::move(fields);
    e.summary = summary;
    e.ts = ts;
    e.viaSid = via;
    return e;
}
Json::Value F(std::initializer_list<std::pair<const char*, const char*>> kv) {
    Json::Value v(Json::objectValue);
    for (auto& [k, x] : kv)
        v[k] = x;
    return v;
}
Database& freshDb() {
    static std::unique_ptr<Database> db;
    db = std::make_unique<Database>(":memory:");
    db->exec("INSERT INTO nodes (id, name, pubkey, created_at) VALUES (1, 'n1', x'00', 0)");
    db->exec("INSERT INTO users (id, email, created_at) VALUES (1, 'me@x.com', 0)");
    return *db;
}
std::string issueStatus(Database& db, const std::string& like) {
    Statement s(db, "SELECT status FROM security_issues WHERE fingerprint LIKE ?");
    s.bind(1, like);
    return s.step() ? s.text(0) : "";
}
} // namespace

TEST(security_classification) {
    std::vector<std::string> admins = {"ubuntu"};
    auto c = classifySecurity(
        1, ev("sudo", F({{"user", "ubuntu"}, {"command", "/bin/ls -la"}}), ""), admins);
    CHECK_EQ(c.severity, "info");
    c = classifySecurity(
        1,
        ev("sudo", F({{"user", "monitor"}, {"command", "/usr/local/bin/health-check certs"}}), ""),
        admins);
    CHECK_EQ(c.severity, "warn");
    // 인자가 달라도 같은 지문
    auto c2 = classifySecurity(
        1,
        ev("sudo", F({{"user", "monitor"}, {"command", "/usr/local/bin/health-check disk"}}), ""),
        admins);
    CHECK_EQ(c.fingerprint, c2.fingerprint);
    CHECK_EQ(
        classifySecurity(
            1,
            ev("file_changed", F({{"path", "/home/u/.ssh/authorized_keys"}, {"sha256", "ab"}}), ""),
            admins)
            .severity,
        "crit");
    CHECK_EQ(
        classifySecurity(
            1, ev("file_changed", F({{"path", "/etc/cron.d/x"}, {"sha256", "ab"}}), ""), admins)
            .severity,
        "warn");
    CHECK(classifySecurity(1, ev("ssh_login", F({{"user", "a"}, {"ip", "1.1.1.1"}}), ""), admins)
              .fingerprint !=
          classifySecurity(2, ev("ssh_login", F({{"user", "a"}, {"ip", "1.1.1.1"}}), ""), admins)
              .fingerprint);
}

TEST(security_issue_lifecycle_and_throttle) {
    auto& db = freshDb();
    SecurityContext ctx;
    ctx.nodeId = 1;
    ctx.nodeName = "n1";
    auto login =
        ev("ssh_login", F({{"user", "monitor"}, {"ip", "10.200.0.2"}}), "SSH 로그인: monitor");
    // 첫 발생 → 알림
    CHECK_EQ(ingestSecurity(db, ctx, {login}, 1000).size(), std::size_t{1});
    // 같은 이슈 반복 → 6시간 안에는 조용
    CHECK(ingestSecurity(db, ctx, {login, login}, 2000).empty());
    // 6시간 지나도 열려 있으면 한 번 다시
    CHECK_EQ(ingestSecurity(db, ctx, {login}, 1000 + 6 * 3600).size(), std::size_t{1});
    // "문제 없음" → 앞으로 조용
    CHECK_EQ(resolveSecurityIssues(db, {"ssh_login|1|monitor|10.200.0.2"}, "ignore", 1, 30000), 1);
    CHECK(ingestSecurity(db, ctx, {login}, 90000).empty());
    CHECK_EQ(issueStatus(db, "ssh_login%"), "ignored");
    // 무시 해제 → 다음 발생 때 알림
    CHECK(reopenSecurityIssue(db, "ssh_login|1|monitor|10.200.0.2"));
    CHECK_EQ(ingestSecurity(db, ctx, {login}, 91000).size(), std::size_t{1});
    // "확인함" → 24시간 동안 조용, 그 뒤 다시 생기면 알림
    resolveSecurityIssues(db, {"ssh_login|1|monitor|10.200.0.2"}, "ack", 1, 92000);
    CHECK_EQ(issueStatus(db, "ssh_login%"), "acked");
    CHECK(ingestSecurity(db, ctx, {login}, 93000).empty());
    CHECK_EQ(issueStatus(db, "ssh_login%"), "acked");
    auto n = ingestSecurity(db, ctx, {login}, 92000 + 24 * 3600 + 1);
    CHECK(n.size() == 1 && n[0].find("다시 발생") != std::string::npos);
    CHECK_EQ(issueStatus(db, "ssh_login%"), "open");
    CHECK_EQ(resolveSecurityIssues(db, {"x"}, "bogus", 1, 1), 0);
}

TEST(security_douve_terminal_actions_are_quiet) {
    auto& db = freshDb();
    SecurityContext ctx;
    ctx.nodeId = 1;
    ctx.nodeName = "n1";
    ctx.terminalUser = [](const std::string& sid) { return sid == "sid1" ? "me@x.com" : ""; };
    ctx.terminalActiveAt = [](std::int64_t ts) { return ts >= 500 && ts <= 700 ? "me@x.com" : ""; };
    // Douve 터미널 세션의 su → 조용, 출처 기록
    CHECK(ingestSecurity(
              db, ctx, {ev("su", F({{"user", "ubuntu"}, {"as", "root"}}), "su", 100, "sid1")}, 1000)
              .empty());
    // 터미널 사용 중 바뀐 authorized_keys → 조용
    CHECK(ingestSecurity(
              db, ctx,
              {ev("file_changed", F({{"path", "/root/.ssh/authorized_keys"}, {"sha256", "aa"}}),
                  "f", 600)},
              1000)
              .empty());
    // 터미널을 쓰지 않을 때 바뀌면 → 알림
    CHECK_EQ(ingestSecurity(
                 db, ctx,
                 {ev("file_changed", F({{"path", "/root/.ssh/authorized_keys"}, {"sha256", "bb"}}),
                     "f", 900)},
                 1000)
                 .size(),
             std::size_t{1});
    Statement s(db,
                "SELECT count(*) FROM security_events WHERE status = 'auto' AND via = 'me@x.com'");
    CHECK(s.step() && s.int64(0) == 2);
}

TEST(security_event_parsing_limits) {
    Json::Value msg;
    for (int i = 0; i < 600; ++i) {
        Json::Value e;
        e["kind"] = "sudo";
        e["summary"] = std::string(1000, 'x');
        msg["events"].append(e);
    }
    auto evs = parseSecurityEvents(msg);
    CHECK_EQ(evs.size(), std::size_t{500});
    CHECK_EQ(evs[0].summary.size(), std::size_t{400});
}
