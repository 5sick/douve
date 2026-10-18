#include "store/access.h"

#include <algorithm>
#include <cctype>

namespace douve {

std::string roleName(Role r) {
    switch (r) {
    case Role::Admin:
        return "admin";
    case Role::Operator:
        return "operator";
    case Role::App:
        return "app";
    }
    return "app";
}

std::optional<Role> parseRole(std::string_view s) {
    if (s == "admin")
        return Role::Admin;
    if (s == "operator")
        return Role::Operator;
    if (s == "app")
        return Role::App;
    return std::nullopt;
}

bool Access::node(std::int64_t nodeId) const {
    return admin() || (role == Role::Operator && nodes.count(nodeId) > 0);
}

bool Access::service(std::int64_t serviceId, std::optional<std::int64_t> nodeId) const {
    if (admin() || services.count(serviceId))
        return true;
    return role == Role::Operator && nodeId && nodes.count(*nodeId) > 0;
}

Access loadAccess(Database& db, std::int64_t userId) {
    Access a;
    {
        Statement s(db, "SELECT role FROM users WHERE id = ?");
        s.bind(1, userId);
        if (!s.step())
            return a; // 없는 사용자: 아무 권한 없음 (app + 빈 목록)
        // 모르는 값은 가장 좁은 권한으로
        a.role = parseRole(s.text(0)).value_or(Role::App);
    }
    Statement g(db, "SELECT kind, target_id FROM user_grants WHERE user_id = ?");
    g.bind(1, userId);
    while (g.step()) {
        const std::string kind = g.text(0);
        if (kind == "node")
            a.nodes.insert(g.int64(1));
        else if (kind == "service")
            a.services.insert(g.int64(1));
    }
    return a;
}

void setAccess(Database& db, std::int64_t userId, Role role, const std::set<std::int64_t>& nodes,
               const std::set<std::int64_t>& services) {
    Transaction tx(db);
    Statement(db, "UPDATE users SET role = ? WHERE id = ?")
        .bind(1, roleName(role))
        .bind(2, userId)
        .run();
    Statement(db, "DELETE FROM user_grants WHERE user_id = ?").bind(1, userId).run();
    auto add = [&](const char* kind, std::int64_t id) {
        Statement(db,
                  "INSERT OR IGNORE INTO user_grants (user_id, kind, target_id) VALUES (?, ?, ?)")
            .bind(1, userId)
            .bind(2, std::string(kind))
            .bind(3, id)
            .run();
    };
    if (role != Role::Admin) {
        if (role == Role::Operator)
            for (auto id : nodes)
                add("node", id);
        for (auto id : services)
            add("service", id);
    }
    tx.commit();
}

int countAdmins(Database& db) {
    // 실제로 들어올 수 있는 관리자만 (패스키가 있거나 초대로 허용됨). 설정 파일 목록만으로 Google
    // 로그인하는 관리자는 세지 않는다 — 보호가 더 보수적이 되는 쪽.
    Statement s(db, "SELECT count(*) FROM users u WHERE u.role = 'admin' AND (u.allowed = 1 OR "
                    "EXISTS (SELECT 1 FROM passkeys p WHERE p.user_id = u.id))");
    return s.step() ? static_cast<int>(s.int64(0)) : 0;
}

std::vector<UserSummary> listUsers(Database& db) {
    std::vector<UserSummary> out;
    {
        Statement s(db, "SELECT u.id, u.email, u.created_at, u.last_login_at, "
                        "(SELECT count(*) FROM passkeys p WHERE p.user_id = u.id) "
                        "FROM users u ORDER BY u.id");
        while (s.step()) {
            UserSummary u;
            u.id = s.int64(0);
            u.email = s.text(1);
            u.createdAt = s.int64(2);
            if (!s.isNull(3))
                u.lastLoginAt = s.int64(3);
            u.passkeys = static_cast<int>(s.int64(4));
            out.push_back(std::move(u));
        }
    }
    for (auto& u : out)
        u.access = loadAccess(db, u.id);
    return out;
}

bool deleteUser(Database& db, std::int64_t userId) {
    auto guard = db.lock();
    Statement(db, "DELETE FROM users WHERE id = ?").bind(1, userId).run();
    return db.changes() > 0;
}

namespace {

bool digits(std::string_view s) {
    return !s.empty() && s.size() <= 18 &&
           std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isdigit(c); });
}

} // namespace

std::optional<Need> apiNeed(std::string_view path) {
    // 로그인 없이 (핸들러가 직접 확인)
    if (path == "/api/privacy" || path == "/api/agent/enroll")
        return std::nullopt;
    // 누구나 (로그인만): 내 계정, 홈 화면 (핸들러가 권한대로 걸러 보여 준다)
    for (std::string_view p :
         {"/api/me", "/api/home", "/api/summary", "/api/passkeys", "/api/passkeys/rename",
          "/api/passkeys/delete", "/api/sessions", "/api/sessions/revoke", "/api/account/recovery",
          "/api/account/recovery/generate", "/api/devices", "/api/devices/create",
          "/api/devices/delete"})
        if (path == p)
            return Need::Login;
    if (path.rfind("/api/icons/", 0) == 0)
        return Need::Login;
    // 운영자 이상 (핸들러가 서버별로 확인)
    for (std::string_view p :
         {"/api/nodes", "/api/terminal/options", "/api/terminal/ticket", "/api/services",
          "/api/services/create", "/api/services/update", "/api/services/delete",
          "/api/services/suggest", "/api/apps", "/api/checkup", "/api/checkup/run",
          "/api/checkup/fix/options", "/api/checkup/fix", "/api/checkup/fix/status",
          "/api/files/options", "/api/files/ticket", "/api/reach", "/api/reach/run"})
        if (path == p)
            return Need::Operator;
    if (path.rfind("/api/nodes/", 0) == 0) { // /api/nodes/{id}, /api/nodes/{id}/metrics
        std::string_view rest = path.substr(11);
        const auto slash = rest.find('/');
        const auto id = rest.substr(0, slash);
        if (digits(id) && (slash == std::string_view::npos || rest.substr(slash) == "/metrics"))
            return Need::Operator;
    }
    return Need::Admin;
}

bool satisfies(const Access& a, Need n) {
    switch (n) {
    case Need::Login:
        return true;
    case Need::Operator:
        return a.atLeastOperator();
    case Need::Admin:
        return a.admin();
    }
    return false;
}

} // namespace douve
