#include "store/access.h"
#include "store/db.h"
#include "store/invites.h"
#include "testing.h"

using namespace douve;

TEST(access_api_paths_default_deny) {
    // 표에 없는 경로는 관리자 전용 — 새 API를 만들고 권한을 잊어도 닫혀 있다
    CHECK(apiNeed("/api/something-new") == Need::Admin);
    CHECK(apiNeed("/api/settings") == Need::Admin);
    CHECK(apiNeed("/api/users/update") == Need::Admin);
    CHECK(apiNeed("/api/nodes/delete") == Need::Admin);
    CHECK(apiNeed("/api/nodes/join-token") == Need::Admin);
    CHECK(apiNeed("/api/nodes/12/whatever") == Need::Admin);
    CHECK(apiNeed("/api/nodes/1x") == Need::Admin);
    CHECK(apiNeed("/api/terminal/recordings") == Need::Admin);
    CHECK(apiNeed("/api/nodes") == Need::Operator);
    CHECK(apiNeed("/api/nodes/12") == Need::Operator);
    CHECK(apiNeed("/api/nodes/12/metrics") == Need::Operator);
    CHECK(apiNeed("/api/terminal/ticket") == Need::Operator);
    CHECK(apiNeed("/api/terminal/options") == Need::Operator);
    CHECK(apiNeed("/api/terminal/trust") == Need::Admin);
    CHECK(apiNeed("/api/terminal/trust/sign") == Need::Admin);
    CHECK(apiNeed("/api/me") == Need::Login);
    CHECK(apiNeed("/api/devices/create") == Need::Login);
    CHECK(apiNeed("/api/devnet/update") == Need::Admin);
    CHECK(apiNeed("/api/icons/service/3") == Need::Login);
    CHECK(!apiNeed("/api/agent/enroll"));
    // 접두사만 같은 경로는 다른 경로
    CHECK(apiNeed("/api/mex") == Need::Admin);
    CHECK(apiNeed("/api/services/createx") == Need::Admin);
}

TEST(access_roles) {
    Access admin{Role::Admin, {}, {}};
    Access op{Role::Operator, {1}, {9}};
    Access app{Role::App, {1}, {7}}; // app의 서버 권한은 의미 없음
    CHECK(admin.node(5) && admin.service(5, std::nullopt));
    CHECK(op.node(1) && !op.node(2));
    CHECK(op.service(3, 1));             // 허락된 서버의 앱
    CHECK(!op.service(3, 2));            // 다른 서버의 앱
    CHECK(!op.service(3, std::nullopt)); // 서버 없는 외부 앱
    CHECK(op.service(9, 2));             // 따로 허락된 앱
    CHECK(!app.node(1));
    CHECK(app.service(7, 2) && !app.service(3, 1));
    CHECK(satisfies(op, Need::Operator) && !satisfies(op, Need::Admin));
    CHECK(satisfies(app, Need::Login) && !satisfies(app, Need::Operator));
    CHECK(parseRole("admin") == Role::Admin && !parseRole("root") && !parseRole(""));
}

TEST(access_store) {
    Database db(":memory:");
    db.exec("INSERT INTO users (id, email, created_at, allowed) VALUES (1, 'a@x', 0, 1)");
    db.exec("INSERT INTO users (id, email, created_at) VALUES (2, 'b@x', 0)");
    CHECK(loadAccess(db, 2).role == Role::App); // 새 행의 기본은 가장 좁은 권한
    CHECK(loadAccess(db, 99).role == Role::App && loadAccess(db, 99).services.empty());
    setAccess(db, 2, Role::Operator, {3, 4}, {8});
    auto a = loadAccess(db, 2);
    CHECK(a.role == Role::Operator && a.nodes == std::set<std::int64_t>({3, 4}) &&
          a.services == std::set<std::int64_t>({8}));
    setAccess(db, 2, Role::App, {3}, {8}); // app은 서버 권한을 저장하지 않는다
    a = loadAccess(db, 2);
    CHECK(a.nodes.empty() && a.services.size() == 1);
    // 들어올 수 있는 관리자만 센다 (초대를 열기만 한 행은 아님)
    CHECK_EQ(countAdmins(db), 0);
    setAccess(db, 1, Role::Admin, {}, {});
    CHECK_EQ(countAdmins(db), 1);
    setAccess(db, 2, Role::Admin, {}, {});
    CHECK_EQ(countAdmins(db), 1); // 2는 패스키도 초대 허용도 없음
    db.exec("UPDATE users SET role = 'superuser' WHERE id = 2");
    CHECK(loadAccess(db, 2).role == Role::App); // 모르는 값은 가장 좁게
    CHECK(deleteUser(db, 2) && listUsers(db).size() == 1);
}

TEST(access_invite_carries_role) {
    Database db(":memory:");
    auto cli = createInvite(db, "a@x", std::nullopt, 60, 0);
    CHECK(inviteAccess(db, cli.token)->role == Role::Admin); // CLI 첫 초대 = 관리자
    auto inv =
        createInvite(db, "b@x", std::nullopt, 60, 0, InviteAccess{Role::Operator, {2}, {5, 6}});
    auto a = inviteAccess(db, inv.token);
    CHECK(a && a->role == Role::Operator && a->nodes == std::set<std::int64_t>({2}) &&
          a->services.size() == 2);
    CHECK(!inviteAccess(db, "nope"));
}
