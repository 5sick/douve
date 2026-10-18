#pragma once
// 역할과 서버·앱별 권한.
//   admin    — 전부 (설정, 사용자, 모든 서버·앱)
//   operator — 허락된 서버만: 보기, 터미널, 그 서버의 서비스 관리·앱 접속. 설정·사용자 관리는 불가
//   app      — 서버 관리 화면 없이 허락된 앱(로그인 보호 서비스)만 접속
// 서버 쪽에서 판단한다. 화면에서 숨기는 것은 편의일 뿐이다.

#include "store/db.h"

#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace douve {

enum class Role { Admin, Operator, App };

std::string roleName(Role r);
std::optional<Role> parseRole(std::string_view s);

struct Access {
    Role role = Role::App;
    std::set<std::int64_t> nodes;    // operator: 허락된 서버
    std::set<std::int64_t> services; // 따로 허락된 앱 (모든 역할)

    bool admin() const { return role == Role::Admin; }
    bool atLeastOperator() const { return role != Role::App; }
    bool node(std::int64_t nodeId) const;
    // 서비스(앱): 따로 허락됐거나, operator이고 그 서비스가 허락된 서버에서 돈다
    bool service(std::int64_t serviceId, std::optional<std::int64_t> nodeId) const;
};

Access loadAccess(Database& db, std::int64_t userId);
// 역할과 권한을 통째로 바꾼다 (admin이면 목록은 비운다).
void setAccess(Database& db, std::int64_t userId, Role role, const std::set<std::int64_t>& nodes,
               const std::set<std::int64_t>& services);
int countAdmins(Database& db);

struct UserSummary {
    std::int64_t id = 0;
    std::string email;
    Access access;
    std::int64_t createdAt = 0;
    std::optional<std::int64_t> lastLoginAt;
    int passkeys = 0;
};
std::vector<UserSummary> listUsers(Database& db);
// 사용자를 지운다 (패스키·세션·권한도 함께). 감사 기록은 남는다.
bool deleteUser(Database& db, std::int64_t userId);

// /api/* 경로에 필요한 최소 역할. 목록에 없는 경로는 관리자 전용 (새 API를 만들고 잊어도 닫혀
// 있게). nullopt: 로그인 없이 쓰는 경로 (Agent 등록 등, 핸들러가 직접 확인).
enum class Need { Login, Operator, Admin };
std::optional<Need> apiNeed(std::string_view path);
bool satisfies(const Access& a, Need n);

} // namespace douve
