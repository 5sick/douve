#pragma once
// 서비스 = 공개 도메인 → 업스트림(메시 주소:포트) + 접근 정책. 입구(edge) Agent의 라우팅 표가 된다.

#include "store/db.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace douve {

struct Service {
    std::int64_t id = 0;
    std::string name;
    std::string host;
    std::optional<std::int64_t> nodeId;
    std::string upstream;
    std::string auth = "douve"; // douve | public
    // 라우팅
    std::string pathPrefix = "/"; // 이 경로 아래만 (도메인 하나에 여러 서비스)
    bool stripPrefix = false;     // 업스트림에 넘길 때 접두사 제거
    std::string kind = "proxy";   // proxy | redirect
    std::string redirectTo;       // kind=redirect: 보낼 주소 (경로는 붙여 줌)
    int upstreamTls = 0;          // 0 http, 1 https, 2 https(인증서 검증 안 함: 자체 서명 장비)
    std::string hostHeader;       // 비우면 원래 도메인 유지
    int timeout = 0;              // 첫 응답까지 초 (0 = 제한 없음)
    std::string origin = "web";   // 만든 곳: web | node (douve-agent expose)
    std::vector<std::string> publicPaths;
    std::int64_t createdAt = 0, updatedAt = 0;
    // 홈 화면
    std::string group, description, icon;
    bool onHome = true;
    int position = 0;
};

// 홈 화면의 외부 링크 (프록시하지 않는 북마크)
struct Link {
    std::int64_t id = 0;
    std::string name, url, group, description, icon;
    int position = 0;
};
// 이름·URL·아이콘 검사. 문제가 있으면 이유.
std::string validateLink(Link& l);
std::vector<Link> listLinks(Database& db);
std::optional<Link> findLink(Database& db, std::int64_t id);
std::int64_t createLink(Database& db, const Link& l, std::int64_t now);
bool updateLink(Database& db, const Link& l);
bool deleteLink(Database& db, std::int64_t id);
// 아이콘 이름 (dashboard-icons): 영문 소문자·숫자·하이픈 1~64자, 빈 값 허용
bool validIconName(const std::string& s);

// 입력 검증. 성공하면 정규화된 값으로 고쳐 놓고 빈 문자열, 실패하면 이유를 돌려준다.
//   host: 소문자 도메인 (라벨 a-z0-9-, 2개 이상), hubHost와 같으면 안 됨
//   upstream: IPv4 또는 호스트명 + ":" + 포트(1~65535), scheme·경로 없음
//   publicPaths: "/"로 시작, 공백·".." 없음, 최대 20개. "/"만은 금지(auth=public을 쓰라고 안내)
//   pathPrefix: "/" 또는 "/a/b" (끝의 /는 제거), redirect는 http(s) 주소, timeout 0~3600
std::string validateService(Service& s, const std::string& hubHost);
// 업스트림이 127.0.0.0/8·localhost (그 노드 안에서만 닿음 → 입구가 터널로 간다)
bool isLoopbackUpstream(const std::string& upstream);

std::vector<Service> listServices(Database& db);
std::optional<Service> findService(Database& db, std::int64_t id);
// 이름·도메인 중복이면 nullopt + error
std::optional<Service> createService(Database& db, Service s, std::int64_t now, std::string& error);
bool updateService(Database& db, const Service& s, std::int64_t now, std::string& error);
bool deleteService(Database& db, std::int64_t id);

} // namespace douve
