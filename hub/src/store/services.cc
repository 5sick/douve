#include "store/services.h"
#include "util/json.h"

#include "store/nodes.h"

#include <json/json.h>

#include <algorithm>
#include <cctype>
#include <sstream>

namespace douve {
namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

bool validLabel(const std::string& l) {
    if (l.empty() || l.size() > 63 || l.front() == '-' || l.back() == '-')
        return false;
    return std::all_of(l.begin(), l.end(), [](unsigned char c) {
        return std::islower(c) || std::isdigit(c) || c == '-';
    });
}

bool validHostname(const std::string& h, std::size_t minLabels) {
    if (h.empty() || h.size() > 253)
        return false;
    std::size_t labels = 0, start = 0;
    while (true) {
        auto dot = h.find('.', start);
        if (!validLabel(
                h.substr(start, dot == std::string::npos ? std::string::npos : dot - start)))
            return false;
        ++labels;
        if (dot == std::string::npos)
            break;
        start = dot + 1;
    }
    return labels >= minLabels;
}

std::string pathsJson(const std::vector<std::string>& paths) {
    Json::Value a(Json::arrayValue);
    for (const auto& p : paths)
        a.append(p);
    Json::StreamWriterBuilder w;
    w["indentation"] = "";
    return Json::writeString(w, a);
}

std::vector<std::string> parsePaths(const std::string& json) {
    Json::Value a;
    std::vector<std::string> out;
    if (parseJson(json, a) && a.isArray())
        for (const auto& p : a)
            if (p.isString())
                out.push_back(p.asString());
    return out;
}

constexpr const char* kCols = "id, name, host, node_id, upstream, auth, public_paths, created_at, "
                              "updated_at, grp, description, "
                              "icon, on_home, position, path_prefix, strip_prefix, kind, "
                              "redirect_to, upstream_tls, host_header, "
                              "timeout, origin, internal, external";

Service readService(Statement& s) {
    Service v;
    v.id = s.int64(0);
    v.name = s.text(1);
    v.host = s.text(2);
    if (!s.isNull(3))
        v.nodeId = s.int64(3);
    v.upstream = s.text(4);
    v.auth = s.text(5);
    v.publicPaths = parsePaths(s.text(6));
    v.createdAt = s.int64(7);
    v.updatedAt = s.int64(8);
    v.group = s.text(9);
    v.description = s.text(10);
    v.icon = s.text(11);
    v.onHome = s.int64(12) != 0;
    v.position = static_cast<int>(s.int64(13));
    v.pathPrefix = s.text(14);
    v.stripPrefix = s.int64(15) != 0;
    v.kind = s.text(16);
    v.redirectTo = s.text(17);
    v.upstreamTls = static_cast<int>(s.int64(18));
    v.hostHeader = s.text(19);
    v.timeout = static_cast<int>(s.int64(20));
    v.origin = s.text(21);
    v.internal = s.int64(22) != 0;
    v.external = s.int64(23) != 0;
    return v;
}

bool nameTaken(Database& db, const std::string& name, std::int64_t exceptId) {
    Statement s(db, "SELECT 1 FROM services WHERE name = ? AND id != ?");
    s.bind(1, name).bind(2, exceptId);
    return s.step();
}

bool routeTaken(Database& db, const Service& v) {
    Statement s(db, "SELECT 1 FROM services WHERE host = ? AND path_prefix = ? AND id != ?");
    s.bind(1, v.host).bind(2, v.pathPrefix).bind(3, v.id);
    return s.step();
}

} // namespace

bool isLoopbackUpstream(const std::string& upstream) {
    const auto host = upstream.substr(0, upstream.rfind(':'));
    return host == "localhost" || host.rfind("127.", 0) == 0 || host == "[::1]";
}

std::string validateService(Service& s, const std::string& hubHost) {
    s.name = sanitizeNodeName(s.name);
    if (s.name.empty())
        return "이름이 필요합니다 (영문 소문자·숫자·하이픈)";
    s.host = lower(s.host);
    while (!s.host.empty() && s.host.back() == '.')
        s.host.pop_back();
    if (!validHostname(s.host, 2))
        return "도메인 형식이 올바르지 않습니다";
    if (s.host == lower(hubHost))
        return "Douve Hub 도메인은 서비스로 쓸 수 없습니다";

    if (!s.internal && !s.external)
        return "내부 길이나 외부 공개 중 하나는 켜야 합니다";
    if (s.kind != "proxy" && s.kind != "redirect")
        return "서비스 유형은 proxy 또는 redirect 입니다";
    // 경로 접두사
    if (s.pathPrefix.empty())
        s.pathPrefix = "/";
    while (s.pathPrefix.size() > 1 && s.pathPrefix.back() == '/')
        s.pathPrefix.pop_back();
    if (s.pathPrefix.front() != '/' || s.pathPrefix.size() > 100 ||
        s.pathPrefix.find("..") != std::string::npos ||
        std::any_of(s.pathPrefix.begin(), s.pathPrefix.end(), [](unsigned char c) {
            return std::isspace(c) || c < 0x20 || c == '?' || c == '#' || c == '%';
        }))
        return "경로 접두사 형식 오류 (예: /api)";
    if (s.pathPrefix == "/")
        s.stripPrefix = false;
    if (s.kind == "redirect") {
        if ((s.redirectTo.rfind("https://", 0) != 0 && s.redirectTo.rfind("http://", 0) != 0) ||
            s.redirectTo.size() > 500 ||
            s.redirectTo.find_first_of(" \t\r\n\"<>") != std::string::npos)
            return "리다이렉트 주소는 http:// 또는 https:// 로 시작해야 합니다";
        s.upstream.clear();
        s.publicPaths.clear();
        s.auth = "public";
        return {};
    }
    s.redirectTo.clear();
    if (s.upstreamTls < 0 || s.upstreamTls > 2)
        return "업스트림 TLS 설정 오류";
    if (s.timeout < 0 || s.timeout > 3600)
        return "타임아웃은 0~3600초입니다";
    if (!s.hostHeader.empty() &&
        !validHostname(lower(s.hostHeader.substr(0, s.hostHeader.rfind(':'))), 1))
        return "Host 헤더 형식 오류";

    auto colon = s.upstream.rfind(':');
    if (s.upstream.find("://") != std::string::npos || s.upstream.find('/') != std::string::npos ||
        colon == std::string::npos)
        return "업스트림은 주소:포트 형식이어야 합니다 (예: 10.200.0.2:3000)";
    const std::string uhost = lower(s.upstream.substr(0, colon));
    const std::string uport = s.upstream.substr(colon + 1);
    if (uport.empty() || uport.size() > 5 ||
        !std::all_of(uport.begin(), uport.end(), [](unsigned char c) { return std::isdigit(c); }))
        return "업스트림 포트가 올바르지 않습니다";
    const int port = std::stoi(uport);
    if (port < 1 || port > 65535)
        return "업스트림 포트가 올바르지 않습니다";
    if (!validHostname(uhost, 1))
        return "업스트림 주소가 올바르지 않습니다";
    s.upstream = uhost + ":" + std::to_string(port);

    if (s.auth == "moat") // 이름을 바꾸기 전 값
        s.auth = "douve";
    if (s.auth != "douve" && s.auth != "public")
        return "접근 정책은 douve 또는 public 입니다";
    if (s.publicPaths.size() > 20)
        return "예외 경로는 20개까지입니다";
    for (auto& p : s.publicPaths) {
        if (p.empty() || p.front() != '/' || p.size() > 200 || p.find("..") != std::string::npos ||
            std::any_of(p.begin(), p.end(), [](unsigned char c) {
                return std::isspace(c) || c < 0x20 || c == '?' || c == '#';
            }))
            return "예외 경로 형식 오류: " + p;
        if (p == "/")
            return "전체 공개는 예외 경로 대신 '공개' 정책을 선택하세요";
    }
    if (s.auth == "public")
        s.publicPaths.clear();
    if (s.group.size() > 40 || s.description.size() > 200)
        return "그룹은 40자, 설명은 200자까지입니다";
    if (!validIconName(s.icon))
        return "아이콘 이름은 영문 소문자·숫자·하이픈입니다 (예: nextcloud)";
    return {};
}

bool validIconName(const std::string& s) {
    if (s.size() > 64)
        return false;
    return std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return std::islower(c) || std::isdigit(c) || c == '-';
    });
}

std::string validateLink(Link& l) {
    auto trim = [](std::string& x) {
        x.erase(0, x.find_first_not_of(" \t"));
        x.erase(x.find_last_not_of(" \t") + 1);
    };
    trim(l.name);
    trim(l.url);
    trim(l.group);
    if (l.name.empty() || l.name.size() > 60)
        return "이름은 1~60자입니다";
    if ((l.url.rfind("https://", 0) != 0 && l.url.rfind("http://", 0) != 0) || l.url.size() > 500 ||
        l.url.find_first_of(" \t\r\n\"<>") != std::string::npos)
        return "주소는 http:// 또는 https:// 로 시작해야 합니다";
    if (l.group.size() > 40 || l.description.size() > 200)
        return "그룹은 40자, 설명은 200자까지입니다";
    if (!validIconName(l.icon))
        return "아이콘 이름은 영문 소문자·숫자·하이픈입니다";
    return {};
}

std::vector<Link> listLinks(Database& db) {
    std::vector<Link> out;
    Statement s(db, "SELECT id, name, url, grp, description, icon, position FROM links "
                    "ORDER BY grp, position, name");
    while (s.step())
        out.push_back({s.int64(0), s.text(1), s.text(2), s.text(3), s.text(4), s.text(5),
                       static_cast<int>(s.int64(6))});
    return out;
}

std::optional<Link> findLink(Database& db, std::int64_t id) {
    for (auto& l : listLinks(db))
        if (l.id == id)
            return l;
    return std::nullopt;
}

std::int64_t createLink(Database& db, const Link& l, std::int64_t now) {
    Statement s(db, "INSERT INTO links (name, url, grp, description, icon, position, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)");
    s.bind(1, l.name).bind(2, l.url).bind(3, l.group).bind(4, l.description).bind(5, l.icon);
    s.bind(6, l.position).bind(7, now).run();
    return db.lastInsertId();
}

bool updateLink(Database& db, const Link& l) {
    Statement s(db, "UPDATE links SET name = ?, url = ?, grp = ?, description = ?, icon = ?, "
                    "position = ? WHERE id = ?");
    s.bind(1, l.name).bind(2, l.url).bind(3, l.group).bind(4, l.description).bind(5, l.icon);
    s.bind(6, l.position).bind(7, l.id).run();
    return db.changes() > 0;
}

bool deleteLink(Database& db, std::int64_t id) {
    Statement s(db, "DELETE FROM links WHERE id = ?");
    s.bind(1, id).run();
    return db.changes() > 0;
}

std::vector<Service> listServices(Database& db) {
    std::vector<Service> out;
    Statement s(db, std::string("SELECT ") + kCols + " FROM services ORDER BY position, name");
    while (s.step())
        out.push_back(readService(s));
    return out;
}

std::optional<Service> findService(Database& db, std::int64_t id) {
    Statement s(db, std::string("SELECT ") + kCols + " FROM services WHERE id = ?");
    s.bind(1, id);
    if (!s.step())
        return std::nullopt;
    return readService(s);
}

std::optional<Service> createService(Database& db, Service v, std::int64_t now,
                                     std::string& error) {
    auto guard = db.lock();
    if (nameTaken(db, v.name, 0) || routeTaken(db, v)) {
        error = "같은 이름이나 같은 도메인·경로의 서비스가 이미 있습니다";
        return std::nullopt;
    }
    Statement s(db,
                "INSERT INTO services (name, host, node_id, upstream, auth, public_paths, "
                "created_at, updated_at, grp, description, icon, on_home, position, path_prefix, "
                "strip_prefix, kind, redirect_to, upstream_tls, host_header, timeout, origin, "
                "internal, external) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    s.bind(1, v.name).bind(2, v.host).bind(3, v.nodeId).bind(4, v.upstream).bind(5, v.auth);
    s.bind(6, pathsJson(v.publicPaths)).bind(7, now).bind(8, now).bind(9, v.group);
    s.bind(10, v.description).bind(11, v.icon).bind(12, v.onHome ? 1 : 0).bind(13, v.position);
    s.bind(14, v.pathPrefix)
        .bind(15, v.stripPrefix ? 1 : 0)
        .bind(16, v.kind)
        .bind(17, v.redirectTo);
    s.bind(18, v.upstreamTls).bind(19, v.hostHeader).bind(20, v.timeout).bind(21, v.origin);
    s.bind(22, v.internal ? 1 : 0).bind(23, v.external ? 1 : 0).run();
    return findService(db, db.lastInsertId());
}

bool updateService(Database& db, const Service& v, std::int64_t now, std::string& error) {
    auto guard = db.lock();
    if (nameTaken(db, v.name, v.id) || routeTaken(db, v)) {
        error = "같은 이름이나 같은 도메인·경로의 서비스가 이미 있습니다";
        return false;
    }
    Statement s(db, "UPDATE services SET name = ?, host = ?, node_id = ?, upstream = ?, auth = ?, "
                    "public_paths = ?, updated_at = ?, grp = ?, description = ?, icon = ?, "
                    "on_home = ?, position = ?, path_prefix = ?, strip_prefix = ?, kind = ?, "
                    "redirect_to = ?, upstream_tls = ?, host_header = ?, timeout = ?, "
                    "internal = ?, external = ? WHERE id = ?");
    s.bind(1, v.name).bind(2, v.host).bind(3, v.nodeId).bind(4, v.upstream).bind(5, v.auth);
    s.bind(6, pathsJson(v.publicPaths)).bind(7, now).bind(8, v.group).bind(9, v.description);
    s.bind(10, v.icon).bind(11, v.onHome ? 1 : 0).bind(12, v.position).bind(13, v.pathPrefix);
    s.bind(14, v.stripPrefix ? 1 : 0)
        .bind(15, v.kind)
        .bind(16, v.redirectTo)
        .bind(17, v.upstreamTls);
    s.bind(18, v.hostHeader).bind(19, v.timeout).bind(20, v.internal ? 1 : 0);
    s.bind(21, v.external ? 1 : 0).bind(22, v.id).run();
    if (db.changes() == 0) {
        error = "서비스를 찾을 수 없습니다";
        return false;
    }
    return true;
}

bool deleteService(Database& db, std::int64_t id) {
    Statement s(db, "DELETE FROM services WHERE id = ?");
    s.bind(1, id).run();
    return db.changes() > 0;
}

} // namespace douve
