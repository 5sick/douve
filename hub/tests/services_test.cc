#include "store/nodes.h"
#include "store/services.h"
#include "testing.h"

using namespace douve;

namespace {
Service svc(std::string host, std::string upstream, std::string auth = "douve") {
    Service s;
    s.name = "Kuma";
    s.host = std::move(host);
    s.upstream = std::move(upstream);
    s.auth = std::move(auth);
    return s;
}
} // namespace

TEST(service_validation_normalizes) {
    auto s = svc("Kuma.Example.COM.", "10.200.0.3:03001");
    s.publicPaths = {"/api/push/"};
    CHECK_EQ(validateService(s, "douve.example.com"), "");
    CHECK_EQ(s.host, "kuma.example.com");
    CHECK_EQ(s.upstream, "10.200.0.3:3001");
    CHECK_EQ(s.name, "kuma");
    auto p = svc("a.example.com", "localhost:80", "public");
    p.publicPaths = {"/x"};
    CHECK_EQ(validateService(p, "douve.example.com"), "");
    CHECK(p.publicPaths.empty()); // 공개면 예외 경로 의미 없음
}

TEST(service_validation_rejects) {
    const std::string hub = "douve.example.com";
    auto bad = [&](Service s) { return !validateService(s, hub).empty(); };
    CHECK(bad(svc("douve.example.com", "10.0.0.1:80"))); // Hub 도메인 탈취
    CHECK(bad(svc("localhost", "10.0.0.1:80")));         // 라벨 1개
    CHECK(bad(svc("a_b.example.com", "10.0.0.1:80")));
    CHECK(bad(svc("-a.example.com", "10.0.0.1:80")));
    CHECK(bad(svc("a.example.com", "http://10.0.0.1:80")));
    CHECK(bad(svc("a.example.com", "10.0.0.1")));
    CHECK(bad(svc("a.example.com", "10.0.0.1:0")));
    CHECK(bad(svc("a.example.com", "10.0.0.1:65536")));
    CHECK(bad(svc("a.example.com", "10.0.0.1:80/x")));
    CHECK(bad(svc("a.example.com", "10.0.0.1:8a")));
    CHECK(bad(svc("a.example.com", "10.0.0.1:80", "none")));
    auto s = svc("a.example.com", "10.0.0.1:80");
    s.publicPaths = {"/"};
    CHECK(bad(s));
    s.publicPaths = {"/../admin"};
    CHECK(bad(s));
    s.publicPaths = {"api"};
    CHECK(bad(s));
    s.publicPaths = {"/a b"};
    CHECK(bad(s));
    auto n = svc("a.example.com", "10.0.0.1:80");
    n.name = "한글";
    CHECK(bad(n));
}

TEST(service_crud_and_uniqueness) {
    Database db(":memory:");
    std::string err;
    auto a = svc("kuma.example.com", "10.200.0.3:3001");
    validateService(a, "douve.example.com");
    auto created = createService(db, a, 100, err);
    CHECK(created.has_value());
    auto dup = a;
    dup.name = "other";
    CHECK(!createService(db, dup, 101, err).has_value()); // 도메인 중복
    auto b = svc("home.example.com", "10.200.0.2:3000");
    b.name = "home";
    validateService(b, "douve.example.com");
    auto cb = createService(db, b, 102, err);
    CHECK(cb.has_value());
    cb->host = "kuma.example.com";
    CHECK(!updateService(db, *cb, 103, err)); // 다른 서비스 도메인으로 변경 불가
    cb->host = "home2.example.com";
    cb->publicPaths = {"/api/"};
    CHECK(updateService(db, *cb, 103, err));
    auto got = findService(db, cb->id);
    CHECK(got && got->host == "home2.example.com" && got->publicPaths.size() == 1);
    CHECK_EQ(listServices(db).size(), std::size_t{2});
    CHECK(deleteService(db, created->id));
    CHECK_EQ(listServices(db).size(), std::size_t{1});
}

TEST(mesh_address_prefers_wireguard) {
    CHECK_EQ(pickMeshAddress(R"({"system":{"addresses":[
        {"interface":"enp0s6","cidr":"10.0.0.194/24"},
        {"interface":"wg0","cidr":"10.200.0.2/24"}]}})"),
             "10.200.0.2");
    CHECK_EQ(pickMeshAddress(R"({"system":{"addresses":[
        {"interface":"eth0","cidr":"203.0.113.5/24"},
        {"interface":"eth1","cidr":"172.20.1.5/16"}]}})"),
             "172.20.1.5");
    CHECK_EQ(
        pickMeshAddress(R"({"system":{"addresses":[{"interface":"wg0","cidr":"fd00::1/64"}]}})"),
        "");
    CHECK_EQ(pickMeshAddress("not json"), "");
}

TEST(service_route_options_validation) {
    const std::string hub = "douve.example.com";
    auto s = svc("app.example.com", "10.0.0.1:80");
    s.pathPrefix = "/api/";
    s.stripPrefix = true;
    CHECK_EQ(validateService(s, hub), "");
    CHECK_EQ(s.pathPrefix, "/api"); // 끝의 / 제거
    auto root = svc("app.example.com", "10.0.0.1:80");
    root.stripPrefix = true;
    CHECK_EQ(validateService(root, hub), "");
    CHECK(!root.stripPrefix); // "/"는 제거할 접두사 없음
    for (const char* bad : {"api", "/a b", "/../x", "/a?b", "/%2e"}) {
        auto b = svc("app.example.com", "10.0.0.1:80");
        b.pathPrefix = bad;
        CHECK(!validateService(b, hub).empty());
    }
    auto r = svc("example.com", "");
    r.kind = "redirect";
    r.redirectTo = "https://douve.example.com/";
    CHECK_EQ(validateService(r, hub), "");
    CHECK_EQ(r.auth, "public");
    r.redirectTo = "javascript:alert(1)";
    CHECK(!validateService(r, hub).empty());
    auto t = svc("pve.example.com", "10.0.0.5:8006");
    t.upstreamTls = 2;
    t.timeout = 300;
    t.hostHeader = "pve.local";
    CHECK_EQ(validateService(t, hub), "");
    t.upstreamTls = 3;
    CHECK(!validateService(t, hub).empty());
    t.upstreamTls = 1;
    t.timeout = 5000;
    CHECK(!validateService(t, hub).empty());
    auto k = svc("x.example.com", "10.0.0.1:80");
    k.kind = "tcp";
    CHECK(!validateService(k, hub).empty());
}

TEST(service_same_host_different_paths) {
    Database db(":memory:");
    std::string err;
    auto a = svc("app.example.com", "10.0.0.1:80");
    a.name = "web";
    validateService(a, "douve.example.com");
    CHECK(createService(db, a, 1, err).has_value());
    auto b = svc("app.example.com", "10.0.0.2:8080");
    b.name = "api";
    b.pathPrefix = "/api";
    validateService(b, "douve.example.com");
    CHECK(createService(db, b, 1, err).has_value()); // 같은 도메인, 다른 경로
    auto c = svc("app.example.com", "10.0.0.3:1");
    c.name = "dup";
    c.pathPrefix = "/api";
    validateService(c, "douve.example.com");
    CHECK(!createService(db, c, 1, err).has_value()); // 같은 도메인·경로
    auto got = listServices(db);
    CHECK_EQ(got.size(), std::size_t{2});
}

// 모든 필드가 저장·조회에서 그대로 유지되는지 (열 목록·바인딩 누락 방지)
TEST(service_all_fields_round_trip) {
    Database db(":memory:");
    db.exec("INSERT INTO nodes (id, name, pubkey, created_at) VALUES (7, 'n7', x'01', 0)");
    Service s = svc("app.example.com", "10.0.0.9:8443");
    s.name = "full";
    s.nodeId = 7;
    s.auth = "douve";
    s.publicPaths = {"/hook/"};
    s.pathPrefix = "/api";
    s.stripPrefix = true;
    s.upstreamTls = 2;
    s.hostHeader = "inner.local";
    s.timeout = 42;
    s.group = "그룹";
    s.description = "설명";
    s.icon = "grafana";
    s.onHome = false;
    s.position = 3;
    s.origin = "node";
    CHECK_EQ(validateService(s, "douve.example.com"), "");
    std::string err;
    auto c = createService(db, s, 100, err);
    CHECK(c.has_value());
    auto check = [&](const Service& g) {
        CHECK_EQ(g.name, "full");
        CHECK(g.nodeId && *g.nodeId == 7);
        CHECK_EQ(g.upstream, "10.0.0.9:8443");
        CHECK(g.publicPaths.size() == 1 && g.publicPaths[0] == "/hook/");
        CHECK_EQ(g.pathPrefix, "/api");
        CHECK(g.stripPrefix);
        CHECK_EQ(g.upstreamTls, 2);
        CHECK_EQ(g.hostHeader, "inner.local");
        CHECK_EQ(g.timeout, 42);
        CHECK_EQ(g.group, "그룹");
        CHECK_EQ(g.description, "설명");
        CHECK_EQ(g.icon, "grafana");
        CHECK(!g.onHome);
        CHECK_EQ(g.position, 3);
        CHECK_EQ(g.origin, "node");
    };
    check(*c);
    auto u = *c;
    u.timeout = 43;
    CHECK(updateService(db, u, 101, err));
    auto again = findService(db, c->id);
    CHECK(again && again->timeout == 43 && again->origin == "node"); // 갱신해도 만든 곳 유지
    auto r = svc("go.example.com", "");
    r.name = "redir";
    r.kind = "redirect";
    r.redirectTo = "https://x.example.com/";
    validateService(r, "douve.example.com");
    auto rc = createService(db, r, 1, err);
    CHECK(rc && rc->kind == "redirect" && rc->redirectTo == "https://x.example.com/" &&
          rc->origin == "web");
}

TEST(services_loopback_upstream) {
    CHECK(isLoopbackUpstream("127.0.0.1:8080"));
    CHECK(isLoopbackUpstream("localhost:80"));
    CHECK(!isLoopbackUpstream("10.200.0.2:8080"));
    CHECK(!isLoopbackUpstream("1270.0.0.1:80"));
}

TEST(services_legacy_moat_policy) {
    Service s;
    s.name = "old";
    s.host = "old.example.com";
    s.upstream = "10.0.0.1:80";
    s.auth = "moat";
    CHECK(validateService(s, "hub.example.com").empty());
    CHECK(s.auth == "douve");
}
