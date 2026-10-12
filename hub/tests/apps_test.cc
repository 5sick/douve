#include "cluster/apps.h"
#include "testing.h"

using namespace douve;

namespace {
Json::Value J(const char* s) {
    Json::Value v;
    Json::Reader().parse(s, v);
    return v;
}
Node node() {
    Node n;
    n.id = 2;
    n.name = "node2";
    n.meshAddress = "10.200.0.2";
    return n;
}
const Json::Value* find(const Json::Value& arr, const std::string& name, int port) {
    for (const auto& a : arr)
        if (a["name"].asString() == name && a["port"].asInt() == port)
            return &a;
    return nullptr;
}
} // namespace

TEST(apps_icon_and_name) {
    CHECK(iconFromImage("lscr.io/linuxserver/jellyfin:latest") == "jellyfin");
    CHECK(iconFromImage("nextcloud:apache") == "nextcloud");
    CHECK(iconFromImage("ghcr.io/home-assistant/home-assistant@sha256:abc") == "home-assistant");
    CHECK(iconFromImage("louislam/uptime_kuma:1") == "uptime-kuma");
    CHECK(suggestName("My_App") == "my-app");
}

TEST(apps_discover_containers_and_processes) {
    auto inv = J(R"({
      "containers": [
        {"name":"jellyfin","image":"jellyfin/jellyfin","state":"running",
         "bindings":[{"ip":"0.0.0.0","port":8096,"private_port":8096},{"ip":"::","port":8096,"private_port":8096}]},
        {"name":"secret","image":"vaultwarden/server:latest","state":"running",
         "bindings":[{"ip":"127.0.0.1","port":8081,"private_port":80}]},
        {"name":"unifi","image":"unifi","state":"running",
         "bindings":[{"ip":"0.0.0.0","port":8443,"private_port":8443}]},
        {"name":"worker","image":"busybox","state":"running"},
        {"name":"old","image":"x","state":"exited","bindings":[{"ip":"0.0.0.0","port":9999}]},
        {"name":"legacy","image":"grafana/grafana","state":"running","ports":[3000]}
      ],
      "ports": [
        {"address":"0.0.0.0","port":8096,"process":"docker-proxy"},
        {"address":"0.0.0.0","port":22,"process":"sshd"},
        {"address":"127.0.0.1","port":5432,"process":"postgres"},
        {"address":"127.0.0.1","port":3000,"process":"docker-proxy"},
        {"address":"0.0.0.0","port":5000,"process":"python3"},
        {"address":"127.0.0.1","port":8700,"process":"douve-hub"}
      ]})");
    Service s;
    s.id = 7;
    s.name = "jelly";
    s.host = "jelly.example.com";
    s.nodeId = 2;
    s.upstream = "10.200.0.2:8096";
    auto apps = discoverApps(node(), inv, {s});

    auto* j = find(apps, "jellyfin", 8096);
    CHECK(j != nullptr);
    if (j) {
        CHECK((*j)["upstream"].asString() == "10.200.0.2:8096");
        CHECK((*j)["published"]["id"].asInt64() == 7);
        CHECK((*j)["icon"].asString() == "jellyfin");
        CHECK(!(*j)["loopback"].asBool());
    }
    int jellyCount = 0;
    for (const auto& a : apps)
        jellyCount += a["name"].asString() == "jellyfin";
    CHECK(jellyCount == 1); // IPv4·IPv6 바인드는 하나로

    auto* v = find(apps, "secret", 8081);
    CHECK(v && (*v)["upstream"].asString() == "127.0.0.1:8081" && (*v)["loopback"].asBool());
    CHECK(v && (*v)["published"].isNull());

    auto* u = find(apps, "unifi", 8443);
    CHECK(u && (*u)["upstream_tls"].asInt() == 2);

    auto* w = find(apps, "worker", 0);
    CHECK(w && (*w)["no_port"].asBool());

    CHECK(find(apps, "old", 9999) == nullptr); // 멈춘 컨테이너 제외

    auto* g = find(apps, "legacy", 3000); // 바인드 정보 없는 예전 Agent: 열린 포트 주소로
    CHECK(g && (*g)["upstream"].asString() == "127.0.0.1:3000");

    auto* p = find(apps, "python3", 5000);
    CHECK(p && p->get("kind", "").asString() == "process");
    CHECK(find(apps, "sshd", 22) == nullptr);
    CHECK(find(apps, "postgres", 5432) == nullptr);
    CHECK(find(apps, "douve-hub", 8700) == nullptr);
    CHECK(find(apps, "docker-proxy", 8096) == nullptr);
}
