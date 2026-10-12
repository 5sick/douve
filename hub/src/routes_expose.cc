// 노드에서 바로 공개: `douve-agent expose <포트>` (tailscale serve와 비슷).
// 자기 노드의 포트만, 기본 도메인 아래 주소만, 다른 노드가 만든 서비스는 건드릴 수 없다. 감사
// 로그·알림.

#include "app.h"
#include "cluster/gateway.h"
#include "store/invites.h"
#include "store/nodes.h"
#include "store/repo.h"
#include "store/services.h"

#include <drogon/drogon.h>

namespace douve {

namespace {

Json::Value fail(const std::string& why) {
    Json::Value v;
    v["ok"] = false;
    v["error"] = why;
    return v;
}

bool endsWith(const std::string& s, const std::string& suf) {
    return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

} // namespace

Json::Value HubApp::handleExpose(std::int64_t nodeId, const Json::Value& req) {
    const auto t = now();
    auto node = findNode(*db_, nodeId);
    if (!node)
        return fail("노드를 찾을 수 없습니다");
    if (getSetting(*db_, "agent.expose").value_or("on") == "off")
        return fail("Douve 설정에서 '노드에서 서비스 공개'가 꺼져 있습니다");
    const std::string op = req.get("op", "").asString();

    if (op == "list") {
        Json::Value v;
        v["ok"] = true;
        v["services"] = Json::Value(Json::arrayValue);
        for (const auto& s : listServices(*db_)) {
            if (s.nodeId != nodeId || s.origin != "node")
                continue;
            Json::Value x;
            x["name"] = s.name;
            x["url"] = "https://" + s.host + (s.pathPrefix == "/" ? "" : s.pathPrefix);
            x["upstream"] = s.kind == "redirect" ? s.redirectTo : s.upstream;
            x["auth"] = s.auth;
            v["services"].append(x);
        }
        return v;
    }

    if (op == "unexpose") {
        const std::string name = sanitizeNodeName(req.get("name", "").asString());
        for (const auto& s : listServices(*db_)) {
            if (s.name != name)
                continue;
            if (s.nodeId != nodeId || s.origin != "node")
                return fail(
                    "이 서버가 공개한 서비스가 아닙니다 (웹에서 만든 서비스는 웹에서 관리)");
            deleteService(*db_, s.id);
            audit(*db_, std::nullopt, "service_unexposed", node->name, s.name + " " + s.host, t);
            notify("🔗 [" + node->name + "] 서비스 공개 해제: " + s.name + " (" + s.host + ")");
            pushRoutes();
            Json::Value v;
            v["ok"] = true;
            return v;
        }
        return fail("그런 이름의 서비스가 없습니다: " + name);
    }

    if (op != "expose")
        return fail("알 수 없는 요청");
    const int port = req.get("port", 0).asInt();
    if (port < 1 || port > 65535)
        return fail("포트가 올바르지 않습니다");

    // 인벤토리로 포트 상태·이름 추정
    auto inv = live_.inventory(nodeId);
    std::string guessName, warning;
    bool listening = false, loopbackOnly = true;
    if (inv) {
        for (const auto& c : (*inv)["containers"])
            for (const auto& p : c["ports"])
                if (p.asInt() == port)
                    guessName = c.get("name", "").asString();
        for (const auto& p : (*inv)["ports"]) {
            if (p.get("port", 0).asInt() != port)
                continue;
            listening = true;
            const std::string addr = p.get("address", "").asString();
            if (addr.rfind("127.", 0) != 0 && addr != "::1")
                loopbackOnly = false;
            if (guessName.empty())
                guessName = p.get("process", "").asString();
        }
    }
    std::string upstreamHost = node->meshAddress;
    if (listening && loopbackOnly) {
        if (!node->edge)
            return fail(
                "포트 " + std::to_string(port) +
                "이(가) 127.0.0.1에서만 열려 있어 입구 서버에서 닿을 수 없습니다. 0.0.0.0 또는 " +
                (node->meshAddress.empty() ? "메시 주소" : node->meshAddress) + "에서 열어 주세요");
        upstreamHost = "127.0.0.1"; // 입구가 같은 서버
    }
    if (upstreamHost.empty())
        return fail("이 서버의 메시 주소를 아직 모릅니다 (잠시 후 다시 시도)");
    if (!listening && inv)
        warning = "아직 포트 " + std::to_string(port) +
                  "이(가) 열려 있지 않습니다. 앱을 실행하면 바로 연결됩니다";

    Service s;
    s.name = req.get("name", "").asString();
    if (s.name.empty())
        s.name = guessName.empty() ? "port-" + std::to_string(port) : guessName;
    s.name = sanitizeNodeName(s.name);
    if (s.name.empty())
        s.name = "port-" + std::to_string(port);
    s.host = req.get("host", "").asString();
    if (s.host.empty())
        s.host = s.name + "." + cfg_.cookieDomain;
    s.pathPrefix = req.get("path", "").asString();
    s.auth = req.get("auth", "douve").asString() == "public" ? "public" : "douve";
    s.nodeId = nodeId;
    s.upstream = upstreamHost + ":" + std::to_string(port);
    s.group = "노드에서 공개";
    s.origin = "node";
    // 노드가 만드는 서비스는 기본 도메인 아래로만
    std::string hostLower = s.host;
    std::transform(hostLower.begin(), hostLower.end(), hostLower.begin(), ::tolower);
    if (hostLower != cfg_.cookieDomain && !endsWith(hostLower, "." + cfg_.cookieDomain))
        return fail("노드에서는 " + cfg_.cookieDomain +
                    " 아래 도메인만 공개할 수 있습니다 (다른 도메인은 Douve 웹에서)");

    // 같은 이름이 있으면: 이 노드가 만든 것이면 갱신, 아니면 거부
    std::optional<Service> existing;
    for (const auto& x : listServices(*db_))
        if (x.name == sanitizeNodeName(s.name))
            existing = x;
    if (existing && (existing->nodeId != nodeId || existing->origin != "node"))
        return fail("같은 이름의 서비스가 이미 있습니다 (다른 서버 또는 웹에서 만든 것): " +
                    existing->name);
    if (existing) {
        s.id = existing->id;
        s.description = existing->description;
        s.icon = existing->icon;
        s.group = existing->group;
        s.onHome = existing->onHome;
    }
    std::string url = "https://" + s.host;
    if (auto err = validateService(s, cfg_.publicUrl.substr(cfg_.publicUrl.find("://") + 3));
        !err.empty())
        return fail(err);
    std::string err;
    if (existing ? !updateService(*db_, s, t, err) : !createService(*db_, s, t, err).has_value())
        return fail(err);
    if (s.pathPrefix != "/")
        url += s.pathPrefix;
    audit(*db_, std::nullopt, "service_exposed", node->name,
          s.name + " " + url + " → " + s.upstream + " (" + s.auth + ")", t);
    notify("🔗 [" + node->name + "] 서비스 공개: " + s.name + " → " + url +
           (s.auth == "public" ? " (누구나)" : " (Douve 로그인)"));
    pushRoutes();
    Json::Value v;
    v["ok"] = true;
    v["url"] = url;
    if (!warning.empty())
        v["warning"] = warning;
    return v;
}

} // namespace douve
