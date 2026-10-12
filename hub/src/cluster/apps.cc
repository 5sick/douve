#include "cluster/apps.h"

#include <map>
#include <set>

namespace douve {

namespace {

// 공개할 대상이 아닌 포트·프로세스 (시스템·Douve 자신)
const std::set<int> kSkipPorts = {22,   25,   53,   111,   323,   631,  3306,
                                  5355, 5432, 6379, 11211, 27017, 51820};
const std::set<std::string> kSkipProcesses = {
    "douve-hub",    "douve-agent", "sshd",     "systemd-resolve", "systemd-resolved",
    "chronyd",      "rpcbind",     "cupsd",    "master",          "dnsmasq",
    "postgres",     "mysqld",      "mariadbd", "redis-server",    "tailscaled",
    "docker-proxy", "containerd",  "dockerd",  "rpc.statd"};

bool isLoopbackIp(const std::string& ip) {
    return ip.rfind("127.", 0) == 0 || ip == "::1" || ip == "localhost";
}
bool isWildcard(const std::string& ip) {
    return ip.empty() || ip == "0.0.0.0" || ip == "::";
}

// 입구에서 이 포트로 가는 업스트림. 모든 주소면 메시 주소, 루프백이면 127.0.0.1(터널),
// 특정 주소면 그 주소.
std::string upstreamFor(const Node& n, const std::string& ip, int port) {
    std::string host;
    if (isLoopbackIp(ip))
        host = "127.0.0.1";
    else if (isWildcard(ip))
        host = n.meshAddress.empty() ? "127.0.0.1" : n.meshAddress;
    else if (ip.find(':') != std::string::npos)
        host = n.meshAddress.empty() ? "127.0.0.1" : n.meshAddress; // IPv6 특정 주소: 메시로
    else
        host = ip;
    return host + ":" + std::to_string(port);
}

int portOf(const std::string& upstream) {
    auto i = upstream.rfind(':');
    return i == std::string::npos ? 0 : std::atoi(upstream.c_str() + i + 1);
}

int tlsGuess(int privatePort, int port) {
    for (int p : {privatePort, port})
        if (p == 443 || p == 8443 || p == 9443)
            return 2; // https(자체 서명 허용)
    return 0;
}

} // namespace

std::string suggestName(const std::string& s) {
    return sanitizeNodeName(s);
}

std::string iconFromImage(const std::string& image) {
    std::string s = image;
    if (auto at = s.find('@'); at != std::string::npos)
        s.resize(at);
    if (auto slash = s.rfind('/'); slash != std::string::npos)
        s = s.substr(slash + 1);
    if (auto colon = s.find(':'); colon != std::string::npos)
        s.resize(colon);
    std::string out;
    for (unsigned char c : s) {
        if (std::isalnum(c))
            out += static_cast<char>(std::tolower(c));
        else if ((c == '-' || c == '_' || c == '.') && !out.empty() && out.back() != '-')
            out += '-';
    }
    while (!out.empty() && out.back() == '-')
        out.pop_back();
    if (out.size() > 64)
        out.resize(64);
    return out;
}

Json::Value discoverApps(const Node& n, const Json::Value& inv,
                         const std::vector<Service>& services) {
    // 이 노드의 포트 → 이미 공개된 서비스
    std::map<int, const Service*> published;
    for (const auto& s : services)
        if (s.nodeId && *s.nodeId == n.id && s.kind == "proxy")
            published.emplace(portOf(s.upstream), &s);

    // 열린 포트의 바인드 주소 (포트 → 주소들)
    std::map<int, std::vector<std::string>> listenAddrs;
    std::map<int, std::string> processOf;
    for (const auto& p : inv["ports"]) {
        const int port = p.get("port", 0).asInt();
        listenAddrs[port].push_back(p.get("address", "").asString());
        if (!processOf.count(port))
            processOf[port] = p.get("process", "").asString();
    }

    Json::Value out(Json::arrayValue);
    std::set<int> taken; // 컨테이너가 차지한 호스트 포트
    auto add = [&](Json::Value v, int port) {
        v["node_id"] = Json::Int64(n.id);
        v["node_name"] = n.name;
        auto it = published.find(port);
        if (port > 0 && it != published.end()) {
            Json::Value p;
            p["id"] = Json::Int64(it->second->id);
            p["name"] = it->second->name;
            p["host"] = it->second->host;
            p["path_prefix"] = it->second->pathPrefix;
            v["published"] = p;
        } else {
            v["published"] = Json::nullValue;
        }
        out.append(v);
    };

    for (const auto& c : inv["containers"]) {
        if (c.get("state", "").asString() != "running")
            continue;
        const std::string name = c.get("name", "").asString();
        const std::string image = c.get("image", "").asString();
        // 포트별로 가장 좋은 바인드 하나 (모든 주소 > 특정 주소 > 루프백)
        std::map<int, Json::Value> best;
        auto rank = [](const std::string& ip) {
            return isWildcard(ip) ? 0 : isLoopbackIp(ip) ? 2 : 1;
        };
        for (const auto& b : c["bindings"]) {
            const int port = b.get("port", 0).asInt();
            if (port <= 0)
                continue;
            auto it = best.find(port);
            if (it == best.end() ||
                rank(b.get("ip", "").asString()) < rank(it->second.get("ip", "").asString()))
                best[port] = b;
        }
        // 예전 Agent(바인드 정보 없음): 포트만 — 열린 포트 목록에서 주소를 찾는다
        if (c["bindings"].empty()) {
            for (const auto& p : c["ports"]) {
                const int port = p.asInt();
                Json::Value b;
                b["port"] = port;
                b["private_port"] = 0;
                std::string ip = "0.0.0.0";
                if (auto it = listenAddrs.find(port);
                    it != listenAddrs.end() && !it->second.empty()) {
                    ip = it->second.front();
                    for (const auto& a : it->second)
                        if (rank(a) < rank(ip))
                            ip = a;
                }
                b["ip"] = ip;
                best[port] = b;
            }
        }
        if (best.empty()) {
            Json::Value v;
            v["kind"] = "container";
            v["name"] = name;
            v["image"] = image;
            v["port"] = 0;
            v["no_port"] = true;
            v["suggest_name"] = suggestName(name);
            v["icon"] = iconFromImage(image);
            add(v, 0);
            continue;
        }
        for (const auto& [port, b] : best) {
            taken.insert(port);
            const std::string ip = b.get("ip", "").asString();
            const int priv = b.get("private_port", 0).asInt();
            Json::Value v;
            v["kind"] = "container";
            v["name"] = name;
            v["image"] = image;
            v["port"] = port;
            v["private_port"] = priv;
            v["upstream"] = upstreamFor(n, ip, port);
            v["upstream_tls"] = tlsGuess(priv, port);
            v["loopback"] = isLoopbackIp(ip);
            v["suggest_name"] = best.size() > 1 ? suggestName(name + "-" + std::to_string(port))
                                                : suggestName(name);
            v["icon"] = iconFromImage(image);
            add(v, port);
        }
    }

    // 컨테이너가 아닌 프로그램이 연 포트
    for (const auto& [port, addrs] : listenAddrs) {
        if (port <= 0 || taken.count(port) || kSkipPorts.count(port))
            continue;
        const std::string proc = processOf[port];
        if (kSkipProcesses.count(proc))
            continue;
        std::string ip = addrs.front();
        bool wildcard = false;
        for (const auto& a : addrs) {
            if (isWildcard(a))
                wildcard = true;
            if (!n.meshAddress.empty() && a == n.meshAddress)
                ip = a;
        }
        if (wildcard)
            ip = "0.0.0.0";
        Json::Value v;
        v["kind"] = "process";
        v["name"] = proc.empty() ? "port-" + std::to_string(port) : proc;
        v["image"] = "";
        v["port"] = port;
        v["private_port"] = 0;
        v["upstream"] = upstreamFor(n, ip, port);
        v["upstream_tls"] = tlsGuess(0, port);
        v["loopback"] = isLoopbackIp(ip);
        v["suggest_name"] = suggestName(proc.empty() ? "port-" + std::to_string(port) : proc);
        v["icon"] = iconFromImage(proc);
        add(v, port);
    }
    return out;
}

} // namespace douve
