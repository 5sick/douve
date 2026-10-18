#include "store/nodes.h"
#include "util/json.h"

#include "util/crypto.h"

#include <json/json.h>

#include <cctype>
#include <cstdlib>
#include <sstream>

namespace douve {
namespace {

Node readNode(Statement& s) {
    Node n;
    n.id = s.int64(0);
    n.name = s.text(1);
    n.pubkey = s.blob(2);
    n.hostname = s.text(3);
    n.os = s.text(4);
    n.arch = s.text(5);
    n.agentVersion = s.text(6);
    n.createdAt = s.int64(7);
    if (!s.isNull(8))
        n.lastSeenAt = s.int64(8);
    n.lastIp = s.text(9);
    n.inventory = s.text(10);
    n.edge = s.int64(11) != 0;
    n.meshAddress = s.text(12);
    n.connectMode = s.text(13);
    n.portForward = s.int64(14) != 0;
    return n;
}

constexpr const char* kNodeCols =
    "id, name, pubkey, hostname, os, arch, agent_version, created_at, "
    "last_seen_at, last_ip, inventory, edge, mesh_address, connect_mode, port_forward";

bool nameTaken(Database& db, const std::string& name) {
    Statement s(db, "SELECT 1 FROM nodes WHERE name = ?");
    s.bind(1, name);
    return s.step();
}

} // namespace

std::string sanitizeNodeName(const std::string& raw) {
    std::string out;
    for (unsigned char c : raw) {
        if (std::isalnum(c))
            out += static_cast<char>(std::tolower(c));
        else if ((c == '-' || c == '_' || c == '.' || c == ' ') && !out.empty() &&
                 out.back() != '-')
            out += '-';
        if (out.size() >= 32)
            break;
    }
    while (!out.empty() && out.back() == '-')
        out.pop_back();
    return out;
}

JoinToken createJoinToken(Database& db, std::optional<std::int64_t> userId, const std::string& name,
                          int ttlSeconds, std::int64_t now) {
    JoinToken t;
    t.token = randomToken(32);
    t.expiresAt = now + ttlSeconds;
    Statement s(db,
                "INSERT INTO join_tokens (token_hash, name, created_by, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)");
    s.bind(1, sha256(t.token)).bind(2, sanitizeNodeName(name)).bind(3, userId).bind(4, now);
    s.bind(5, t.expiresAt).run();
    return t;
}

std::optional<Node> enrollNode(Database& db, const EnrollRequest& req, std::int64_t now,
                               std::string& error) {
    if (req.pubkey.size() != 32) {
        error = "공개키 형식 오류";
        return std::nullopt;
    }
    Transaction tx(db);
    Statement q(db, "SELECT name FROM join_tokens WHERE token_hash = ? AND used_at IS NULL AND "
                    "expires_at > ?");
    q.bind(1, sha256(req.token)).bind(2, now);
    if (!q.step()) {
        error = "토큰이 없거나 만료되었거나 이미 사용되었습니다";
        return std::nullopt;
    }
    std::string base = q.text(0);
    if (base.empty())
        base = sanitizeNodeName(req.hostname);
    if (base.empty())
        base = "node";
    {
        Statement dup(db, "SELECT 1 FROM nodes WHERE pubkey = ?");
        dup.bind(1, req.pubkey);
        if (dup.step()) {
            error = "이미 등록된 공개키입니다";
            return std::nullopt;
        }
    }
    std::string name = base;
    for (int i = 2; nameTaken(db, name); ++i)
        name = base.substr(0, 28) + "-" + std::to_string(i);

    Statement ins(db, "INSERT INTO nodes (name, pubkey, hostname, os, arch, agent_version, "
                      "created_at, last_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    ins.bind(1, name).bind(2, req.pubkey).bind(3, req.hostname.substr(0, 64));
    ins.bind(4, req.os.substr(0, 64)).bind(5, req.arch.substr(0, 16));
    ins.bind(6, req.agentVersion.substr(0, 32)).bind(7, now).bind(8, req.ip).run();
    const std::int64_t id = db.lastInsertId();

    Statement use(db, "UPDATE join_tokens SET used_at = ?, node_id = ? WHERE token_hash = ?");
    use.bind(1, now).bind(2, id).bind(3, sha256(req.token)).run();
    tx.commit();
    return findNode(db, id);
}

std::vector<Node> listNodes(Database& db) {
    std::vector<Node> out;
    Statement s(db, std::string("SELECT ") + kNodeCols + " FROM nodes ORDER BY name");
    while (s.step())
        out.push_back(readNode(s));
    return out;
}

std::optional<Node> findNode(Database& db, std::int64_t id) {
    Statement s(db, std::string("SELECT ") + kNodeCols + " FROM nodes WHERE id = ?");
    s.bind(1, id);
    if (!s.step())
        return std::nullopt;
    return readNode(s);
}

bool deleteNode(Database& db, std::int64_t id) {
    Statement s(db, "DELETE FROM nodes WHERE id = ?");
    s.bind(1, id).run();
    return db.changes() > 0;
}

bool renameNode(Database& db, std::int64_t id, const std::string& name) {
    const std::string clean = sanitizeNodeName(name);
    if (clean.empty() || nameTaken(db, clean))
        return false;
    Statement s(db, "UPDATE nodes SET name = ? WHERE id = ?");
    s.bind(1, clean).bind(2, id).run();
    return db.changes() > 0;
}

void touchNode(Database& db, std::int64_t id, const std::string& ip,
               const std::string& agentVersion, std::int64_t now) {
    Statement s(db, "UPDATE nodes SET last_seen_at = ?, last_ip = ?, agent_version = "
                    "CASE WHEN ? = '' THEN agent_version ELSE ? END WHERE id = ?");
    s.bind(1, now).bind(2, ip).bind(3, agentVersion).bind(4, agentVersion.substr(0, 32));
    s.bind(5, id).run();
}

void saveInventory(Database& db, std::int64_t id, const std::string& json) {
    Statement s(db, "UPDATE nodes SET inventory = ? WHERE id = ?");
    s.bind(1, json).bind(2, id).run();
}

bool setNodeEdge(Database& db, std::int64_t id, bool edge) {
    Statement s(db, "UPDATE nodes SET edge = ? WHERE id = ?");
    s.bind(1, edge ? 1 : 0).bind(2, id).run();
    return db.changes() > 0;
}

bool setNodeConnectMode(Database& db, std::int64_t id, const std::string& mode) {
    if (mode != "auto" && mode != "direct" && mode != "tunnel")
        return false;
    Statement s(db, "UPDATE nodes SET connect_mode = ? WHERE id = ?");
    s.bind(1, mode).bind(2, id).run();
    return db.changes() > 0;
}

bool setNodePortForward(Database& db, std::int64_t id, bool on) {
    Statement s(db, "UPDATE nodes SET port_forward = ? WHERE id = ?");
    s.bind(1, on ? 1 : 0).bind(2, id).run();
    return db.changes() > 0;
}

void setMeshAddress(Database& db, std::int64_t id, const std::string& address) {
    Statement s(db, "UPDATE nodes SET mesh_address = ? WHERE id = ? AND mesh_address != ?");
    s.bind(1, address).bind(2, id).bind(3, address).run();
}

std::string pickMeshAddress(const std::string& inventoryJson) {
    Json::Value inv;
    if (!parseJson(inventoryJson, inv) || !inv.isObject())
        return {};
    std::string fallback, tailscale;
    for (const auto& a : inv["system"]["addresses"]) {
        const std::string iface = a.get("interface", "").asString();
        std::string cidr = a.get("cidr", "").asString();
        const std::string ip = cidr.substr(0, cidr.find('/'));
        if (ip.find(':') != std::string::npos || ip.empty())
            continue; // IPv4만
        const bool priv = ip.rfind("10.", 0) == 0 || ip.rfind("192.168.", 0) == 0 ||
                          (ip.rfind("172.", 0) == 0 && [&] {
                              int b = std::atoi(ip.c_str() + 4);
                              return b >= 16 && b <= 31;
                          }());
        if (iface.rfind("wg", 0) == 0)
            return ip;
        if (iface.rfind("tailscale", 0) == 0 && tailscale.empty())
            tailscale = ip; // WireGuard가 없으면 Tailscale(100.x)
        if (priv && fallback.empty())
            fallback = ip;
    }
    return tailscale.empty() ? fallback : tailscale;
}

void insertMetric(Database& db, std::int64_t nodeId, const MetricRow& m) {
    Statement s(db, "INSERT OR REPLACE INTO metrics (node_id, ts, cpu, mem_used, mem_total, "
                    "swap_used, swap_total, disk_used, disk_total, net_rx, net_tx, load1) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    s.bind(1, nodeId).bind(2, m.ts).bind(3, m.cpu).bind(4, m.memUsed).bind(5, m.memTotal);
    s.bind(6, m.swapUsed).bind(7, m.swapTotal).bind(8, m.diskUsed).bind(9, m.diskTotal);
    s.bind(10, m.netRx).bind(11, m.netTx).bind(12, m.load1).run();
}

std::vector<MetricRow> queryMetrics(Database& db, std::int64_t nodeId, std::int64_t since,
                                    std::int64_t bucketSeconds) {
    if (bucketSeconds < 60)
        bucketSeconds = 60;
    std::vector<MetricRow> out;
    Statement s(db, "SELECT (ts / ?1) * ?1 AS b, avg(cpu), avg(mem_used), max(mem_total), "
                    "avg(swap_used), max(swap_total), avg(disk_used), max(disk_total), "
                    "avg(net_rx), avg(net_tx), avg(load1) FROM metrics "
                    "WHERE node_id = ?2 AND ts >= ?3 GROUP BY b ORDER BY b");
    s.bind(1, bucketSeconds).bind(2, nodeId).bind(3, since);
    while (s.step()) {
        MetricRow m;
        m.ts = s.int64(0);
        m.cpu = s.real(1);
        m.memUsed = static_cast<std::int64_t>(s.real(2));
        m.memTotal = s.int64(3);
        m.swapUsed = static_cast<std::int64_t>(s.real(4));
        m.swapTotal = s.int64(5);
        m.diskUsed = static_cast<std::int64_t>(s.real(6));
        m.diskTotal = s.int64(7);
        m.netRx = s.real(8);
        m.netTx = s.real(9);
        m.load1 = s.real(10);
        out.push_back(m);
    }
    return out;
}

void purgeMetrics(Database& db, std::int64_t before) {
    Statement s(db, "DELETE FROM metrics WHERE ts < ?");
    s.bind(1, before).run();
}

std::vector<OpenAlert> openAlerts(Database& db) {
    std::vector<OpenAlert> out;
    Statement s(db, "SELECT id, node_id, rule, message, started_at FROM alerts "
                    "WHERE resolved_at IS NULL ORDER BY started_at");
    while (s.step()) {
        OpenAlert a;
        a.id = s.int64(0);
        if (!s.isNull(1))
            a.nodeId = s.int64(1);
        a.rule = s.text(2);
        a.message = s.text(3);
        a.startedAt = s.int64(4);
        out.push_back(a);
    }
    return out;
}

std::int64_t openAlert(Database& db, std::optional<std::int64_t> nodeId, const std::string& rule,
                       const std::string& message, std::int64_t now) {
    Statement s(db, "INSERT INTO alerts (node_id, rule, message, started_at) VALUES (?, ?, ?, ?)");
    s.bind(1, nodeId).bind(2, rule).bind(3, message).bind(4, now).run();
    return db.lastInsertId();
}

void resolveAlert(Database& db, std::int64_t id, std::int64_t now) {
    Statement s(db, "UPDATE alerts SET resolved_at = ? WHERE id = ?");
    s.bind(1, now).bind(2, id).run();
}

} // namespace douve
