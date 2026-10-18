#include "store/devnet.h"

#include "util/encoding.h"
#include "util/json.h"

#include <openssl/evp.h>

#include <array>
#include <set>
#include <stdexcept>

namespace douve {

namespace {

// WireGuard는 표준 base64(패딩 포함)를 쓴다
std::string stdB64(const Bytes& b) {
    std::string s = base64UrlEncode(b);
    for (auto& c : s)
        c = c == '-' ? '+' : c == '_' ? '/' : c;
    while (s.size() % 4)
        s += '=';
    return s;
}

std::optional<Bytes> fromStdB64(std::string s) {
    if (s.size() != 44 || s.back() != '=')
        return std::nullopt;
    while (!s.empty() && s.back() == '=')
        s.pop_back();
    for (auto& c : s) {
        if (c == '-' || c == '_')
            return std::nullopt;
        c = c == '+' ? '-' : c == '/' ? '_' : c;
    }
    return base64UrlDecode(s);
}

Device row(Statement& q) {
    Device d;
    d.id = q.int64(0);
    d.userId = q.int64(1);
    d.name = q.text(2);
    d.pubkey = q.text(3);
    d.ip = q.text(4);
    d.createdAt = q.int64(5);
    return d;
}

constexpr const char* kCols = "id, user_id, name, pubkey, ip, created_at";

// 이름: 앞뒤 공백 제거, 제어 문자 없이 1~40바이트
std::string cleanName(const std::string& raw) {
    std::size_t a = raw.find_first_not_of(" \t"), b = raw.find_last_not_of(" \t");
    if (a == std::string::npos)
        return "";
    std::string s = raw.substr(a, b - a + 1);
    for (unsigned char c : s)
        if (c < 0x20 || c == 0x7f || c == '<' || c == '>')
            return "";
    return s.size() > 40 ? "" : s;
}

} // namespace

DevnetSettings loadDevnet(Database& db) {
    auto guard = db.lock();
    DevnetSettings s;
    Statement q(db, "SELECT value FROM settings WHERE key = 'devnet'");
    Json::Value v;
    if (q.step() && parseJson(q.text(0), v) && v.isObject()) {
        s.enabled = v.get("enabled", false).asBool();
        s.port = v.get("port", 51821).asInt();
        s.endpoint = v.get("endpoint", "").asString();
        s.gatewayKey = v.get("gateway_key", "").asString();
        s.gatewayNode = v.get("gateway_node", 0).asInt64();
    }
    return s;
}

void saveDevnet(Database& db, const DevnetSettings& s, std::int64_t now) {
    Json::Value v;
    v["enabled"] = s.enabled;
    v["port"] = s.port;
    v["endpoint"] = s.endpoint;
    v["gateway_key"] = s.gatewayKey;
    v["gateway_node"] = Json::Int64(s.gatewayNode);
    Json::StreamWriterBuilder w;
    w["indentation"] = "";
    auto guard = db.lock();
    Statement(db, "INSERT INTO settings (key, value, updated_at) VALUES ('devnet', ?, ?) "
                  "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = "
                  "excluded.updated_at")
        .bind(1, Json::writeString(w, v))
        .bind(2, now)
        .run();
}

std::string validateDevnet(const DevnetSettings& s) {
    if (s.port < 1024 || s.port > 65535)
        return "UDP 포트는 1024~65535";
    if (s.endpoint.size() > 253)
        return "접속 주소가 너무 깁니다";
    for (unsigned char c : s.endpoint)
        if (!(std::isalnum(c) || c == '.' || c == '-' || c == ':' || c == '[' || c == ']'))
            return "접속 주소는 도메인이나 IP만 (포트 없이)";
    return "";
}

std::vector<Device> listDevices(Database& db) {
    auto guard = db.lock();
    Statement q(db, std::string("SELECT ") + kCols + " FROM devices ORDER BY id");
    std::vector<Device> out;
    while (q.step())
        out.push_back(row(q));
    return out;
}

std::vector<Device> listDevicesOf(Database& db, std::int64_t userId) {
    auto guard = db.lock();
    Statement q(db, std::string("SELECT ") + kCols + " FROM devices WHERE user_id = ? ORDER BY id");
    q.bind(1, userId);
    std::vector<Device> out;
    while (q.step())
        out.push_back(row(q));
    return out;
}

std::optional<Device> findDevice(Database& db, std::int64_t id) {
    auto guard = db.lock();
    Statement q(db, std::string("SELECT ") + kCols + " FROM devices WHERE id = ?");
    q.bind(1, id);
    if (!q.step())
        return std::nullopt;
    return row(q);
}

std::optional<Device> createDevice(Database& db, std::int64_t userId, const std::string& name,
                                   const std::string& pubkey, std::int64_t now,
                                   std::string& error) {
    Device d;
    d.name = cleanName(name);
    if (d.name.empty()) {
        error = "기기 이름이 필요합니다 (40바이트까지)";
        return std::nullopt;
    }
    if (!validWgKey(pubkey)) {
        error = "잘못된 키";
        return std::nullopt;
    }
    Transaction tx(db);
    std::set<std::string> used;
    {
        Statement q(db, "SELECT ip FROM devices");
        while (q.step())
            used.insert(q.text(0));
    }
    for (int i = 2; i <= 254 && d.ip.empty(); ++i) {
        const std::string ip = "10.201.0." + std::to_string(i);
        if (!used.contains(ip))
            d.ip = ip;
    }
    if (d.ip.empty()) {
        error = "기기 주소가 모두 찼습니다 (253대)";
        return std::nullopt;
    }
    Statement exists(db, "SELECT 1 FROM devices WHERE pubkey = ?");
    exists.bind(1, pubkey);
    if (exists.step()) {
        error = "이미 등록된 키입니다";
        return std::nullopt;
    }
    Statement(db,
              "INSERT INTO devices (user_id, name, pubkey, ip, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(1, userId)
        .bind(2, d.name)
        .bind(3, pubkey)
        .bind(4, d.ip)
        .bind(5, now)
        .run();
    d.id = db.lastInsertId();
    d.userId = userId;
    d.pubkey = pubkey;
    d.createdAt = now;
    tx.commit();
    return d;
}

bool deleteDevice(Database& db, std::int64_t id) {
    auto guard = db.lock();
    Statement(db, "DELETE FROM devices WHERE id = ?").bind(1, id).run();
    return db.changes() > 0;
}

bool validWgKey(const std::string& b64) {
    auto k = fromStdB64(b64);
    return k && k->size() == 32;
}

WgKeyPair generateWgKeyPair() {
    EVP_PKEY* key = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
    if (!key)
        throw std::runtime_error("X25519 키 생성 실패");
    Bytes priv(32), pub(32);
    std::size_t pl = 32, ul = 32;
    const bool ok = EVP_PKEY_get_raw_private_key(key, priv.data(), &pl) == 1 &&
                    EVP_PKEY_get_raw_public_key(key, pub.data(), &ul) == 1 && pl == 32 && ul == 32;
    EVP_PKEY_free(key);
    if (!ok)
        throw std::runtime_error("X25519 키 꺼내기 실패");
    return {stdB64(priv), stdB64(pub)};
}

std::string deviceConfig(const DevnetSettings& s, const std::string& endpointHost,
                         const std::string& privateKey, const std::string& ip) {
    std::string host = s.endpoint.empty() ? endpointHost : s.endpoint;
    if (host.find(':') != std::string::npos && host.front() != '[')
        host = "[" + host + "]"; // IPv6
    return "[Interface]\n"
           "PrivateKey = " +
           privateKey + "\nAddress = " + ip + "/32\nDNS = " + kDevnetAddress +
           "\n\n[Peer]\n"
           "PublicKey = " +
           s.gatewayKey + "\nEndpoint = " + host + ":" + std::to_string(s.port) +
           "\nAllowedIPs = " + kDevnetSubnet + "\nPersistentKeepalive = 25\n";
}

} // namespace douve
