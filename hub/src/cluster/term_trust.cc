#include "cluster/term_trust.h"

#include "store/access.h"
#include "store/passkeys.h"
#include "util/crypto.h"
#include "util/encoding.h"
#include "util/json.h"
#include "webauthn/cose.h"

#include <algorithm>

namespace douve {

namespace {

constexpr const char* kOpenPrefix = "douve-terminal-open:v1\n";
constexpr const char* kTrustPrefix = "douve-terminal-trust:v1\n";
constexpr const char* kActionPrefix = "douve-server-action:v1\n";

std::string compact(const Json::Value& v) {
    Json::StreamWriterBuilder w;
    w["indentation"] = "";
    w["emitUTF8"] = true;
    return Json::writeString(w, v);
}

// COSE 키 → 신뢰 목록의 키 항목. Agent(termauth)가 받지 않는 키면 nullopt.
std::optional<Json::Value> keyEntry(const Passkey& p) {
    std::string err;
    std::size_t used = 0;
    auto k = webauthn::parseCoseKey(p.publicKeyCose.data(), p.publicKeyCose.size(), &used, err);
    if (!k)
        return std::nullopt;
    Json::Value v;
    v["id"] = base64UrlEncode(p.credentialId);
    v["alg"] = k->alg;
    if (k->alg == webauthn::kAlgES256 && k->x.size() == 32 && k->y.size() == 32) {
        v["x"] = base64UrlEncode(k->x);
        v["y"] = base64UrlEncode(k->y);
    } else if (k->alg == webauthn::kAlgEdDSA && k->x.size() == 32) {
        v["x"] = base64UrlEncode(k->x);
    } else if (k->alg == webauthn::kAlgRS256 && k->n.size() >= 256 && k->n.size() <= 1024 &&
               !k->e.empty() && k->e.size() <= 4) {
        v["n"] = base64UrlEncode(k->n);
        v["e"] = base64UrlEncode(k->e);
    } else {
        return std::nullopt;
    }
    return v;
}

TrustRecord row(Statement& q) {
    TrustRecord r;
    r.version = q.int64(0);
    r.snapshot = q.text(1);
    r.sig = q.text(2);
    if (!q.isNull(3))
        r.signerId = q.int64(3);
    r.createdAt = q.int64(4);
    return r;
}

} // namespace

std::string termOpenStatement(std::int64_t nodeId, const std::string& user, std::int64_t ts,
                              const std::string& nonce) {
    return std::string(kOpenPrefix) + std::to_string(nodeId) + "\n" + user + "\n" +
           std::to_string(ts) + "\n" + nonce;
}

Bytes termOpenChallenge(std::int64_t nodeId, const std::string& user, std::int64_t ts,
                        const std::string& nonce) {
    return sha256(termOpenStatement(nodeId, user, ts, nonce));
}

std::string serverActionStatement(std::int64_t nodeId, const std::string& action, std::int64_t ts,
                                  const std::string& nonce) {
    return std::string(kActionPrefix) + std::to_string(nodeId) + "\n" + action + "\n" +
           std::to_string(ts) + "\n" + nonce;
}

Bytes termTrustChallenge(const std::string& snapshot) {
    return sha256(std::string(kTrustPrefix) + snapshot);
}

std::string buildTrustSnapshot(Database& db, const std::string& origin, const std::string& rpId,
                               const std::vector<std::string>& alwaysAdmin, std::int64_t version) {
    auto guard = db.lock();
    Json::Value t;
    t["v"] = 1;
    t["version"] = Json::Int64(version);
    t["origin"] = origin;
    t["rp_id"] = rpId;
    t["keys"] = Json::Value(Json::arrayValue);
    for (const auto& u : listUsers(db)) {
        const bool admin = u.access.admin() || std::find(alwaysAdmin.begin(), alwaysAdmin.end(),
                                                         u.email) != alwaysAdmin.end();
        if (!admin && u.access.role != Role::Operator)
            continue;
        if (!admin && u.access.nodes.empty())
            continue;
        for (const auto& p : listPasskeys(db, u.id)) {
            auto k = keyEntry(p);
            if (!k)
                continue;
            (*k)["user"] = u.email;
            if (admin) {
                (*k)["admin"] = true;
            } else {
                for (auto n : u.access.nodes) // std::set이라 정렬됨
                    (*k)["nodes"].append(Json::Int64(n));
            }
            t["keys"].append(*k);
        }
    }
    return compact(t);
}

std::optional<TrustRecord> latestTrust(Database& db) {
    auto guard = db.lock();
    Statement q(db, "SELECT version, snapshot, sig, signer_id, created_at FROM term_trust "
                    "ORDER BY version DESC LIMIT 1");
    if (!q.step())
        return std::nullopt;
    return row(q);
}

std::vector<TrustRecord> trustRecords(Database& db, std::size_t limit) {
    auto guard = db.lock();
    Statement q(db, "SELECT version, snapshot, sig, signer_id, created_at FROM term_trust "
                    "ORDER BY version DESC LIMIT ?");
    q.bind(1, static_cast<std::int64_t>(limit));
    std::vector<TrustRecord> out;
    while (q.step())
        out.push_back(row(q));
    std::reverse(out.begin(), out.end());
    return out;
}

bool insertTrust(Database& db, const TrustRecord& r) {
    auto guard = db.lock();
    Statement exists(db, "SELECT 1 FROM term_trust WHERE version = ?");
    exists.bind(1, r.version);
    if (exists.step())
        return false;
    Statement(db, "INSERT INTO term_trust (version, snapshot, sig, signer_id, created_at) VALUES "
                  "(?, ?, ?, ?, ?)")
        .bind(1, r.version)
        .bind(2, r.snapshot)
        .bind(3, r.sig)
        .bind(4, r.signerId)
        .bind(5, r.createdAt)
        .run();
    return true;
}

std::set<std::string> trustKeyIds(const std::string& snapshot, bool adminOnly,
                                  std::optional<std::int64_t> nodeId) {
    std::set<std::string> out;
    Json::Value t;
    if (!parseJson(snapshot, t) || !t["keys"].isArray())
        return out;
    for (const auto& k : t["keys"]) {
        const bool admin = k.get("admin", false).asBool();
        if (adminOnly && !admin)
            continue;
        if (nodeId && !admin) {
            bool found = false;
            for (const auto& n : k["nodes"])
                found = found || n.asInt64() == *nodeId;
            if (!found)
                continue;
        }
        out.insert(k.get("id", "").asString());
    }
    return out;
}

bool sameTrustContent(const std::string& a, const std::string& b) {
    Json::Value x, y;
    if (!parseJson(a, x) || !parseJson(b, y))
        return false;
    x.removeMember("version");
    y.removeMember("version");
    return x == y;
}

Json::Value trustMessage(const std::vector<TrustRecord>& records) {
    Json::Value m;
    m["type"] = "term_trust";
    m["records"] = Json::Value(Json::arrayValue);
    for (const auto& r : records) {
        Json::Value v;
        v["snapshot"] = r.snapshot;
        Json::Value sig;
        if (!r.sig.empty() && parseJson(r.sig, sig))
            v["sig"] = sig;
        m["records"].append(v);
    }
    return m;
}

} // namespace douve
