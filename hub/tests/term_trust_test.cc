#include "cluster/term_trust.h"
#include "soft_authenticator.h"
#include "store/access.h"
#include "store/db.h"
#include "store/passkeys.h"
#include "testing.h"
#include "util/json.h"

using namespace douve;
using douve::testing::KeyType;
using douve::testing::SoftAuthenticator;

namespace {

void addKey(Database& db, std::int64_t userId, const SoftAuthenticator& a,
            const std::string& name) {
    Passkey p;
    p.userId = userId;
    p.credentialId = a.credentialId;
    p.publicKeyCose = a.coseKey();
    p.name = name;
    CHECK(insertPasskey(db, p).has_value());
}

} // namespace

TEST(term_trust_statements) {
    // agent/internal/termauth와 같은 문장이어야 한다
    CHECK_EQ(termOpenStatement(3, "ubuntu", 1700000000, "nonce-1"),
             std::string("douve-terminal-open:v1\n3\nubuntu\n1700000000\nnonce-1"));
    CHECK(termOpenChallenge(3, "ubuntu", 1, "n") ==
          sha256("douve-terminal-open:v1\n3\nubuntu\n1\nn"));
    CHECK(termTrustChallenge("{}") == sha256("douve-terminal-trust:v1\n{}"));
    CHECK_EQ(serverActionStatement(3, "fix:ssh_password", 1700000000, "n1"),
             std::string("douve-server-action:v1\n3\nfix:ssh_password\n1700000000\nn1"));
}

TEST(term_trust_snapshot) {
    Database db(":memory:");
    db.exec("INSERT INTO users (id, email, created_at, role) VALUES (1, 'admin@x', 0, 'admin')");
    db.exec("INSERT INTO users (id, email, created_at, role) VALUES (2, 'op@x', 0, 'operator')");
    db.exec("INSERT INTO users (id, email, created_at, role) VALUES (3, 'app@x', 0, 'app')");
    db.exec("INSERT INTO users (id, email, created_at, role) VALUES (4, 'root@x', 0, 'app')");
    db.exec("INSERT INTO users (id, email, created_at, role) VALUES (5, 'op2@x', 0, 'operator')");
    setAccess(db, 2, Role::Operator, {7, 3}, {});
    setAccess(db, 5, Role::Operator, {}, {}); // 허락된 서버 없음 → 빠짐
    SoftAuthenticator es(KeyType::ES256), ed(KeyType::EdDSA), rs(KeyType::RS256),
        app(KeyType::ES256), root(KeyType::ES256), op2(KeyType::ES256);
    addKey(db, 1, es, "맥북");
    addKey(db, 1, rs, "윈도우");
    addKey(db, 2, ed, "운영자 키");
    addKey(db, 3, app, "앱 사용자 키");
    addKey(db, 4, root, "allowed_emails");
    addKey(db, 5, op2, "서버 없음");

    const auto snap =
        buildTrustSnapshot(db, "https://douve.example.com", "example.com", {"root@x"}, 4);
    Json::Value t;
    CHECK(parseJson(snap, t));
    CHECK_EQ(t["v"].asInt(), 1);
    CHECK_EQ(t["version"].asInt64(), 4);
    CHECK_EQ(t["origin"].asString(), std::string("https://douve.example.com"));
    CHECK_EQ(t["rp_id"].asString(), std::string("example.com"));
    CHECK_EQ(t["keys"].size(), 4u); // admin 2개 + 운영자 1개 + allowed_emails 1개
    std::map<std::string, Json::Value> byUser;
    for (const auto& k : t["keys"])
        byUser[k["user"].asString() + ":" + std::to_string(k["alg"].asInt())] = k;
    auto esk = byUser["admin@x:-7"];
    CHECK(esk["admin"].asBool() && !esk.isMember("nodes"));
    CHECK_EQ(base64UrlDecode(esk["x"].asString())->size(), 32u);
    CHECK_EQ(base64UrlDecode(esk["y"].asString())->size(), 32u);
    CHECK(byUser["admin@x:-257"].isMember("n") && byUser["admin@x:-257"].isMember("e"));
    auto edk = byUser["op@x:-8"];
    CHECK(!edk.isMember("admin"));
    CHECK_EQ(edk["nodes"].size(), 2u);
    CHECK_EQ(edk["nodes"][0].asInt64(), 3); // 정렬됨
    CHECK_EQ(edk["nodes"][1].asInt64(), 7);
    CHECK(byUser["root@x:-7"]["admin"].asBool()); // hub.json allowed_emails는 항상 관리자

    // 서버별·관리자 키
    CHECK_EQ(trustKeyIds(snap, true).size(), 3u);
    CHECK(trustKeyIds(snap, false, 7).contains(base64UrlEncode(ed.credentialId)));
    CHECK(!trustKeyIds(snap, false, 8).contains(base64UrlEncode(ed.credentialId)));
    CHECK(trustKeyIds(snap, false, 8).contains(base64UrlEncode(es.credentialId)));
    CHECK(!trustKeyIds(snap, false).contains(base64UrlEncode(app.credentialId)));

    // 같은 내용이면 버전만 달라도 같다, 같은 입력이면 같은 문자열 (승인 대기 판단)
    const auto again =
        buildTrustSnapshot(db, "https://douve.example.com", "example.com", {"root@x"}, 9);
    CHECK(sameTrustContent(snap, again) && snap != again);
    CHECK_EQ(snap,
             buildTrustSnapshot(db, "https://douve.example.com", "example.com", {"root@x"}, 4));
    setAccess(db, 2, Role::Operator, {7}, {});
    CHECK(!sameTrustContent(
        snap, buildTrustSnapshot(db, "https://douve.example.com", "example.com", {"root@x"}, 4)));
}

TEST(term_trust_store) {
    Database db(":memory:");
    CHECK(!latestTrust(db));
    CHECK(insertTrust(db, {1, "{\"a\":1}", "", std::nullopt, 10}));
    CHECK(insertTrust(db, {2, "{\"a\":2}", "{\"id\":\"x\"}", 1, 20}));
    CHECK(!insertTrust(db, {2, "{\"a\":3}", "", std::nullopt, 30})); // 같은 버전
    CHECK_EQ(latestTrust(db)->version, 2);
    auto all = trustRecords(db);
    CHECK_EQ(all.size(), 2u);
    CHECK_EQ(all[0].version, 1); // 오래된 판부터
    auto m = trustMessage(all);
    CHECK_EQ(m["type"].asString(), std::string("term_trust"));
    CHECK(!m["records"][0].isMember("sig")); // 첫 판은 서명 없음
    CHECK_EQ(m["records"][1]["sig"]["id"].asString(), std::string("x"));
    CHECK_EQ(trustRecords(db, 1).size(), 1u);
    CHECK_EQ(trustRecords(db, 1)[0].version, 2);
}
