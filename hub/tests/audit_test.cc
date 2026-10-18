// 감사 기록 해시 체인: 고치거나 중간을 지우면 확인에서 걸리고, 내보낸 묶음으로 밖에서도 검증된다.
#include "cluster/channels.h"
#include "store/db.h"
#include "store/repo.h"
#include "testing.h"
#include "util/crypto.h"
#include "util/encoding.h"
#include "util/json.h"

#include <cstdio>
#include <unistd.h>

using namespace douve;

namespace {
Bytes unhex(const std::string& h) {
    Bytes out;
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<std::uint8_t>(std::stoi(h.substr(i, 2), nullptr, 16)));
    return out;
}
void write3(Database& db) {
    audit(db, 1, "login", "1.2.3.4", "passkey", 100);
    audit(db, std::nullopt, "node_joined", "cli", "web1", 101);
    audit(db, 1, "terminal_opened", "1.2.3.4", "web1 root", 102);
}
} // namespace

TEST(audit_chain_verifies) {
    Database db(":memory:");
    CHECK(verifyAuditChain(db).ok); // 빈 기록
    write3(db);
    auto c = verifyAuditChain(db);
    CHECK(c.ok);
    CHECK_EQ(c.rows, 3);
    auto rows = auditRowsAfter(db, 0, 10);
    CHECK_EQ(rows.size(), std::size_t{3});
    CHECK(c.head == rows[2].hash);
    // 첫 행은 32바이트 0에서 시작, 각 행은 앞 행에 이어진다
    CHECK(rows[0].hash == auditHash(Bytes(32, 0), rows[0]));
    CHECK(rows[2].hash == auditHash(rows[1].hash, rows[2]));
    CHECK(auditHashAt(db, 0) == Bytes(32, 0));
    CHECK(auditHashAt(db, rows[1].id) == rows[1].hash);
    // 필드 경계: "a"+"bc" 와 "ab"+"c" 는 다른 해시
    AuditRow x = rows[0], y = rows[0];
    x.event = "a", x.ip = "bc";
    y.event = "ab", y.ip = "c";
    CHECK(auditHash(Bytes(32, 0), x) != auditHash(Bytes(32, 0), y));
}

TEST(audit_chain_detects_tampering) {
    {
        Database db(":memory:");
        write3(db);
        db.exec("UPDATE audit_log SET detail = 'web2 root' WHERE id = 3");
        auto c = verifyAuditChain(db);
        CHECK(!c.ok);
        CHECK_EQ(c.brokenAt, 3);
    }
    {
        Database db(":memory:");
        write3(db);
        db.exec("DELETE FROM audit_log WHERE id = 2"); // 중간 삭제 → 다음 행에서 끊김
        auto c = verifyAuditChain(db);
        CHECK(!c.ok);
        CHECK_EQ(c.brokenAt, 3);
    }
    {
        Database db(":memory:");
        write3(db);
        // 해시까지 다시 계산해 넣어도 다음 행이 끊긴다
        db.exec("UPDATE audit_log SET event = 'x' WHERE id = 2");
        auto rows = auditRowsAfter(db, 0, 10);
        Statement(db, "UPDATE audit_log SET hash = ? WHERE id = 2")
            .bind(1, auditHash(rows[0].hash, rows[1]))
            .run();
        auto c = verifyAuditChain(db);
        CHECK(!c.ok);
        CHECK_EQ(c.brokenAt, 3);
    }
    {
        Database db(":memory:");
        write3(db);
        db.exec("UPDATE audit_log SET hash = NULL WHERE id = 1");
        CHECK_EQ(verifyAuditChain(db).brokenAt, 1);
    }
}

TEST(audit_chain_seals_old_rows) {
    Database db(":memory:");
    // 체인 도입 전에 쓴 행 (hash 없음)
    for (int i = 0; i < 3; ++i)
        Statement(db, "INSERT INTO audit_log (ts, user_id, event, ip, detail) VALUES (?, NULL, "
                      "'old', '', '')")
            .bind(1, std::int64_t{50 + i})
            .run();
    CHECK(!verifyAuditChain(db).ok);
    sealAuditLog(db);
    CHECK(verifyAuditChain(db).ok);
    // 봉인 전 행이 남아 있어도 새 기록이 알아서 채운다
    Statement(db, "INSERT INTO audit_log (ts, event, ip, detail) VALUES (60, 'old', '', '')").run();
    audit(db, 1, "login", "", "", 61);
    auto c = verifyAuditChain(db);
    CHECK(c.ok);
    CHECK_EQ(c.rows, 5);
}

TEST(audit_chain_inside_transaction) {
    Database db(":memory:");
    {
        Transaction tx(db);
        audit(db, 1, "a", "", "", 1);
        audit(db, 1, "b", "", "", 2);
        tx.commit();
    }
    {
        Transaction tx(db); // 되돌리면 기록도 없어지고 체인은 그대로
        audit(db, 1, "c", "", "", 3);
    }
    auto c = verifyAuditChain(db);
    CHECK(c.ok);
    CHECK_EQ(c.rows, 2);
}

TEST(audit_chain_two_processes) {
    // Hub와 root CLI가 같은 파일에 번갈아 쓴다
    char path[] = "/tmp/douve-audit-XXXXXX";
    int fd = mkstemp(path);
    close(fd);
    std::remove(path);
    {
        Database a(path), b(path);
        for (int i = 0; i < 20; ++i)
            audit(i % 3 ? a : b, std::nullopt, "e", "", std::to_string(i), i);
        auto c = verifyAuditChain(a);
        CHECK(c.ok);
        CHECK_EQ(c.rows, 20);
    }
    for (const char* sfx : {"", "-wal", "-shm"})
        std::remove((std::string(path) + sfx).c_str());
}

TEST(audit_export_request) {
    Database db(":memory:");
    write3(db);
    Channel c;
    c.kind = "webhook";
    c.config = Json::Value(Json::objectValue);
    c.config["url"] = "https://logs.example.com/in";
    c.config["audit"] = true;
    CHECK(!validateChannel(c).empty()); // 서명 비밀값 없이는 안 됨
    c.config["secret"] = "s3cret";
    CHECK(validateChannel(c).empty());
    CHECK(sendsAudit(c));
    CHECK(channelJson(c)["audit"].asBool());
    c.enabled = false;
    CHECK(!sendsAudit(c));
    c.enabled = true;

    // 두 번째 묶음: 받는 쪽이 prev_hash부터 이어 계산해 확인할 수 있어야 한다
    auto rows = auditRowsAfter(db, 1, 10);
    auto req = auditRequest(c, rows, auditHashAt(db, 1), 1000);
    Json::Value b;
    CHECK(parseJson(req.body, b));
    CHECK_EQ(b["type"].asString(), "audit");
    CHECK_EQ(b["records"].size(), 2u);
    Bytes prev = unhex(b["prev_hash"].asString());
    CHECK(prev == auditHashAt(db, 1));
    for (const auto& r : b["records"]) {
        AuditRow x;
        x.id = r["id"].asInt64();
        x.ts = r["ts"].asInt64();
        if (!r["user_id"].isNull())
            x.userId = r["user_id"].asInt64();
        x.event = r["event"].asString();
        x.ip = r["ip"].asString();
        x.detail = r["detail"].asString();
        prev = auditHash(prev, x);
        CHECK_EQ(toHex(prev), r["hash"].asString());
    }
    bool signedOk = false;
    for (const auto& [k, v] : req.headers)
        if (k == "X-Douve-Signature")
            signedOk = v == "sha256=" + toHex(hmacSha256("s3cret", "1000." + req.body));
    CHECK(signedOk);
}
