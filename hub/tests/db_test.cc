#include "store/db.h"
#include "testing.h"

#include <cstdio>
#include <unistd.h>

using namespace douve;

TEST(db_migrates_to_latest) {
    Database db(":memory:");
    CHECK_EQ(db.schemaVersion(), 20);
    // 테이블이 실제로 생겼는지
    Statement s(db, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN "
                    "('users','passkeys','sessions','pending','audit_log','nodes','join_tokens',"
                    "'metrics','alerts','services','invites','settings','security_events',"
                    "'security_issues','links')");
    CHECK(s.step() && s.int64(0) == 15);
}

TEST(db_roundtrip_types) {
    Database db(":memory:");
    db.exec("CREATE TABLE t (i INTEGER, s TEXT, b BLOB, n TEXT)");
    Bytes blob{0, 1, 2, 255};
    Statement ins(db, "INSERT INTO t VALUES (?, ?, ?, ?)");
    ins.bind(1, std::int64_t{1} << 40).bind(2, std::string("한글")).bind(3, blob).bindNull(4).run();
    Statement q(db, "SELECT i, s, b, n FROM t");
    CHECK(q.step());
    CHECK_EQ(q.int64(0), std::int64_t{1} << 40);
    CHECK_EQ(q.text(1), "한글");
    CHECK(q.blob(2) == blob);
    CHECK(q.isNull(3));
    CHECK(!q.step());
}

TEST(db_transaction_rollback) {
    Database db(":memory:");
    db.exec("CREATE TABLE t (x INTEGER)");
    {
        Transaction tx(db);
        db.exec("INSERT INTO t VALUES (1)");
        // commit 없이 범위 종료 → 롤백
    }
    {
        Transaction tx(db);
        db.exec("INSERT INTO t VALUES (2)");
        tx.commit();
    }
    Statement q(db, "SELECT group_concat(x) FROM t");
    CHECK(q.step() && q.text(0) == "2");
}

TEST(db_foreign_keys_enforced) {
    Database db(":memory:");
    bool threw = false;
    try {
        db.exec("INSERT INTO passkeys (user_id, credential_id, public_key_cose, name, created_at) "
                "VALUES (999, x'01', x'02', 'k', 0)");
    } catch (const DbError&) {
        threw = true;
    }
    CHECK(threw);
}

TEST(db_file_reopen_keeps_version) {
    char path[] = "/tmp/douve-db-test-XXXXXX";
    int fd = mkstemp(path);
    close(fd);
    {
        Database db(path);
        db.exec("INSERT INTO users (email, created_at) VALUES ('a@b.c', 1)");
    }
    {
        Database db(path);
        CHECK_EQ(db.schemaVersion(), 20);
        Statement q(db, "SELECT email FROM users");
        CHECK(q.step() && q.text(0) == "a@b.c");
    }
    std::remove(path);
    std::remove((std::string(path) + "-wal").c_str());
    std::remove((std::string(path) + "-shm").c_str());
}

#include "store/passkeys.h"
#include "store/repo.h"

TEST(passkey_store_ownership) {
    Database db(":memory:");
    auto a = findOrCreateUser(db, "a@x", 0), b = findOrCreateUser(db, "b@x", 0);
    Passkey p;
    p.userId = a.id;
    p.credentialId = {1, 2, 3};
    p.publicKeyCose = {9};
    p.name = "맥북";
    p.createdAt = 1;
    auto id = insertPasskey(db, p);
    CHECK(id.has_value());
    // 같은 credentialId를 다른 사용자에게 등록 시도 → 거부
    p.userId = b.id;
    CHECK(!insertPasskey(db, p));
    CHECK_EQ(findPasskeyByCredentialId(db, {1, 2, 3})->userId, a.id);
    // 다른 사용자는 삭제·이름변경 불가
    CHECK(!deletePasskey(db, b.id, *id));
    CHECK(!renamePasskey(db, b.id, *id, "x"));
    CHECK(renamePasskey(db, a.id, *id, "아이폰"));
    updatePasskeyUse(db, *id, 7, 100);
    auto list = listPasskeys(db, a.id);
    CHECK(list.size() == 1 && list[0].name == "아이폰" && list[0].signCount == 7 &&
          list[0].lastUsedAt == 100);
    CHECK_EQ(countPasskeys(db, a.id), 1);
    CHECK(deletePasskey(db, a.id, *id));
    CHECK_EQ(countPasskeys(db, a.id), 0);
}
