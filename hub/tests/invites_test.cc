#include "store/invites.h"
#include "store/repo.h"
#include "testing.h"

using namespace douve;

TEST(invite_single_use_and_expiry) {
    Database db(":memory:");
    auto inv = createInvite(db, "Me@Example.com", std::nullopt, 3600, 1000);
    CHECK_EQ(inv.email, "me@example.com");
    CHECK(peekInvite(db, inv.token, 1500).value_or("") == "me@example.com");
    CHECK(!peekInvite(db, inv.token, 4601).has_value()); // 만료
    CHECK(!peekInvite(db, "short", 1500).has_value());
    CHECK(consumeInvite(db, inv.token, 1500));
    CHECK(!consumeInvite(db, inv.token, 1501)); // 재사용 불가
    CHECK(!peekInvite(db, inv.token, 1502).has_value());
    auto inv2 = createInvite(db, "x@example.com", std::nullopt, 10, 1000);
    CHECK(!consumeInvite(db, inv2.token, 2000)); // 만료 후 소모 불가
    // DB에는 평문 토큰이 없다
    Statement s(db, "SELECT count(*) FROM invites WHERE token_hash = ?");
    s.bind(1, Bytes(inv.token.begin(), inv.token.end()));
    CHECK(s.step() && s.int64(0) == 0);
}

TEST(invited_user_allowed_flag) {
    Database db(":memory:");
    auto u = findOrCreateUser(db, "a@example.com", 1);
    CHECK(!userAllowed(db, "a@example.com"));
    setUserAllowed(db, u.id, true);
    CHECK(userAllowed(db, "a@example.com"));
    CHECK(!userAllowed(db, "nobody@example.com"));
}

TEST(settings_upsert) {
    Database db(":memory:");
    CHECK(!getSetting(db, "k").has_value());
    putSetting(db, "k", "v1", 1);
    putSetting(db, "k", "v2", 2);
    CHECK_EQ(getSetting(db, "k").value_or(""), "v2");
    deleteSetting(db, "k");
    CHECK(!getSetting(db, "k").has_value());
}

#include "settings.h"

TEST(runtime_settings_db_overrides_config) {
    Database db(":memory:");
    HubConfig cfg;
    cfg.telegramBotToken = "111:from-config";
    cfg.telegramChatId = "1";
    RuntimeSettings rs;
    rs.load(cfg, db);
    CHECK_EQ(rs.get().telegramBotToken, "111:from-config");
    Credentials c = rs.get();
    c.telegramChatId = "999";
    c.googleClientId = "1-abc.apps.googleusercontent.com";
    rs.save(db, cfg, c, 10);
    CHECK_EQ(rs.get().telegramChatId, "999");
    CHECK(!rs.get().googleEnabled()); // 비밀 없음
    RuntimeSettings again;            // 재시작해도 DB 값 유지
    again.load(cfg, db);
    CHECK_EQ(again.get().telegramChatId, "999");
    c.telegramChatId.clear(); // 비우면 설정 파일 값으로
    again.save(db, cfg, c, 11);
    CHECK_EQ(again.get().telegramChatId, "1");
}

TEST(settings_validation) {
    CHECK(validateTelegram("", "").empty());
    CHECK(validateTelegram("123456789:AAAbbbCCCdddEEEfffGGGhhhIIIjjjKKK", "-1001234").empty());
    CHECK(validateTelegram("123456789:AAAbbbCCCdddEEEfffGGGhhhIIIjjjKKK", "@my_channel").empty());
    CHECK(!validateTelegram("not-a-token", "").empty());
    CHECK(!validateTelegram("", "12a").empty());
    CHECK(validateGoogle("464975595115-ti2kh9gb.apps.googleusercontent.com", "GOCSPX-x").empty());
    CHECK(!validateGoogle("evil.example.com", "").empty());
    CHECK(!validateGoogle("", "has space").empty());
}
