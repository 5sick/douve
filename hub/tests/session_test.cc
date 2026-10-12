#include "auth/redirect.h"
#include "auth/session.h"
#include "store/repo.h"
#include "testing.h"

using namespace douve;

namespace {
constexpr std::int64_t kDay = 86400;

HubConfig testConfig() {
    std::string err;
    return *parseConfig(
        R"({"public_url":"https://douve.example.com","cookie_domain":"example.com",
                            "session_idle_days":30,"session_max_days":90})",
        err);
}
} // namespace

TEST(session_create_validate_revoke) {
    Database db(":memory:");
    auto cfg = testConfig();
    SessionManager sm(db, cfg);
    auto u = findOrCreateUser(db, "a@b.c", 1000);
    auto tok = sm.create(u.id, "passkey", "1.2.3.4", "UA", 1000);
    auto s = sm.validate(tok, 1001);
    CHECK(s && s->userId == u.id && s->email == "a@b.c" && s->authMethod == "passkey");
    CHECK(!sm.validate(tok + "x", 1001));
    CHECK(!sm.validate("short", 1001));
    sm.revoke(tok);
    CHECK(!sm.validate(tok, 1002));
}

TEST(session_db_stores_only_hash) {
    Database db(":memory:");
    auto cfg = testConfig();
    SessionManager sm(db, cfg);
    auto u = findOrCreateUser(db, "a@b.c", 0);
    auto tok = sm.create(u.id, "google", "", "", 0);
    Statement q(db, "SELECT count(*) FROM sessions WHERE token_hash = ?");
    q.bind(1, toBytes(tok));
    CHECK(q.step() && q.int64(0) == 0); // 원본 토큰으로는 찾을 수 없어야 함
}

TEST(session_idle_expiry_and_sliding) {
    Database db(":memory:");
    auto cfg = testConfig();
    SessionManager sm(db, cfg);
    auto u = findOrCreateUser(db, "a@b.c", 0);
    auto tok = sm.create(u.id, "passkey", "", "", 0);
    // 29일째 사용 → 연장되어 59일째에도 유효
    CHECK(sm.validate(tok, 29 * kDay));
    CHECK(sm.validate(tok, 58 * kDay));
    // 연장된 시점(58일)에서 30일 이상 미사용 → 만료
    CHECK(!sm.validate(tok, 89 * kDay));
}

TEST(session_absolute_expiry) {
    Database db(":memory:");
    auto cfg = testConfig();
    SessionManager sm(db, cfg);
    auto u = findOrCreateUser(db, "a@b.c", 0);
    auto tok = sm.create(u.id, "passkey", "", "", 0);
    // 매일 사용해도 90일이 지나면 만료
    for (int d = 1; d < 90; d += 20)
        CHECK(sm.validate(tok, d * kDay));
    CHECK(sm.validate(tok, 89 * kDay));
    CHECK(!sm.validate(tok, 90 * kDay));
}

TEST(session_reauth_window) {
    Database db(":memory:");
    auto cfg = testConfig(); // reauth 5분
    SessionManager sm(db, cfg);
    auto u = findOrCreateUser(db, "a@b.c", 0);
    auto tok = sm.create(u.id, "passkey", "", "", 0);
    CHECK(sm.reauthFresh(*sm.validate(tok, 299), 299));
    CHECK(!sm.reauthFresh(*sm.validate(tok, 400), 400));
    sm.markReauth(tok, 400);
    CHECK(sm.reauthFresh(*sm.validate(tok, 500), 500));
}

TEST(session_list_and_revoke_by_hint) {
    Database db(":memory:");
    auto cfg = testConfig();
    SessionManager sm(db, cfg);
    auto u = findOrCreateUser(db, "a@b.c", 0);
    auto other = findOrCreateUser(db, "x@y.z", 0);
    auto t1 = sm.create(u.id, "passkey", "", "", 10);
    auto t2 = sm.create(u.id, "google", "", "", 20);
    auto t3 = sm.create(other.id, "google", "", "", 20);
    auto list = sm.listForUser(u.id, 30);
    CHECK_EQ(list.size(), 2u);
    auto hint = sm.validate(t1, 30)->idHint;
    sm.revokeByHint(other.id, hint); // 다른 사용자의 힌트로는 삭제 불가
    CHECK(sm.validate(t1, 31));
    sm.revokeByHint(u.id, hint);
    CHECK(!sm.validate(t1, 32));
    CHECK(sm.validate(t2, 32));
    CHECK_EQ(sm.revokeAllForUser(u.id), 1);
    CHECK(sm.validate(t3, 33));
}

TEST(session_cookie_header) {
    Database db(":memory:");
    auto cfg = testConfig();
    SessionManager sm(db, cfg);
    auto c = sm.cookieHeader("TOKEN");
    CHECK(c.find("douve_session=TOKEN") == 0);
    CHECK(c.find("HttpOnly") != std::string::npos);
    CHECK(c.find("Secure") != std::string::npos);
    CHECK(c.find("SameSite=Lax") != std::string::npos);
    CHECK(c.find("Domain=example.com") != std::string::npos);
    CHECK(sm.clearCookieHeader().find("Max-Age=0") != std::string::npos);
}

TEST(cookie_value_parsing) {
    CHECK_EQ(*cookieValue("a=1; douve_session=abc; b=2", "douve_session"), "abc");
    CHECK_EQ(*cookieValue("douve_session=abc", "douve_session"), "abc");
    CHECK(!cookieValue("xdouve_session=abc", "douve_session"));
    CHECK(!cookieValue("", "douve_session"));
}

TEST(redirect_allows_own_domains) {
    auto cfg = testConfig();
    CHECK_EQ(safeRedirect("/account", cfg), "/account");
    CHECK_EQ(safeRedirect("https://kuma.example.com/dashboard", cfg),
             "https://kuma.example.com/dashboard");
    CHECK_EQ(safeRedirect("https://example.com", cfg), "https://example.com");
    CHECK_EQ(safeRedirect("https://KUMA.example.com:443/x?y=1", cfg),
             "https://KUMA.example.com:443/x?y=1");
}

TEST(redirect_rejects_bypasses) {
    auto cfg = testConfig();
    const char* bad[] = {
        "//evil.com",
        "https://evil.com",
        "https://evil.com/.example.com",
        "https://example.com.evil.com",
        "https://evilexample.com",
        "https://example.com@evil.com",
        "https://user@kuma.example.com",
        "http://kuma.example.com",
        "/\\evil.com",
        "javascript:alert(1)",
        "https://kuma.example.com\t.evil.com",
        "",
    };
    for (auto b : bad) {
        if (safeRedirect(b, cfg) != "/")
            douve::testing::fail(__FILE__, __LINE__, std::string("허용됨: ") + b);
    }
}

TEST(pending_single_use_and_expiry) {
    Database db(":memory:");
    auto id = putPending(db, "oidc", "{\"n\":1}", 600, 1000);
    CHECK(!takePending(db, id, "webauthn", 1001)); // 종류가 다르면 실패 (그리고 소모되지 않음)
    CHECK_EQ(*takePending(db, id, "oidc", 1001), "{\"n\":1}");
    CHECK(!takePending(db, id, "oidc", 1002)); // 재사용 불가
    auto id2 = putPending(db, "oidc", "x", 10, 1000);
    CHECK(!takePending(db, id2, "oidc", 1011)); // 만료
}

TEST(audit_log_written) {
    Database db(":memory:");
    audit(db, std::nullopt, "login_failed", "1.2.3.4", "bad email", 5);
    Statement q(db, "SELECT event, ip, user_id IS NULL FROM audit_log");
    CHECK(q.step() && q.text(0) == "login_failed" && q.text(1) == "1.2.3.4" && q.int64(2) == 1);
}

TEST(session_one_per_device) {
    Database db(":memory:");
    auto cfg = testConfig();
    SessionManager sm(db, cfg);
    auto u = findOrCreateUser(db, "a@b.c", 1000);
    auto other = findOrCreateUser(db, "x@b.c", 1000);
    auto t1 = sm.create(u.id, "passkey", "1.1.1.1", "PC", 1000, "dev-pc");
    auto t2 = sm.create(u.id, "passkey", "2.2.2.2", "Phone", 1000, "dev-phone");
    auto o1 = sm.create(other.id, "passkey", "1.1.1.1", "PC", 1000,
                        "dev-pc");                                   // 같은 브라우저, 다른 사용자
    auto legacy = sm.create(u.id, "passkey", "1.1.1.1", "PC", 1000); // 기기 정보 없는 옛 세션
    auto t3 = sm.create(u.id, "passkey", "3.3.3.3", "PC", 1100, "dev-pc"); // PC에서 다시 로그인
    CHECK(!sm.validate(t1, 1101)); // 같은 기기 이전 세션 정리
    CHECK(sm.validate(t2, 1101).has_value());
    CHECK(sm.validate(t3, 1101).has_value());
    CHECK(sm.validate(o1, 1101).has_value());
    CHECK(sm.validate(legacy, 1101).has_value());
    CHECK_EQ(sm.listForUser(u.id, 1101).size(), 3u);
}
