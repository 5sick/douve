#include "config.h"
#include "testing.h"

using namespace douve;

namespace {
const char* kValid = R"({
  "public_url": "https://douve.example.com/",
  "cookie_domain": ".example.com",
  "google": {"client_id": "cid", "client_secret": "sec"},
  "allowed_emails": ["Me@Example.com"],
  "listen_port": 8701
})";
}

TEST(config_parse_valid) {
    std::string err;
    auto c = parseConfig(kValid, err);
    CHECK(c.has_value());
    if (!c)
        return;
    CHECK_EQ(c->publicUrl, "https://douve.example.com");
    CHECK_EQ(c->cookieDomain, "example.com");
    CHECK_EQ(c->effectiveRpId(), "example.com");
    CHECK_EQ(c->origin(), "https://douve.example.com");
    CHECK_EQ(c->redirectHostSuffix, ".example.com");
    CHECK_EQ(c->allowedEmails.size(), 1u);
    CHECK_EQ(c->allowedEmails[0], "me@example.com");
    CHECK_EQ(c->listenPort, 8701);
    CHECK_EQ(c->googleClientSecret, "sec");
}

TEST(config_reject_invalid) {
    std::string err;
    CHECK(!parseConfig("{", err));
    CHECK(!parseConfig(R"({"public_url":"http://douve.example.com","cookie_domain":"example.com"})",
                       err));
    CHECK(!parseConfig(R"({"public_url":"https://douve.example.com"})", err));
    CHECK(!parseConfig(R"({"public_url":"https://douve.evil.com","cookie_domain":"example.com"})",
                       err));
    CHECK(!parseConfig(
        R"({"public_url":"https://douve.example.com","cookie_domain":"example.com","rp_id":"other.com"})",
        err));
    CHECK(!parseConfig(
        R"({"public_url":"https://douve.example.com","cookie_domain":"example.com","session_idle_days":40,"session_max_days":10})",
        err));
    CHECK(parseConfig(R"({"public_url":"http://localhost:8700","cookie_domain":"localhost"})", err)
              .has_value());
}

TEST(config_wrong_types_are_errors_not_crashes) {
    // 퍼징으로 찾은 입력: "google"이 객체가 아니라 배열이면 jsoncpp가 예외를 던졌다
    std::string err;
    CHECK(!parseConfig(
        R"({"public_url":"https://d.example.com","cookie_domain":"example.com","google":["1.1"]})",
        err));
    CHECK(err.find("형식") != std::string::npos);
    CHECK(!parseConfig(
        R"({"public_url":"https://d.example.com","cookie_domain":"example.com","telegram":"x"})",
        err));
    CHECK(!parseConfig(R"({"public_url":["x"],"cookie_domain":"example.com"})", err));
}
