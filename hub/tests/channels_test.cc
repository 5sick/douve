#include "cluster/channels.h"
#include "testing.h"
#include "util/crypto.h"

using namespace douve;

namespace {
Channel ch(const std::string& kind, Json::Value cfg) {
    Channel c;
    c.kind = kind;
    c.config = std::move(cfg);
    return c;
}
Json::Value J(const char* s) {
    Json::Value v;
    Json::Reader().parse(s, v);
    return v;
}
std::string header(const HttpPost& r, const std::string& k) {
    for (const auto& [n, v] : r.headers)
        if (n == k)
            return v;
    return "";
}
} // namespace

TEST(channels_validate) {
    auto n = ch("ntfy", J(R"({"topic":"douve-alerts_1","server":"https://ntfy.example.com/"})"));
    CHECK(validateChannel(n).empty());
    CHECK(n.config["server"].asString() == "https://ntfy.example.com"); // 끝의 / 제거
    CHECK(n.name == "ntfy");                                            // 이름 기본값
    auto d = ch("ntfy", J(R"({"topic":"x"})"));
    CHECK(validateChannel(d).empty() && d.config["server"].asString() == "https://ntfy.sh");
    auto rejects = [](const char* kind, const char* cfg) {
        auto c = ch(kind, J(cfg));
        return !validateChannel(c).empty();
    };
    CHECK(rejects("ntfy", R"({"topic":"bad topic"})"));
    CHECK(rejects("ntfy", R"({"topic":"a","server":"ftp://x"})"));
    auto dc = ch("discord", J(R"({"url":"https://discord.com/api/webhooks/123/abc_DEF-1"})"));
    CHECK(validateChannel(dc).empty());
    auto dcBad = ch("discord", J(R"({"url":"https://evil.example/api/webhooks/123/abc"})"));
    CHECK(!validateChannel(dcBad).empty());
    auto sl = ch("slack", J(R"({"url":"https://hooks.slack.com/services/T0/B0/xyz"})"));
    CHECK(validateChannel(sl).empty());
    auto wh = ch("webhook", J(R"({"url":"http://192.168.0.5:8080/hook","secret":"s3"})"));
    CHECK(validateChannel(wh).empty());
    auto whBad = ch("webhook", J(R"({"url":"https://user@evil.com/x"})"));
    CHECK(!validateChannel(whBad).empty());
    auto nl = ch("webhook", J("{\"url\":\"https://x.com/a\\nb\"}"));
    CHECK(!validateChannel(nl).empty()); // 줄바꿈 금지
    auto unknown = ch("email", J("{}"));
    CHECK(!validateChannel(unknown).empty());
    // 알 수 없는 설정 키는 버린다
    auto extra = ch("slack", J(R"({"url":"https://hooks.slack.com/services/a","x":"y"})"));
    CHECK(validateChannel(extra).empty() && !extra.config.isMember("x"));
}

TEST(channels_requests) {
    auto n = ch("ntfy", J(R"({"server":"https://ntfy.sh","topic":"t1","token":"tk_abc"})"));
    auto r = channelRequest(n, "🔴 [web-1] 응답 없음", 1000);
    CHECK(r.url == "https://ntfy.sh/t1");
    CHECK(r.body == "🔴 [web-1] 응답 없음");
    CHECK(header(r, "Priority") == "high" && header(r, "Authorization") == "Bearer tk_abc");
    CHECK(header(channelRequest(n, "✅ 해소", 1000), "Priority") == "default");

    auto d = ch("discord", J(R"({"url":"https://discord.com/api/webhooks/1/a"})"));
    auto rd = channelRequest(d, "@everyone hi", 1000);
    auto bd = J(rd.body.c_str());
    CHECK(bd["content"].asString() == "@everyone hi" && bd["allowed_mentions"]["parse"].empty() &&
          bd["allowed_mentions"]["parse"].isArray());
    CHECK(
        J(channelRequest(d, std::string(3000, 'x'), 1).body.c_str())["content"].asString().size() <
        2000);

    auto s = ch("slack", J(R"({"url":"https://hooks.slack.com/services/a"})"));
    CHECK(J(channelRequest(s, "<!channel> a & b", 1).body.c_str())["text"].asString() ==
          "&lt;!channel&gt; a &amp; b");

    auto w = ch("webhook", J(R"({"url":"https://x.example/h","secret":"k"})"));
    auto rw = channelRequest(w, "hello", 1700000000);
    auto bw = J(rw.body.c_str());
    CHECK(bw["text"].asString() == "hello" && bw["source"].asString() == "douve" &&
          bw["time"].asInt64() == 1700000000);
    CHECK(header(rw, "X-Douve-Timestamp") == "1700000000");
    CHECK(header(rw, "X-Douve-Signature") ==
          "sha256=" + toHex(hmacSha256("k", "1700000000." + rw.body)));
    auto w2 = ch("webhook", J(R"({"url":"https://x.example/h"})"));
    CHECK(header(channelRequest(w2, "x", 1), "X-Douve-Signature").empty());
}

TEST(channels_mask_and_store) {
    Database db(":memory:");
    auto d = ch("discord", J(R"({"url":"https://discord.com/api/webhooks/123/SECRETTOKENabcd"})"));
    d.name = "내 디스코드";
    CHECK(validateChannel(d).empty());
    d.id = createChannel(db, d, 5);
    auto j = channelJson(*findChannel(db, d.id));
    CHECK(j["target"].asString() == "https://discord.com/…abcd");
    CHECK(j["target"].asString().find("SECRET") == std::string::npos);
    auto n = ch("ntfy", J(R"({"topic":"secret-topic","token":"tk"})"));
    CHECK(validateChannel(n).empty());
    n.id = createChannel(db, n, 6);
    auto jn = channelJson(*findChannel(db, n.id));
    CHECK(jn["target"].asString() == "https://ntfy.sh/se…" && jn["has_token"].asBool());
    CHECK(listChannels(db).size() == 2);
    CHECK(setChannelEnabled(db, n.id, false) && !findChannel(db, n.id)->enabled);
    CHECK(deleteChannel(db, d.id) && listChannels(db).size() == 1);
}

TEST(crypto_hmac_sha256_rfc4231) {
    // RFC 4231 테스트 케이스 2
    CHECK(toHex(hmacSha256("Jefe", "what do ya want for nothing?")) ==
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}
