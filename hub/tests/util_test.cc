#include "testing.h"
#include "util/crypto.h"
#include "util/encoding.h"
#include "util/json.h"

using namespace douve;

TEST(base64url_rfc4648_vectors) {
    // RFC 4648 §10 테스트 벡터 (패딩 제거, url-safe)
    CHECK_EQ(base64UrlEncode(std::string_view("")), "");
    CHECK_EQ(base64UrlEncode(std::string_view("f")), "Zg");
    CHECK_EQ(base64UrlEncode(std::string_view("fo")), "Zm8");
    CHECK_EQ(base64UrlEncode(std::string_view("foo")), "Zm9v");
    CHECK_EQ(base64UrlEncode(std::string_view("foob")), "Zm9vYg");
    CHECK_EQ(base64UrlEncode(std::string_view("fooba")), "Zm9vYmE");
    CHECK_EQ(base64UrlEncode(std::string_view("foobar")), "Zm9vYmFy");
    CHECK_EQ(base64UrlEncode(Bytes{0xfb, 0xff}), "-_8");
}

TEST(base64url_roundtrip_and_reject) {
    for (std::size_t n = 0; n < 70; ++n) {
        Bytes b = randomBytes(n);
        auto d = base64UrlDecode(base64UrlEncode(b));
        CHECK(d && *d == b);
    }
    CHECK(base64UrlDecode("Zm9vYg==").has_value()); // 패딩 허용
    CHECK(!base64UrlDecode("Zm9v!").has_value());   // 잘못된 문자
    CHECK(!base64UrlDecode("Z").has_value());       // 불가능한 길이
    CHECK(!base64UrlDecode("Zh").has_value());      // 비정규 (남는 비트 ≠ 0)
}

TEST(sha256_known_vector) {
    CHECK_EQ(toHex(sha256(std::string_view("abc"))),
             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(random_token_unique) {
    auto a = randomToken(), b = randomToken();
    CHECK_EQ(a.size(), 43u);
    CHECK(a != b);
}

TEST(constant_time_equals) {
    CHECK(constantTimeEquals(Bytes{1, 2, 3}, Bytes{1, 2, 3}));
    CHECK(!constantTimeEquals(Bytes{1, 2, 3}, Bytes{1, 2, 4}));
    CHECK(!constantTimeEquals(Bytes{1, 2}, Bytes{1, 2, 3}));
}

TEST(json_parse_never_throws) {
    Json::Value v;
    CHECK(parseJson(R"({"a":"x","n":3,"b":true})", v));
    CHECK_EQ(jsonStr(v, "a"), "x");
    CHECK_EQ(jsonInt(v, "n"), 3);
    CHECK(jsonBool(v, "b"));
    // 형식이 다르면 기본값 (asString은 예외를 던진다)
    CHECK(parseJson(R"({"a":[1],"n":"3","b":"yes"})", v));
    CHECK_EQ(jsonStr(v, "a", "d"), "d");
    CHECK_EQ(jsonInt(v, "n", -1), -1);
    CHECK(!jsonBool(v, "b"));
    CHECK_EQ(jsonStr(Json::Value(Json::arrayValue), "a"), "");
    // 깊은 중첩·깨진 입력은 예외 없이 실패
    CHECK(!parseJson(std::string(100000, '['), v));
    CHECK(v.isNull());
    CHECK(!parseJson("{\"a\":", v));
    CHECK(!parseJson("", v));
}
