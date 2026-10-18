#include "store/db.h"
#include "store/devnet.h"
#include "store/services.h"
#include "testing.h"
#include "util/encoding.h"

using namespace douve;

TEST(devnet_settings_roundtrip) {
    Database db(":memory:");
    auto s = loadDevnet(db);
    CHECK(!s.enabled);
    CHECK_EQ(s.port, 51821);
    s.enabled = true;
    s.port = 40000;
    s.endpoint = "vpn.example.com";
    s.gatewayKey = generateWgKeyPair().publicKey;
    s.gatewayNode = 3;
    saveDevnet(db, s, 1);
    auto t = loadDevnet(db);
    CHECK(t.enabled && t.port == 40000 && t.endpoint == "vpn.example.com" && t.gatewayNode == 3);
    CHECK_EQ(t.gatewayKey, s.gatewayKey);
    CHECK_EQ(validateDevnet(t), "");
    t.port = 80;
    CHECK(!validateDevnet(t).empty());
    t.port = 51821;
    t.endpoint = "vpn.example.com:51821/x";
    CHECK(!validateDevnet(t).empty());
}

TEST(devnet_keys) {
    auto a = generateWgKeyPair(), b = generateWgKeyPair();
    CHECK(validWgKey(a.publicKey) && validWgKey(a.privateKey));
    CHECK_EQ(a.publicKey.size(), 44u);
    CHECK(a.publicKey.back() == '=');
    CHECK(a.publicKey != b.publicKey && a.privateKey != a.publicKey);
    CHECK(!validWgKey(""));
    CHECK(!validWgKey("abc"));
    std::string urlsafe = a.publicKey;
    for (auto& c : urlsafe)
        c = c == '+' ? '-' : c == '/' ? '_' : c;
    if (urlsafe != a.publicKey)
        CHECK(!validWgKey(urlsafe)); // 표준 base64만
}

TEST(devnet_devices) {
    Database db(":memory:");
    db.exec("INSERT INTO users (id, email, created_at) VALUES (1, 'a@x', 0), (2, 'b@x', 0)");
    std::string err;
    auto k1 = generateWgKeyPair(), k2 = generateWgKeyPair();
    auto d1 = createDevice(db, 1, "  아이폰 ", k1.publicKey, 10, err);
    CHECK(d1.has_value());
    CHECK_EQ(d1->ip, std::string("10.201.0.2"));
    CHECK_EQ(d1->name, std::string("아이폰"));
    auto d2 = createDevice(db, 2, "맥북", k2.publicKey, 11, err);
    CHECK_EQ(d2->ip, std::string("10.201.0.3"));
    CHECK(!createDevice(db, 1, "중복", k1.publicKey, 12, err)); // 같은 키
    CHECK(!createDevice(db, 1, "", generateWgKeyPair().publicKey, 12, err));
    CHECK(!createDevice(db, 1, "<script>", generateWgKeyPair().publicKey, 12, err));
    CHECK(!createDevice(db, 1, "x", "not-a-key", 12, err));
    CHECK_EQ(listDevicesOf(db, 1).size(), 1u);
    CHECK_EQ(listDevices(db).size(), 2u);
    // 지운 주소는 다시 쓴다
    CHECK(deleteDevice(db, d1->id));
    auto d3 = createDevice(db, 2, "폰", generateWgKeyPair().publicKey, 13, err);
    CHECK_EQ(d3->ip, std::string("10.201.0.2"));
    // 사용자를 지우면 기기도
    db.exec("DELETE FROM users WHERE id = 2");
    CHECK(listDevices(db).empty());
}

TEST(devnet_device_config) {
    DevnetSettings s;
    s.port = 51821;
    s.gatewayKey = "GW+key/abc=";
    auto c = deviceConfig(s, "douve.example.com", "PRIV=", "10.201.0.5");
    CHECK(c.find("PrivateKey = PRIV=\n") != std::string::npos);
    CHECK(c.find("Address = 10.201.0.5/32\n") != std::string::npos);
    CHECK(c.find("DNS = 10.201.0.1\n") != std::string::npos);
    CHECK(c.find("PublicKey = GW+key/abc=\n") != std::string::npos);
    CHECK(c.find("Endpoint = douve.example.com:51821\n") != std::string::npos);
    CHECK(c.find("AllowedIPs = 10.201.0.0/24\n") !=
          std::string::npos); // 내부 길만 (나머지는 원래대로)
    s.endpoint = "2001:db8::1";
    CHECK(deviceConfig(s, "x", "P", "10.201.0.5").find("Endpoint = [2001:db8::1]:51821") !=
          std::string::npos);
}

TEST(service_internal_external) {
    Database db(":memory:");
    Service s;
    s.name = "app";
    s.host = "app.example.com";
    s.upstream = "10.200.0.2:8080";
    s.internal = true;
    s.external = false;
    CHECK_EQ(validateService(s, "douve.example.com"), "");
    std::string err;
    auto c = createService(db, s, 1, err);
    CHECK(c && c->internal && !c->external);
    c->external = true;
    CHECK(updateService(db, *c, 2, err));
    auto f = findService(db, c->id);
    CHECK(f->internal && f->external);
    s.internal = s.external = false;
    CHECK(!validateService(s, "douve.example.com").empty()); // 둘 다 끄면 안 됨
    // 기존 서비스(마이그레이션 전 행)는 외부만
    db.exec("INSERT INTO services (name, host, upstream, created_at, updated_at) VALUES ('old', "
            "'old.example.com', '10.0.0.1:80', 0, 0)");
    for (const auto& x : listServices(db))
        if (x.name == "old")
            CHECK(x.external && !x.internal);
}
