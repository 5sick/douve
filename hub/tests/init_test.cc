#include "config.h"
#include "init.h"
#include "testing.h"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

using namespace douve;

TEST(init_infer_cookie_domain) {
    CHECK_EQ(inferCookieDomain("https://douve.example.com"), "example.com");
    CHECK_EQ(inferCookieDomain("https://douve.example.com:8443/x"), "example.com");
    CHECK_EQ(inferCookieDomain("https://example.com"), "example.com");
    CHECK_EQ(inferCookieDomain("http://localhost:8700"), "localhost");
}

TEST(init_writes_valid_private_config) {
    std::string path = "/tmp/douve-init-test-" + std::to_string(::getpid()) + ".json";
    std::remove(path.c_str());
    int rc = runInit({"--public-url", "https://douve.example.com", "--email", "A@B.com", "--listen",
                      "10.200.0.2:8700", "--trusted-proxy", "10.200.0.1", "--output", path});
    CHECK_EQ(rc, 0);
    struct stat st{};
    CHECK(::stat(path.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);
    std::string err;
    auto c = loadConfigFile(path, err);
    CHECK(c.has_value());
    if (c) {
        CHECK_EQ(c->cookieDomain, "example.com");
        CHECK_EQ(c->listenAddress, "10.200.0.2");
        CHECK_EQ(c->allowedEmails[0], "a@b.com");
        CHECK_EQ(c->trustedProxies.size(), 3u);
    }
    // 덮어쓰기는 --force 없이 거부
    CHECK(runInit({"--public-url", "https://douve.x.com", "--email", "a@b.c", "--output", path}) !=
          0);
    CHECK_EQ(runInit({"--public-url", "https://douve.x.com", "--email", "a@b.c", "--output", path,
                      "--force"}),
             0);
    std::remove(path.c_str());
}

TEST(init_rejects_bad_input) {
    CHECK(runInit({"--email", "a@b.c", "--output", "/tmp/douve-init-x.json"}) !=
          0); // 공개 주소 없음
    CHECK(runInit({"--public-url", "http://douve.x.com", "--email", "a@b.c", "--output",
                   "/tmp/douve-init-x.json"}) != 0); // https 아님
    CHECK(runInit({"--public-url", "https://douve.x.com", "--output", "/tmp/douve-init-x.json"}) !=
          0); // 이메일 없음
    std::remove("/tmp/douve-init-x.json");
}
