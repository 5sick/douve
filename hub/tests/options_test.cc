#include "options.h"
#include "testing.h"

using douve::parseOptions;

TEST(options_defaults) {
    std::string err;
    auto o = parseOptions({}, err);
    CHECK(o && o->listenAddress == "127.0.0.1" && o->listenPort == 8700 && o->configPath.empty());
}

TEST(options_listen) {
    std::string err;
    auto wg = parseOptions({"--listen", "10.200.0.2:8700"}, err);
    CHECK(wg && wg->listenAddress == "10.200.0.2" && wg->listenPort == 8700 && wg->listenSet);
    auto v6 = parseOptions({"--listen", "[::1]:9000"}, err);
    CHECK(v6 && v6->listenAddress == "::1" && v6->listenPort == 9000);
}

TEST(options_reject_invalid) {
    std::string err;
    CHECK(!parseOptions({"--listen", "10.0.0.1"}, err));
    CHECK(!parseOptions({"--listen", "10.0.0.1:0"}, err));
    CHECK(!parseOptions({"--listen", "10.0.0.1:70000"}, err));
    CHECK(!parseOptions({"--listen", "10.0.0.1:80x"}, err));
    CHECK(!parseOptions({"--listen"}, err));
    CHECK(!parseOptions({"--config"}, err));
    CHECK(!parseOptions({"--bogus"}, err));
}

TEST(options_flags) {
    std::string err;
    auto v = parseOptions({"--version"}, err);
    CHECK(v && v->showVersion);
    auto c = parseOptions({"--config", "/etc/douve/hub.json"}, err);
    CHECK(c && c->configPath == "/etc/douve/hub.json");
}
