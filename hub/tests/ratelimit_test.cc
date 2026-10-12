#include "auth/ratelimit.h"
#include "testing.h"

using douve::RateLimiter;

TEST(ratelimit_window) {
    RateLimiter rl(3, 60);
    CHECK(rl.allow("a", 0));
    CHECK(rl.allow("a", 1));
    CHECK(rl.allow("a", 2));
    CHECK(!rl.allow("a", 3));  // 한도 초과
    CHECK(rl.allow("b", 3));   // 다른 키는 별개
    CHECK(!rl.allow("a", 59)); // 아직 창 안
    CHECK(rl.allow("a", 60));  // 첫 요청(0초)이 창 밖으로
    CHECK(!rl.allow("a", 60));
}

TEST(ratelimit_cleanup_keeps_working) {
    RateLimiter rl(1, 10);
    for (int i = 0; i < 1000; ++i)
        CHECK(rl.allow("ip" + std::to_string(i), 0));
    CHECK(rl.allow("ip0", 100)); // 정리 후에도 정상 동작
    CHECK(!rl.allow("ip0", 101));
}
