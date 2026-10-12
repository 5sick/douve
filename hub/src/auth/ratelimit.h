#pragma once

#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>

namespace douve {

// 고정 창(sliding window) 방식의 요청 횟수 제한. 키(보통 IP)별로 windowSeconds 동안 limit회까지
// 허용. 메모리 상태라 재시작하면 초기화된다 (개인 서버 규모에서는 충분).
class RateLimiter {
  public:
    RateLimiter(int limit, int windowSeconds) : limit_(limit), window_(windowSeconds) {}

    bool allow(const std::string& key, std::int64_t now);

  private:
    void cleanup(std::int64_t now);

    const int limit_;
    const int window_;
    std::mutex mu_;
    std::unordered_map<std::string, std::deque<std::int64_t>> hits_;
    std::int64_t lastCleanup_ = 0;
};

} // namespace douve
