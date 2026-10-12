#include "auth/ratelimit.h"

namespace douve {

bool RateLimiter::allow(const std::string& key, std::int64_t now) {
    std::lock_guard lk(mu_);
    if (now - lastCleanup_ > window_)
        cleanup(now);
    auto& q = hits_[key];
    while (!q.empty() && q.front() <= now - window_)
        q.pop_front();
    if (static_cast<int>(q.size()) >= limit_)
        return false;
    q.push_back(now);
    return true;
}

void RateLimiter::cleanup(std::int64_t now) {
    lastCleanup_ = now;
    for (auto it = hits_.begin(); it != hits_.end();) {
        auto& q = it->second;
        while (!q.empty() && q.front() <= now - window_)
            q.pop_front();
        it = q.empty() ? hits_.erase(it) : std::next(it);
    }
}

} // namespace douve
