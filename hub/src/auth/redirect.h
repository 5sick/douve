#pragma once

#include "config.h"

#include <string>

namespace douve {

// 로그인 후 돌아갈 주소가 안전한지 검사한다 (오픈 리다이렉트 방지).
// 허용: "/"로 시작하는 Hub 내부 경로, 또는 https://<cookie_domain 또는 그 서브도메인>/...
std::string safeRedirect(const std::string& target, const HubConfig& cfg,
                         const std::string& fallback = "/");

} // namespace douve
