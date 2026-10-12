#pragma once

#include <string>
#include <vector>

namespace douve {

// `douve-hub init ...` — 설정 파일을 만든다. 성공 시 0.
int runInit(const std::vector<std::string>& args);

// 공개 주소의 호스트에서 쿠키 도메인을 추론한다 (douve.example.com → example.com, example.com →
// example.com).
std::string inferCookieDomain(const std::string& publicUrl);

} // namespace douve
