#pragma once

#include <string>
#include <vector>

namespace douve {

// `douve-hub join-token`: Hub가 설치된 서버에서 root가 서버 추가 명령을 만든다.
// (웹 화면 없이 첫 서버를 등록하거나 스크립트로 여러 대를 추가할 때)
int runJoinToken(const std::vector<std::string>& args);

} // namespace douve
