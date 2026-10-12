#pragma once

#include <string>
#include <vector>

namespace douve {

// `douve-hub invite --email 주소`: 1회용 초대 링크(패스키 등록)를 만든다. 설치 직후 첫 관리자도
// 이것으로.
int runInvite(const std::vector<std::string>& args);

} // namespace douve
