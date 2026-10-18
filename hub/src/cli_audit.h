#pragma once

#include <string>
#include <vector>

namespace douve {

// `douve-hub audit-verify`: 감사 기록 해시 체인을 처음부터 다시 계산해 확인한다 (root가 실행).
// 정상이면 0, 끊겼으면 1.
int runAuditVerify(const std::vector<std::string>& args);

} // namespace douve
