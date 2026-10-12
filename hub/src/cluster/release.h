#pragma once
// Hub가 배포하는 Agent 릴리스 정보 (agent_dir의 VERSION + SHA256SUMS).
// 접속한 Agent의 버전이 다르면 Hub가 업데이트를 지시한다.

#include <map>
#include <optional>
#include <string>

namespace douve {

struct AgentRelease {
    std::string version;
    std::map<std::string, std::string> sha256; // arch(amd64/arm64) → 체크섬
};

std::optional<AgentRelease> loadAgentRelease(const std::string& dir);

} // namespace douve
