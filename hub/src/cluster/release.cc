#include "cluster/release.h"

#include <fstream>
#include <regex>
#include <sstream>

namespace douve {

std::optional<AgentRelease> loadAgentRelease(const std::string& dir) {
    AgentRelease r;
    std::ifstream v(dir + "/VERSION");
    if (!v || !std::getline(v, r.version))
        return std::nullopt;
    while (!r.version.empty() && std::isspace(static_cast<unsigned char>(r.version.back())))
        r.version.pop_back();
    if (r.version.empty() || r.version.size() > 64)
        return std::nullopt;
    auto readAll = [](const std::string& p) {
        std::ifstream f(p, std::ios::binary);
        std::stringstream ss;
        ss << f.rdbuf();
        return ss.str();
    };
    r.sums = readAll(dir + "/SHA256SUMS");
    r.signature = readAll(dir + "/SHA256SUMS.minisig");
    std::istringstream sums(r.sums);
    static const std::regex line(R"(^([0-9a-f]{64})\s+\*?douve-agent-linux-(amd64|arm64)\s*$)");
    std::string s;
    while (std::getline(sums, s)) {
        std::smatch m;
        if (std::regex_match(s, m, line))
            r.sha256[m[2]] = m[1];
    }
    if (r.sha256.empty())
        return std::nullopt;
    return r;
}

} // namespace douve
