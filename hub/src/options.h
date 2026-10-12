#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace douve {

// douve-hub 명령줄 옵션. 대부분의 설정은 설정 파일(--config)에서 읽고,
// --listen은 설정 파일 값을 덮어쓴다.
struct Options {
    std::string configPath;
    std::string listenAddress = "127.0.0.1";
    std::uint16_t listenPort = 8700;
    bool listenSet = false;
    bool showVersion = false;
    bool showHelp = false;
};

// 인자 파싱. 실패 시 nullopt를 반환하고 error에 사유를 채운다.
std::optional<Options> parseOptions(const std::vector<std::string>& args, std::string& error);

std::string usage();

} // namespace douve
