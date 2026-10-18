#include "options.h"
#include "cli_i18n.h"

#include <charconv>

namespace douve {
namespace {

// "host:port" 형식. IPv6는 "[::1]:8700".
bool parseListen(const std::string& value, Options& opts) {
    auto colon = value.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 == value.size()) {
        return false;
    }
    std::string host = value.substr(0, colon);
    if (host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }
    const std::string portText = value.substr(colon + 1);
    unsigned port = 0;
    auto [ptr, ec] = std::from_chars(portText.data(), portText.data() + portText.size(), port);
    if (ec != std::errc{} || ptr != portText.data() + portText.size() || port == 0 ||
        port > 65535) {
        return false;
    }
    opts.listenAddress = host;
    opts.listenPort = static_cast<std::uint16_t>(port);
    opts.listenSet = true;
    return true;
}

} // namespace

std::optional<Options> parseOptions(const std::vector<std::string>& args, std::string& error) {
    Options opts;
    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string& arg = args[i];
        if (arg == "--version" || arg == "-v") {
            opts.showVersion = true;
        } else if (arg == "--help" || arg == "-h") {
            opts.showHelp = true;
        } else if (arg == "--config") {
            if (i + 1 >= args.size()) {
                error = T("--config 에 파일 경로가 필요합니다");
                return std::nullopt;
            }
            opts.configPath = args[++i];
        } else if (arg == "--listen") {
            if (i + 1 >= args.size() || !parseListen(args[++i], opts)) {
                error = T("--listen 값은 host:port 형식이어야 합니다");
                return std::nullopt;
            }
        } else {
            error = T("알 수 없는 인자: ") + arg;
            return std::nullopt;
        }
    }
    return opts;
}

std::string usage() {
    return T("사용법: douve-hub [--config 파일] [--listen host:port] [--version] [--help]\n"
             "       douve-hub init --help   (설정 파일 만들기)\n"
             "       douve-hub join-token --help   (서버 추가 명령 만들기)\n"
             "       douve-hub service-add --help  (서비스 등록)\n"
             "       douve-hub invite --help       (초대 링크: 패스키로 사용자 추가)\n"
             "       douve-hub recovery-codes --help  (비상용 일회용 복구 코드)\n"
             "       douve-hub backup --help / restore --help  (DB·설정 백업과 복원)\n"
             "       douve-hub audit-verify  (감사 기록 해시 체인 확인)\n"
             "  --config   설정 파일 (예: /etc/douve/hub.json)\n"
             "  --listen   수신 주소 (설정 파일 값보다 우선, 기본 127.0.0.1:8700)\n");
}

} // namespace douve
