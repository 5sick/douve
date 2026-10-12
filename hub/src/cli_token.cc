#include "cli_token.h"
#include "cli_i18n.h"

#include "config.h"
#include "store/db.h"
#include "store/nodes.h"
#include "store/repo.h"

#include <sys/stat.h>
#include <unistd.h>

#include <ctime>
#include <iostream>

namespace douve {
namespace {

const char* kUsage = "사용: douve-hub join-token [--config /etc/douve/hub.json] [--name 이름] "
                     "[--ttl-minutes 15] [--connect-url URL]\n"
                     "  --connect-url  Agent가 접속할 주소를 바꿀 때 (예: WireGuard 내부 "
                     "http://10.200.0.2:8700)\n";

// Hub 서비스(DynamicUser)가 계속 쓸 수 있도록 root가 만든 WAL 파일 소유자를 DB 파일과 맞춘다.
void matchOwner(const std::string& dbPath) {
    struct stat st{};
    if (stat(dbPath.c_str(), &st) != 0)
        return;
    for (const char* suffix : {"-wal", "-shm"}) {
        const std::string p = dbPath + suffix;
        struct stat s2{};
        if (stat(p.c_str(), &s2) == 0 && (s2.st_uid != st.st_uid || s2.st_gid != st.st_gid))
            (void)chown(p.c_str(), st.st_uid, st.st_gid);
    }
}

} // namespace

int runJoinToken(const std::vector<std::string>& args) {
    std::string configPath = "/etc/douve/hub.json", name, connectUrl;
    int ttlMinutes = 15;
    for (std::size_t i = 0; i < args.size(); ++i) {
        const auto& a = args[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= args.size())
                throw std::runtime_error(a + T(" 값이 필요합니다"));
            return args[++i];
        };
        try {
            if (a == "--config")
                configPath = next();
            else if (a == "--name")
                name = next();
            else if (a == "--ttl-minutes")
                ttlMinutes = std::stoi(next());
            else if (a == "--connect-url")
                connectUrl = next();
            else if (a == "--help" || a == "-h") {
                std::cout << T(kUsage);
                return 0;
            } else {
                std::cerr << T("알 수 없는 옵션: ") << a << "\n" << T(kUsage);
                return 2;
            }
        } catch (const std::exception& e) {
            std::cerr << e.what() << "\n" << T(kUsage);
            return 2;
        }
    }
    if (ttlMinutes < 1 || ttlMinutes > 24 * 60) {
        std::cerr << T("--ttl-minutes는 1~1440\n");
        return 2;
    }
    std::string error;
    auto cfg = loadConfigFile(configPath, error);
    if (!cfg) {
        std::cerr << error << "\n";
        return 2;
    }
    try {
        const auto now = static_cast<std::int64_t>(std::time(nullptr));
        JoinToken tok;
        {
            Database db(cfg->databasePath);
            tok = createJoinToken(db, std::nullopt, name, ttlMinutes * 60, now);
            audit(db, std::nullopt, "join_token_created", "cli", sanitizeNodeName(name), now);
        }
        matchOwner(cfg->databasePath);
        std::string env = connectUrl.empty() ? "" : "DOUVE_CONNECT_URL=" + connectUrl + " ";
        std::cout << "curl -fsSL " << cfg->publicUrl << "/join.sh | sudo " << env << "sh -s -- "
                  << tok.token << "\n";
        std::cerr << "(" << ttlMinutes << T("분 동안 한 번만 사용 가능)\n");
    } catch (const std::exception& e) {
        std::cerr << T("토큰 생성 실패: ") << e.what() << "\n";
        return 1;
    }
    return 0;
}

} // namespace douve
