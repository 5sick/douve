#include "cli_audit.h"
#include "cli_i18n.h"

#include "config.h"
#include "store/db.h"
#include "store/repo.h"
#include "util/encoding.h"

#include <sys/stat.h>
#include <unistd.h>

#include <iostream>

namespace douve {
namespace {

const char* kUsage = "사용: douve-hub audit-verify [--config /etc/douve/hub.json]\n"
                     "  감사 기록의 해시 체인을 처음부터 다시 계산합니다. 기록이 바뀌었거나 "
                     "중간이 지워졌으면 그 위치를 알려 주고 1로 끝납니다.\n";

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

int runAuditVerify(const std::vector<std::string>& args) {
    std::string configPath = "/etc/douve/hub.json";
    for (std::size_t i = 0; i < args.size(); ++i) {
        const auto& a = args[i];
        if (a == "--config" && i + 1 < args.size()) {
            configPath = args[++i];
        } else if (a == "--help" || a == "-h") {
            std::cout << T(kUsage);
            return 0;
        } else {
            std::cerr << T("알 수 없는 옵션: ") << a << "\n" << T(kUsage);
            return 2;
        }
    }
    std::string error;
    auto cfg = loadConfigFile(configPath, error);
    if (!cfg) {
        std::cerr << error << "\n";
        return 2;
    }
    AuditCheck c;
    try {
        {
            Database db(cfg->databasePath);
            c = verifyAuditChain(db);
        }
        matchOwner(cfg->databasePath);
    } catch (const std::exception& e) {
        std::cerr << T("감사 기록을 읽을 수 없습니다: ") << e.what() << "\n";
        return 1;
    }
    if (!c.ok) {
        std::cout << T("✗ 해시 체인이 끊겼습니다: #" + std::to_string(c.brokenAt) +
                       " — 이 기록이 바뀌었거나 바로 앞 기록이 지워졌습니다")
                  << "\n";
        return 1;
    }
    std::cout << T("✓ 감사 기록 " + std::to_string(c.rows) + "건, 해시 체인 정상") << "\n"
              << T("마지막 해시:") << " " << toHex(c.head) << "\n"
              << T("(마지막 기록 몇 개를 지운 것은 체인만으로 알 수 없습니다 — 웹훅으로 내보낸 "
                   "사본과 비교하세요)")
              << "\n";
    return 0;
}

} // namespace douve
