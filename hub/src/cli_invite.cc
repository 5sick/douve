#include "cli_invite.h"
#include "cli_i18n.h"

#include "config.h"
#include "store/db.h"
#include "store/invites.h"
#include "store/repo.h"

#include <sys/stat.h>
#include <unistd.h>

#include <ctime>
#include <iostream>

namespace douve {
namespace {

const char* kUsage =
    "사용: douve-hub invite --email 주소 [--hours 24] [--config /etc/douve/hub.json]\n";

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

int runInvite(const std::vector<std::string>& args) {
    std::string configPath = "/etc/douve/hub.json", email;
    int hours = 24;
    for (std::size_t i = 0; i < args.size(); ++i) {
        const auto& a = args[i];
        if (a == "--help" || a == "-h") {
            std::cout << T(kUsage);
            return 0;
        }
        if (i + 1 >= args.size()) {
            std::cerr << a << T(" 값이 필요합니다\n") << T(kUsage);
            return 2;
        }
        const std::string v = args[++i];
        if (a == "--config")
            configPath = v;
        else if (a == "--email")
            email = v;
        else if (a == "--hours")
            hours = std::atoi(v.c_str());
        else {
            std::cerr << T("알 수 없는 옵션: ") << a << "\n" << T(kUsage);
            return 2;
        }
    }
    if (email.find('@') == std::string::npos || email.size() > 254 || hours < 1 || hours > 24 * 7) {
        std::cerr << T("--email(주소)과 --hours(1~168)를 확인하세요\n") << T(kUsage);
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
        Invite inv;
        {
            Database db(cfg->databasePath);
            inv = createInvite(db, email, std::nullopt, hours * 3600, now);
            audit(db, std::nullopt, "invite_created", "cli", inv.email, now);
        }
        matchOwner(cfg->databasePath);
        // 토큰은 # 뒤(프래그먼트)에 두어 서버·프록시 로그와 Referer에 남지 않게 한다
        std::cout << cfg->publicUrl << "/invite#" << inv.token << "\n";
        std::cerr << "(" << inv.email << ", " << hours << T("시간 동안 한 번만 사용 가능)\n");
    } catch (const std::exception& e) {
        std::cerr << T("초대 생성 실패: ") << e.what() << "\n";
        return 1;
    }
    return 0;
}

} // namespace douve
