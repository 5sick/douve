#include "cli_recovery.h"
#include "cli_i18n.h"

#include "config.h"
#include "store/backup.h"
#include "store/db.h"
#include "store/recovery.h"
#include "store/repo.h"
#include "version.h"

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>

namespace douve {
namespace {

std::int64_t nowSec() {
    return static_cast<std::int64_t>(std::time(nullptr));
}

// root가 만든 WAL 파일을 Hub(DynamicUser)가 계속 쓸 수 있게 DB 파일 소유자에 맞춘다
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

// "--key value" 옵션 읽기. 위치 인자는 positional에.
bool parseArgs(const std::vector<std::string>& args, std::map<std::string, std::string>& opts,
               std::vector<std::string>& positional, const std::set<std::string>& flags,
               const char* usage) {
    for (std::size_t i = 0; i < args.size(); ++i) {
        const auto& a = args[i];
        if (a == "--help" || a == "-h") {
            std::cout << T(usage);
            return false;
        }
        if (a.rfind("--", 0) != 0) {
            positional.push_back(a);
            continue;
        }
        if (flags.count(a)) {
            opts[a] = "1";
            continue;
        }
        if (i + 1 >= args.size()) {
            std::cerr << a << T(" 값이 필요합니다\n") << T(usage);
            return false;
        }
        opts[a] = args[++i];
    }
    return true;
}

bool hubRunning() {
    // systemd 아래에서 실행 중이면 복원하지 않는다
    const int rc = std::system("systemctl is-active --quiet douve-hub 2>/dev/null");
    return rc != -1 && WIFEXITED(rc) && WEXITSTATUS(rc) == 0;
}

} // namespace

int runRecoveryCodes(const std::vector<std::string>& args) {
    const char* usage =
        "사용: douve-hub recovery-codes --email 주소 [--config /etc/douve/hub.json]\n"
        "  패스키·기기를 잃었을 때 로그인하는 일회용 복구 코드 10개를 새로 만듭니다.\n"
        "  (이전 코드는 모두 무효)\n";
    std::map<std::string, std::string> o;
    std::vector<std::string> pos;
    if (!parseArgs(args, o, pos, {}, usage))
        return args.empty() ? 2 : 0;
    const std::string configPath = o.count("--config") ? o["--config"] : "/etc/douve/hub.json";
    std::string email = o["--email"];
    for (auto& c : email)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (email.find('@') == std::string::npos) {
        std::cerr << T("--email 이 필요합니다\n") << T(usage);
        return 2;
    }
    std::string error;
    auto cfg = loadConfigFile(configPath, error);
    if (!cfg) {
        std::cerr << error << "\n";
        return 2;
    }
    try {
        std::vector<std::string> codes;
        {
            Database db(cfg->databasePath);
            // 아직 로그인한 적 없는 첫 관리자도 만들 수 있게 (허용 목록에 있어야 로그인 가능)
            auto user = findOrCreateUser(db, email, nowSec());
            codes = generateRecoveryCodes(db, user.id, nowSec());
            audit(db, user.id, "recovery_codes_created", "cli", email, nowSec());
        }
        matchOwner(cfg->databasePath);
        for (const auto& c : codes)
            std::cout << c << "\n";
        std::cerr << "(" << email
                  << T(" — 한 번씩만 쓸 수 있습니다. 서버 밖 안전한 곳에 적어 두세요. ")
                  << T("로그인 화면의 '복구 코드로 로그인')\n");
    } catch (const std::exception& e) {
        std::cerr << T("복구 코드 생성 실패: ") << e.what() << "\n";
        return 1;
    }
    return 0;
}

int runBackup(const std::vector<std::string>& args) {
    const char* usage =
        "사용: douve-hub backup [--output 파일] [--config /etc/douve/hub.json]\n"
        "  DB 전체와 설정(hub.json)을 파일 하나로 백업합니다 (Hub 실행 중에도 가능).\n"
        "  비밀(Agent 키·세션·알림 토큰)이 들어 있으니 서버 밖 안전한 곳에 보관하세요.\n";
    std::map<std::string, std::string> o;
    std::vector<std::string> pos;
    if (!parseArgs(args, o, pos, {}, usage))
        return 0;
    const std::string configPath = o.count("--config") ? o["--config"] : "/etc/douve/hub.json";
    std::string out = o["--output"];
    if (out.empty()) {
        char buf[32];
        std::time_t t = std::time(nullptr);
        std::tm tm{};
        localtime_r(&t, &tm);
        std::strftime(buf, sizeof buf, "%Y%m%d-%H%M%S", &tm);
        out = std::string("douve-backup-") + buf + ".db";
    }
    std::string error;
    auto cfg = loadConfigFile(configPath, error);
    if (!cfg) {
        std::cerr << error << "\n";
        return 2;
    }
    try {
        {
            Database db(cfg->databasePath);
            error = writeBackup(db, configPath, out, kVersion, nowSec());
        }
        matchOwner(cfg->databasePath);
    } catch (const std::exception& e) {
        error = e.what();
    }
    if (!error.empty()) {
        std::cerr << error << "\n";
        return 1;
    }
    std::cout << out << "\n";
    std::cerr << T("(복원: 새 서버에서 douve-hub restore ") << out << ")\n";
    return 0;
}

int runRestore(const std::vector<std::string>& args) {
    const char* usage =
        "사용: douve-hub restore <백업 파일> [--config /etc/douve/hub.json] [--keep-config] "
        "[--force]\n"
        "  Hub를 멈춘 뒤 실행하세요 (systemctl stop douve-hub). 기존 DB·설정은 "
        "*.before-restore-<시각>으로 남깁니다.\n"
        "  --keep-config  지금 설정 파일을 그대로 두고 DB만 복원\n";
    std::map<std::string, std::string> o;
    std::vector<std::string> pos;
    if (!parseArgs(args, o, pos, {"--keep-config", "--force"}, usage))
        return 0;
    if (pos.size() != 1) {
        std::cerr << T(usage);
        return 2;
    }
    const std::string configPath = o.count("--config") ? o["--config"] : "/etc/douve/hub.json";
    if (!o.count("--force") && hubRunning()) {
        std::cerr << T("douve-hub가 실행 중입니다. 먼저 멈추세요: systemctl stop douve-hub\n");
        return 1;
    }
    std::string error;
    auto info = readBackupInfo(pos[0], error);
    if (!info) {
        std::cerr << error << "\n";
        return 1;
    }
    const auto t = nowSec();
    // 설정: 백업에 든 것을 쓴다 (기존 것은 남겨 둠)
    std::string configText;
    if (!o.count("--keep-config") && !info->config.empty()) {
        std::string perr;
        if (!parseConfig(info->config, perr)) {
            std::cerr << T("백업 안의 설정이 올바르지 않습니다: ") << perr << "\n";
            return 1;
        }
        configText = info->config;
    }
    if (!configText.empty()) {
        namespace fs = std::filesystem;
        std::error_code ec;
        fs::create_directories(fs::path(configPath).parent_path(), ec);
        if (fs::exists(configPath))
            fs::copy_file(configPath, configPath + ".before-restore-" + std::to_string(t),
                          fs::copy_options::overwrite_existing, ec);
        const mode_t old = umask(0077);
        std::ofstream f(configPath, std::ios::trunc);
        f << configText;
        f.close();
        umask(old);
        if (!f) {
            std::cerr << T("설정 파일을 쓸 수 없습니다: ") << configPath << "\n";
            return 1;
        }
    }
    auto cfg = loadConfigFile(configPath, error);
    if (!cfg) {
        std::cerr << error << "\n";
        return 1;
    }
    error = restoreDatabase(pos[0], cfg->databasePath, t);
    if (!error.empty()) {
        std::cerr << error << "\n";
        return 1;
    }
    std::cout << T("복원했습니다: ") << cfg->databasePath
              << (configText.empty() ? "" : " + " + configPath) << "\n";
    std::cerr << T("(백업 시각 ") << info->createdAt << T(", 버전 ") << info->version
              << T(") 이제 systemctl start douve-hub\n")
              << T("다른 서버로 옮겼다면 DNS(또는 Tailscale)가 새 서버를 가리키게 하세요. "
                   "Agent들은 같은 주소로 다시 접속합니다.\n");
    return 0;
}

} // namespace douve
