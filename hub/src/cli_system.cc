#include "cli_system.h"
#include "cli_i18n.h"
#include "util/json.h"

#include "config.h"
#include "settings.h"
#include "store/db.h"
#include "store/invites.h"

#include <sys/stat.h>
#include <unistd.h>

#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>

namespace douve {

std::string hubUnitFile() {
    return R"unit([Unit]
Description=Douve Hub (서버 관리 · 로그인 관문)
Documentation=https://github.com/5sick/douve
Wants=network-online.target
After=network-online.target

[Service]
# 설정은 root 전용 파일을 systemd 자격증명으로만 읽는다
LoadCredential=hub.json:/etc/douve/hub.json
ExecStart=/usr/local/bin/douve-hub --config ${CREDENTIALS_DIRECTORY}/hub.json
Restart=on-failure
RestartSec=3
DynamicUser=yes
StateDirectory=douve
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

[Install]
WantedBy=multi-user.target
)unit";
}

int runInstallService(const std::vector<std::string>& args) {
    std::string path = "/etc/systemd/system/douve-hub.service";
    if (args.size() == 2 && args[0] == "--output")
        path = args[1];
    else if (!args.empty()) {
        std::cerr << T("사용: douve-hub install-service [--output 파일]\n");
        return 2;
    }
    std::ofstream out(path, std::ios::trunc);
    if (!out) {
        std::cerr << T("쓸 수 없습니다: ") << path << T(" (root 권한 필요)\n");
        return 1;
    }
    out << hubUnitFile();
    std::cout << T("설치됨: ") << path << "\n";
    return 0;
}

namespace {
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

int runConfigure(const std::vector<std::string>& args) {
    std::string configPath = "/etc/douve/hub.json", features, expose;
    for (std::size_t i = 0; i + 1 < args.size(); i += 2) {
        if (args[i] == "--config")
            configPath = args[i + 1];
        else if (args[i] == "--features")
            features = args[i + 1];
        else if (args[i] == "--expose")
            expose = args[i + 1];
        else {
            std::cerr << T("알 수 없는 옵션: ") << args[i] << "\n";
            return 2;
        }
    }
    if (features.empty() && expose.empty()) {
        std::cerr << T(
            "사용: douve-hub configure [--features JSON] [--expose on|off] [--config 파일]\n");
        return 2;
    }
    std::string error;
    auto cfg = loadConfigFile(configPath, error);
    if (!cfg) {
        std::cerr << error << "\n";
        return 2;
    }
    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    try {
        {
            Database db(cfg->databasePath);
            if (!features.empty()) {
                Json::Value v;
                std::string err;
                if (!parseJson(features, v, &err) || !v.isObject()) {
                    std::cerr << T("--features JSON 오류: ") << err << "\n";
                    return 2;
                }
                RuntimeSettings rs;
                rs.saveFeatures(db, Features::fromJson(v), now);
            }
            if (!expose.empty()) {
                if (expose != "on" && expose != "off") {
                    std::cerr << T("--expose는 on 또는 off\n");
                    return 2;
                }
                putSetting(db, "agent.expose", expose, now);
            }
        }
        matchOwner(cfg->databasePath);
        std::cout << T("설정 저장됨 (실행 중인 Hub는 재시작하면 반영)\n");
    } catch (const std::exception& e) {
        std::cerr << T("실패: ") << e.what() << "\n";
        return 1;
    }
    return 0;
}

} // namespace douve
