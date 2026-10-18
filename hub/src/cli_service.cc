#include "cli_service.h"
#include "cli_i18n.h"

#include "config.h"
#include "store/db.h"
#include "store/nodes.h"
#include "store/repo.h"
#include "store/services.h"

#include <sys/stat.h>
#include <unistd.h>

#include <ctime>
#include <iostream>

namespace douve {
namespace {

const char* kUsage =
    "사용: douve-hub service-add --name 이름 --host 도메인 (--upstream 주소:포트 | --redirect "
    "URL)\n"
    "         [--node 노드이름] [--auth douve|public] [--public-path /경로/ ...] [--config 파일]\n";

std::string hostOfUrl(const std::string& url) {
    auto start = url.find("://");
    start = start == std::string::npos ? 0 : start + 3;
    auto end = url.find_first_of(":/", start);
    return url.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

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

int runServiceAdd(const std::vector<std::string>& args) {
    std::string configPath = "/etc/douve/hub.json", nodeName;
    Service s;
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
        else if (a == "--name")
            s.name = v;
        else if (a == "--host")
            s.host = v;
        else if (a == "--upstream")
            s.upstream = v;
        else if (a == "--redirect") {
            // 다른 주소로 보내기 (예: 주소를 옮긴 뒤 예전 주소)
            s.kind = "redirect";
            s.redirectTo = v;
            s.auth = "public";
        } else if (a == "--node")
            nodeName = v;
        else if (a == "--auth")
            s.auth = v;
        else if (a == "--public-path")
            s.publicPaths.push_back(v);
        else {
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
    try {
        const auto now = static_cast<std::int64_t>(std::time(nullptr));
        {
            Database db(cfg->databasePath);
            if (!nodeName.empty()) {
                for (const auto& n : listNodes(db))
                    if (n.name == nodeName)
                        s.nodeId = n.id;
                if (!s.nodeId) {
                    std::cerr << T("노드를 찾을 수 없습니다: ") << nodeName << "\n";
                    return 1;
                }
            }
            if (auto err = validateService(s, hostOfUrl(cfg->publicUrl)); !err.empty()) {
                std::cerr << err << "\n";
                return 1;
            }
            auto created = createService(db, s, now, error);
            if (!created) {
                std::cerr << error << "\n";
                return 1;
            }
            audit(db, std::nullopt, "service_created", "cli",
                  s.name + " " + s.host + " → " +
                      (s.kind == "redirect" ? s.redirectTo : s.upstream) + " (" + s.auth + ")",
                  now);
            std::cout << T("등록: ") << created->name << " " << created->host << " → "
                      << (created->kind == "redirect" ? created->redirectTo : created->upstream)
                      << " (" << created->auth << ")\n";
        }
        matchOwner(cfg->databasePath);
    } catch (const std::exception& e) {
        std::cerr << T("등록 실패: ") << e.what() << "\n";
        return 1;
    }
    return 0;
}

int runNodeSet(const std::vector<std::string>& args) {
    std::string configPath = "/etc/douve/hub.json", name, edge, portForward;
    for (std::size_t i = 0; i + 1 < args.size(); i += 2) {
        if (args[i] == "--config")
            configPath = args[i + 1];
        else if (args[i] == "--name")
            name = args[i + 1];
        else if (args[i] == "--edge")
            edge = args[i + 1];
        else if (args[i] == "--port-forward")
            portForward = args[i + 1];
    }
    auto onOff = [](const std::string& v) { return v.empty() || v == "on" || v == "off"; };
    if (name.empty() || (edge.empty() && portForward.empty()) || !onOff(edge) ||
        !onOff(portForward)) {
        std::cerr << T("사용: douve-hub node-set --name 노드 [--edge on|off] [--port-forward "
                       "on|off] [--config 파일]\n");
        return 2;
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
            std::optional<std::int64_t> id;
            for (const auto& n : listNodes(db))
                if (n.name == name)
                    id = n.id;
            if (!id) {
                std::cerr << T("노드를 찾을 수 없습니다: ") << name << "\n";
                return 1;
            }
            const auto now = static_cast<std::int64_t>(std::time(nullptr));
            if (!edge.empty()) {
                setNodeEdge(db, *id, edge == "on");
                audit(db, std::nullopt, edge == "on" ? "edge_enabled" : "edge_disabled", "cli",
                      name, now);
            }
            if (!portForward.empty()) {
                setNodePortForward(db, *id, portForward == "on");
                audit(db, std::nullopt,
                      portForward == "on" ? "port_forward_on" : "port_forward_off", "cli", name,
                      now);
            }
        }
        matchOwner(cfg->databasePath);
        if (!edge.empty())
            std::cout << name << T(": 입구 ") << (edge == "on" ? T("지정") : T("해제")) << "\n";
        if (!portForward.empty())
            std::cout << name << T(": 공유기 포트 자동 열기 ")
                      << (portForward == "on" ? T("켬") : T("끔")) << "\n";
    } catch (const std::exception& e) {
        std::cerr << T("실패: ") << e.what() << "\n";
        return 1;
    }
    return 0;
}

} // namespace douve
