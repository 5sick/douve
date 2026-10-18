#include "app.h"
#include "cli_audit.h"
#include "cli_i18n.h"
#include "cli_invite.h"
#include "cli_recovery.h"
#include "cli_service.h"
#include "cli_system.h"
#include "cli_token.h"
#include "init.h"
#include "net/https_client.h"
#include "options.h"
#include "version.h"

#include <drogon/drogon.h>

#include <cstdio>
#include <filesystem>
#include <iostream>

int main(int argc, char* argv[]) {
    // journald(파이프)로 보낼 때도 로그가 즉시 보이도록 줄 단위 버퍼링
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    if (argc > 1 && std::string(argv[1]) == "init")
        return douve::runInit({argv + 2, argv + argc});
    if (argc > 1 && std::string(argv[1]) == "join-token")
        return douve::runJoinToken({argv + 2, argv + argc});
    if (argc > 1 && std::string(argv[1]) == "invite")
        return douve::runInvite({argv + 2, argv + argc});
    if (argc > 1 && std::string(argv[1]) == "install-service")
        return douve::runInstallService({argv + 2, argv + argc});
    if (argc > 1 && std::string(argv[1]) == "configure")
        return douve::runConfigure({argv + 2, argv + argc});
    if (argc > 1 && std::string(argv[1]) == "node-set")
        return douve::runNodeSet({argv + 2, argv + argc});
    if (argc > 1 && std::string(argv[1]) == "service-add")
        return douve::runServiceAdd({argv + 2, argv + argc});
    if (argc > 1 && std::string(argv[1]) == "recovery-codes")
        return douve::runRecoveryCodes({argv + 2, argv + argc});
    if (argc > 1 && std::string(argv[1]) == "backup")
        return douve::runBackup({argv + 2, argv + argc});
    if (argc > 1 && std::string(argv[1]) == "restore")
        return douve::runRestore({argv + 2, argv + argc});
    if (argc > 1 && std::string(argv[1]) == "audit-verify")
        return douve::runAuditVerify({argv + 2, argv + argc});
    std::string error;
    auto opts = douve::parseOptions({argv + 1, argv + argc}, error);
    if (!opts) {
        std::cerr << error << "\n" << douve::T(douve::usage());
        return 2;
    }
    if (opts->showHelp) {
        std::cout << douve::T(douve::usage());
        return 0;
    }
    if (opts->showVersion) {
        std::cout << "douve-hub " << douve::kVersion << "\n";
        return 0;
    }
    if (opts->configPath.empty()) {
        std::cerr << douve::T("--config 가 필요합니다\n") << douve::T(douve::usage());
        return 2;
    }
    auto cfg = douve::loadConfigFile(opts->configPath, error);
    if (!cfg) {
        std::cerr << error << "\n";
        return 2;
    }
    if (opts->listenSet) {
        cfg->listenAddress = opts->listenAddress;
        cfg->listenPort = opts->listenPort;
    }

    douve::httpGlobalInit();
    if (!douve::httpsSupported()) {
        std::cerr << douve::T("libcurl에 TLS 지원이 없습니다 (Google 로그인 불가)\n");
        return 1;
    }
    std::unique_ptr<douve::HubApp> hub;
    try {
        hub = std::make_unique<douve::HubApp>(*cfg);
    } catch (const std::exception& e) {
        std::cerr << douve::T("초기화 실패: ") << e.what() << "\n";
        return 1;
    }
    hub->registerRoutes();
    hub->startBackgroundTasks();

    LOG_INFO << "douve-hub " << douve::kVersion << " listening on " << cfg->listenAddress << ":"
             << cfg->listenPort << " (public " << cfg->publicUrl << ")";
    drogon::app()
        .addListener(cfg->listenAddress, cfg->listenPort)
        .setThreadNum(2)
        .setServerHeaderField("douve")
        .setClientMaxWebSocketMessageSize(1024 * 1024)
        // 업로드 기능은 쓰지 않지만 Drogon이 시작 시 폴더를 만든다 → 쓰기 가능한 /tmp 아래로
        // (systemd PrivateTmp)
        .setUploadPath((std::filesystem::temp_directory_path() / "douve-uploads").string())
        // 처리 중 예외: JSON 값의 형식이 틀린 요청(예: 문자열 자리에 객체)은 400, 그 밖은 500.
        // 내부 오류 문구는 응답에 넣지 않는다.
        .setExceptionHandler([](const std::exception& e, const drogon::HttpRequestPtr& req,
                                std::function<void(const drogon::HttpResponsePtr&)>&& cb) {
            const bool badInput = dynamic_cast<const Json::Exception*>(&e) != nullptr;
            if (!badInput)
                LOG_ERROR << "요청 처리 실패 " << req->path() << ": " << e.what();
            Json::Value v;
            v["error"] = badInput ? "요청 형식이 올바르지 않습니다" : "서버 오류";
            auto r = drogon::HttpResponse::newHttpJsonResponse(v);
            r->setStatusCode(badInput ? drogon::k400BadRequest : drogon::k500InternalServerError);
            cb(r);
        })
        .run();
    return 0;
}
