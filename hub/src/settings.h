#pragma once
// 웹에서 바꾸는 설정 (Google 로그인, 텔레그램). 기본값은 hub.json, 웹에서 저장하면 DB(settings)가
// 우선. 여러 스레드가 읽으므로 뮤텍스로 보호하고 복사본을 돌려준다.

#include "config.h"
#include "store/db.h"

#include <json/json.h>

#include <mutex>
#include <string>

namespace douve {

struct Credentials {
    std::string googleClientId, googleClientSecret;
    std::string telegramBotToken, telegramChatId;
    bool googleEnabled() const { return !googleClientId.empty() && !googleClientSecret.empty(); }
    bool telegramEnabled() const { return !telegramBotToken.empty() && !telegramChatId.empty(); }
};

// 켜고 끌 수 있는 기능. Hub 설정이 기준이고 Agent는 접속할 때·바뀔 때 받아서 따른다.
struct Features {
    bool monitoring = true;    // 리소스 모니터링 (CPU·메모리·디스크·네트워크, 관련 알림)
    bool serviceChecks = true; // 서비스 상태 확인·알림
    bool terminal = true;      // 웹 터미널
    // 보안 감시 항목
    bool secSsh = true, secSudo = true, secAccount = true, secFiles = true, secPorts = true;

    Json::Value toJson() const;
    static Features fromJson(const Json::Value& v);
};

class RuntimeSettings {
  public:
    Features features() const;
    void saveFeatures(Database& db, const Features& f, std::int64_t now);
    // 설정 파일 값 위에 DB에 저장된 값을 덮어 읽는다.
    void load(const HubConfig& cfg, Database& db);
    Credentials get() const;
    // DB에 저장하고 적용한다. 빈 값은 "설정 파일 값으로 되돌림"(DB 항목 삭제).
    void save(Database& db, const HubConfig& cfg, const Credentials& c, std::int64_t now);

  private:
    mutable std::mutex mu_;
    Credentials c_;
    Features f_;
};

// 입력 형식 검사 (빈 값 허용). 문제가 있으면 이유.
std::string validateTelegram(const std::string& botToken, const std::string& chatId);
std::string validateGoogle(const std::string& clientId, const std::string& clientSecret);

} // namespace douve
