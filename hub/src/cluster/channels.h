#pragma once
// 알림 채널: 텔레그램 말고도 ntfy, Discord, Slack, 일반 웹훅으로 같은 알림을 보낸다.

#include "net/https_client.h"
#include "store/db.h"

#include <json/json.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace douve {

struct Channel {
    std::int64_t id = 0;
    std::string kind; // ntfy | discord | slack | webhook
    std::string name;
    Json::Value config; // ntfy: server, topic, token / discord·slack: url / webhook: url, secret
    bool enabled = true;
    std::int64_t createdAt = 0;
};

// 입력 검사·정규화 (기본값 채움). 문제가 있으면 이유.
std::string validateChannel(Channel& c);

std::vector<Channel> listChannels(Database& db);
std::optional<Channel> findChannel(Database& db, std::int64_t id);
std::int64_t createChannel(Database& db, const Channel& c, std::int64_t now);
bool deleteChannel(Database& db, std::int64_t id);
bool setChannelEnabled(Database& db, std::int64_t id, bool enabled);

// 화면용: 비밀(웹훅 주소·토큰·ntfy 토픽)은 일부만
Json::Value channelJson(const Channel& c);

// 보낼 요청 (now: 웹훅 서명 시각)
HttpPost channelRequest(const Channel& c, const std::string& text, std::int64_t now);

} // namespace douve
