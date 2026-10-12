#pragma once
// 실행 중인 앱 찾기: 노드 인벤토리(컨테이너·열린 포트)에서 "공개할 수 있는 것"을 뽑아
// 이름·아이콘·업스트림을 제안하고, 이미 서비스로 공개됐는지 표시한다.

#include "store/nodes.h"
#include "store/services.h"

#include <json/json.h>

#include <string>
#include <vector>

namespace douve {

// 한 노드의 앱 목록 (JSON 배열). 각 항목:
//   kind container|process, name, image, port, private_port, upstream, upstream_tls,
//   suggest_name, icon, loopback(127.0.0.1에만 열림 → 입구가 터널로), no_port(호스트에 포트 없음),
//   published: {id, name, host} | null
Json::Value discoverApps(const Node& node, const Json::Value& inventory,
                         const std::vector<Service>& services);

// "lscr.io/linuxserver/jellyfin:latest" → "jellyfin"
std::string iconFromImage(const std::string& image);
// 서비스 이름 규칙(영문 소문자·숫자·하이픈, 32자)에 맞춘다
std::string suggestName(const std::string& s);

} // namespace douve
