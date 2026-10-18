#pragma once
// 바깥에서 온 JSON(요청 본문, Agent·브라우저 WebSocket 메시지, 외부 서버 응답)을 읽는 유일한 통로.
// jsoncpp는 깊은 중첩·잘못된 입력에 예외를 던지는데, 이벤트 루프 안에서 던지면 Hub가 죽는다.

#include <json/json.h>

#include <string>
#include <string_view>

namespace douve {

// 실패하면(형식 오류·너무 깊은 중첩) false, out은 null. 예외를 던지지 않는다.
bool parseJson(std::string_view s, Json::Value& out, std::string* error = nullptr);

// 객체의 필드를 형식이 맞을 때만 읽는다 (asString 등은 형식이 다르면 예외를 던진다).
std::string jsonStr(const Json::Value& obj, const char* key, const std::string& fallback = "");
std::int64_t jsonInt(const Json::Value& obj, const char* key, std::int64_t fallback = 0);
bool jsonBool(const Json::Value& obj, const char* key, bool fallback = false);

} // namespace douve
