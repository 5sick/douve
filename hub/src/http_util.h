#pragma once
// 라우트 파일들이 공유하는 응답 도우미.

#include <drogon/HttpResponse.h>
#include <json/json.h>

#include <string>

namespace douve::http {

inline drogon::HttpResponsePtr json(const Json::Value& v,
                                    drogon::HttpStatusCode code = drogon::k200OK) {
    auto r = drogon::HttpResponse::newHttpJsonResponse(v);
    r->setStatusCode(code);
    r->addHeader("Cache-Control", "no-store");
    return r;
}

inline drogon::HttpResponsePtr error(drogon::HttpStatusCode code, const std::string& msg) {
    Json::Value v;
    v["error"] = msg;
    return json(v, code);
}

} // namespace douve::http
