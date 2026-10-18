#include "util/json.h"

#include <memory>

namespace douve {

bool parseJson(std::string_view s, Json::Value& out, std::string* error) {
    out = Json::Value();
    Json::CharReaderBuilder b;
    b["stackLimit"] = 64;
    std::unique_ptr<Json::CharReader> reader(b.newCharReader());
    std::string err;
    try {
        if (reader->parse(s.data(), s.data() + s.size(), &out, &err))
            return true;
    } catch (const Json::Exception& e) {
        err = e.what();
    }
    out = Json::Value();
    if (error)
        *error = err;
    return false;
}

std::string jsonStr(const Json::Value& obj, const char* key, const std::string& fallback) {
    if (!obj.isObject())
        return fallback;
    const Json::Value& v = obj[key];
    return v.isString() ? v.asString() : fallback;
}

std::int64_t jsonInt(const Json::Value& obj, const char* key, std::int64_t fallback) {
    if (!obj.isObject())
        return fallback;
    const Json::Value& v = obj[key];
    return v.isInt64() ? v.asInt64() : fallback;
}

bool jsonBool(const Json::Value& obj, const char* key, bool fallback) {
    if (!obj.isObject())
        return fallback;
    const Json::Value& v = obj[key];
    return v.isBool() ? v.asBool() : fallback;
}

} // namespace douve
