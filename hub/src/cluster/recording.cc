#include "cluster/recording.h"

#include <json/json.h>

namespace douve {

std::string takeCompleteUtf8(std::string& carry, const std::string& chunk) {
    std::string s = carry + chunk;
    carry.clear();
    // 끝에서 최대 3바이트를 보고 시작 바이트가 요구하는 길이보다 짧으면 잘라 둔다
    std::size_t n = s.size();
    for (std::size_t back = 1; back <= 3 && back <= n; ++back) {
        const unsigned char c = static_cast<unsigned char>(s[n - back]);
        if ((c & 0xC0) == 0x80)
            continue; // 이어지는 바이트
        std::size_t need = (c & 0xE0) == 0xC0   ? 2
                           : (c & 0xF0) == 0xE0 ? 3
                           : (c & 0xF8) == 0xF0 ? 4
                                                : 1;
        if (need > back) {
            carry = s.substr(n - back);
            s.resize(n - back);
        }
        break;
    }
    return s;
}

namespace {
std::string compact(const Json::Value& v) {
    Json::StreamWriterBuilder w;
    w["indentation"] = "";
    w["emitUTF8"] = true;
    return Json::writeString(w, v);
}
} // namespace

Recorder::Recorder(const std::string& path, int cols, int rows, std::int64_t startUnix,
                   const std::string& title)
    : out_(path, std::ios::out | std::ios::trunc) {
    ok_ = static_cast<bool>(out_);
    if (!ok_)
        return;
    Json::Value h;
    h["version"] = 2;
    h["width"] = cols;
    h["height"] = rows;
    h["timestamp"] = Json::Int64(startUnix);
    h["title"] = title;
    h["env"]["TERM"] = "xterm-256color";
    line(compact(h));
}

void Recorder::line(const std::string& json) {
    if (!ok_ || truncated_)
        return;
    if (written_ + json.size() + 1 > kMaxBytes) {
        truncated_ = true;
        out_ << "[0, \"o\", \"\\r\\n[Douve: 녹화 용량 한도(20MB)에 도달해 이후는 기록하지 "
                "않음]\\r\\n\"]\n";
        out_.flush();
        return;
    }
    out_ << json << '\n';
    written_ += json.size() + 1;
}

void Recorder::output(const std::string& bytes, double t) {
    std::string text = takeCompleteUtf8(carry_, bytes);
    if (text.empty())
        return;
    Json::Value e(Json::arrayValue);
    e.append(t);
    e.append("o");
    e.append(text);
    line(compact(e));
}

void Recorder::resize(int cols, int rows, double t) {
    Json::Value e(Json::arrayValue);
    e.append(t);
    e.append("r");
    e.append(std::to_string(cols) + "x" + std::to_string(rows));
    line(compact(e));
}

} // namespace douve
