#include "util/i18n.h"

#include "assets.h"

#include <json/json.h>

#include <algorithm>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <vector>

namespace douve::i18n {

namespace {

// "{a}을(를) 지울까요?" → 조각: [자리 a][글자 "을(를) 지울까요?"]
struct Piece {
    bool hole = false;
    std::string text; // hole이면 이름
};
struct Pattern {
    std::vector<Piece> pieces;
    std::vector<std::string> names;
    std::string out;
    std::size_t len = 0;
};

bool isDigits(const std::string& s) {
    if (s.empty())
        return false;
    bool digit = false;
    for (char c : s) {
        if (c >= '0' && c <= '9')
            digit = true;
        else if (c != '.' && c != ',')
            return false;
    }
    return digit && s.front() >= '0' && s.front() <= '9';
}

// 앞에서부터 짧은 것 먼저 맞춰 보는 백트래킹 (자바스크립트 정규식의 (.+?)와 같은 결과)
bool matchFrom(const std::vector<Piece>& ps, std::size_t pi, const std::string& s, std::size_t si,
               std::vector<std::string>& caps) {
    if (pi == ps.size())
        return si == s.size();
    const Piece& p = ps[pi];
    if (!p.hole) {
        if (s.compare(si, p.text.size(), p.text) != 0)
            return false;
        return matchFrom(ps, pi + 1, s, si + p.text.size(), caps);
    }
    const bool numeric = p.text == "n" || p.text == "m";
    for (std::size_t end = si + 1; end <= s.size(); ++end) {
        // UTF-8 글자 중간에서 자르지 않는다
        if (end < s.size() && (static_cast<unsigned char>(s[end]) & 0xC0) == 0x80)
            continue;
        std::string cap = s.substr(si, end - si);
        if (numeric && !isDigits(cap))
            continue;
        caps.push_back(cap);
        if (matchFrom(ps, pi + 1, s, end, caps))
            return true;
        caps.pop_back();
    }
    return false;
}

struct Dictionary {
    std::map<std::string, std::string> exact;
    std::vector<Pattern> patterns;
};

std::mutex mu;
std::shared_ptr<const Dictionary> current;

bool hasHangul(const std::string& s) {
    // 한글 음절 U+AC00–U+D7A3: UTF-8 첫 바이트 0xEA–0xED
    for (std::size_t i = 0; i + 2 < s.size(); ++i) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (c >= 0xEA && c <= 0xED) {
            const unsigned cp = ((c & 0x0F) << 12) |
                                ((static_cast<unsigned char>(s[i + 1]) & 0x3F) << 6) |
                                (static_cast<unsigned char>(s[i + 2]) & 0x3F);
            if (cp >= 0xAC00 && cp <= 0xD7A3)
                return true;
        }
    }
    return false;
}

// "{이름}" 위치를 찾아 조각으로 나눈다. 자리가 없으면 빈 벡터.
std::vector<Piece> split(const std::string& k) {
    std::vector<Piece> out;
    std::size_t i = 0, lit = 0;
    bool any = false;
    while (i < k.size()) {
        if (k[i] == '{') {
            std::size_t j = i + 1;
            while (j < k.size() && (std::isalnum(static_cast<unsigned char>(k[j])) || k[j] == '_'))
                ++j;
            if (j < k.size() && k[j] == '}' && j > i + 1) {
                if (i > lit)
                    out.push_back({false, k.substr(lit, i - lit)});
                out.push_back({true, k.substr(i + 1, j - i - 1)});
                any = true;
                i = lit = j + 1;
                continue;
            }
        }
        ++i;
    }
    if (!any)
        return {};
    if (lit < k.size())
        out.push_back({false, k.substr(lit)});
    return out;
}

std::shared_ptr<const Dictionary> build(const std::string& json) {
    auto d = std::make_shared<Dictionary>();
    Json::Value root;
    Json::CharReaderBuilder b;
    std::string errs;
    std::istringstream in(json);
    if (!Json::parseFromStream(b, in, &root, &errs) || !root.isObject())
        return d;
    for (const auto& k : root.getMemberNames()) {
        if (k.empty() || k[0] == '_' || !root[k].isString())
            continue;
        auto pieces = split(k);
        if (pieces.empty()) {
            d->exact.emplace(k, root[k].asString());
            continue;
        }
        Pattern p;
        for (const auto& pc : pieces)
            if (pc.hole)
                p.names.push_back(pc.text);
        p.pieces = std::move(pieces);
        p.out = root[k].asString();
        p.len = k.size();
        d->patterns.push_back(std::move(p));
    }
    std::stable_sort(d->patterns.begin(), d->patterns.end(),
                     [](const Pattern& a, const Pattern& b) { return a.len > b.len; });
    return d;
}

std::shared_ptr<const Dictionary> dict() {
    std::lock_guard lk(mu);
    if (!current) {
        const auto* a = assets::find("i18n-en.json");
        current = build(a ? std::string(reinterpret_cast<const char*>(a->data), a->size) : "{}");
    }
    return current;
}

bool isDecor(char c) {
    return c == ' ' || c == '\t' || c == '\n';
}

std::string tr(const Dictionary& d, const std::string& s, int depth) {
    if (depth > 5 || !hasHangul(s))
        return s;
    // 앞뒤 공백·가운뎃점(U+00B7 = C2 B7)은 그대로 두고 가운데만 번역
    std::size_t a = 0, b = s.size();
    auto midDotAt = [&](std::size_t i) {
        return i + 1 < s.size() && static_cast<unsigned char>(s[i]) == 0xC2 &&
               static_cast<unsigned char>(s[i + 1]) == 0xB7;
    };
    while (a < b && (isDecor(s[a]) || midDotAt(a)))
        a += midDotAt(a) ? 2 : 1;
    while (b > a && (isDecor(s[b - 1]) || (b >= 2 && midDotAt(b - 2))))
        b -= (b >= 2 && midDotAt(b - 2)) ? 2 : 1;
    const std::string core = s.substr(a, b - a);
    if (core.empty())
        return s;
    std::optional<std::string> r;
    if (auto it = d.exact.find(core); it != d.exact.end())
        r = it->second;
    auto splitJoin = [&](const std::string& sep) {
        std::string out;
        std::size_t start = 0;
        while (true) {
            auto i = core.find(sep, start);
            out += tr(d, core.substr(start, i == std::string::npos ? std::string::npos : i - start),
                      depth + 1);
            if (i == std::string::npos)
                break;
            out += sep;
            start = i + sep.size();
        }
        return out;
    };
    if (!r && core.find('\n') != std::string::npos)
        r = splitJoin("\n");
    if (!r) {
        for (const auto& p : d.patterns) {
            std::vector<std::string> caps;
            if (!matchFrom(p.pieces, 0, core, 0, caps))
                continue;
            // 값 조립: {이름}은 번역한 캡처, {n|단수|복수}는 n이 1이면 단수
            std::string out;
            const std::string& v = p.out;
            for (std::size_t i = 0; i < v.size();) {
                if (v[i] == '{') {
                    const auto close = v.find('}', i);
                    if (close != std::string::npos) {
                        const std::string inner = v.substr(i + 1, close - i - 1);
                        const auto bar = inner.find('|');
                        const std::string name = inner.substr(0, bar);
                        const auto pos = std::find(p.names.begin(), p.names.end(), name);
                        if (pos != p.names.end()) {
                            const std::string& cap = caps[pos - p.names.begin()];
                            if (bar == std::string::npos) {
                                out += tr(d, cap, depth + 1);
                            } else {
                                const auto bar2 = inner.find('|', bar + 1);
                                const std::string one = inner.substr(bar + 1, bar2 - bar - 1);
                                const std::string many =
                                    bar2 == std::string::npos ? one : inner.substr(bar2 + 1);
                                out += cap == "1" ? one : many;
                            }
                            i = close + 1;
                            continue;
                        }
                    }
                }
                out += v[i++];
            }
            r = out;
            break;
        }
    }
    if (!r && core.find(" \xC2\xB7 ") != std::string::npos)
        r = splitJoin(" \xC2\xB7 ");
    return r ? s.substr(0, a) + *r + s.substr(b) : s;
}

} // namespace

void loadDictionary(const std::string& json) {
    auto d = build(json);
    std::lock_guard lk(mu);
    current = d;
}

void resetDictionary() {
    std::lock_guard lk(mu);
    current.reset();
}

std::string translate(const std::string& text, const std::string& lang) {
    if (lang != "en")
        return text;
    return tr(*dict(), text, 0);
}

} // namespace douve::i18n
