#pragma once
// douve-hub 명령줄 문구 번역: 환경 변수(DOUVE_LANG → LC_ALL → LC_MESSAGES → LANG)가 ko로 시작하면
// 한국어 그대로, 아니면 영어(web/i18n-en.json 사전). 원문은 한국어로 쓰고 T("...")로 감싼다.

#include "util/i18n.h"

#include <cctype>
#include <cstdlib>
#include <string>

namespace douve {

inline std::string cliLang() {
    for (const char* k : {"DOUVE_LANG", "LC_ALL", "LC_MESSAGES", "LANG"}) {
        const char* v = std::getenv(k);
        if (!v || !*v || std::string(v) == "C" || std::string(v) == "POSIX")
            continue;
        return (std::tolower(static_cast<unsigned char>(v[0])) == 'k' &&
                std::tolower(static_cast<unsigned char>(v[1])) == 'o')
                   ? "ko"
                   : "en";
    }
    return "en";
}

inline std::string T(const std::string& ko) {
    return i18n::translate(ko, cliLang());
}

} // namespace douve
