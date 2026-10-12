#pragma once
// 한국어 원문 → 영어 번역 (웹과 같은 사전 web/i18n-en.json, 바이너리에 내장).
// 키의 {이름}은 패턴({n}·{m}은 숫자만), 통째로 없으면 줄·" · " 단위로 나눠 번역한다.
// 규칙은 web/i18n.js의 tr()과 같다 — 한쪽을 바꾸면 다른 쪽도.

#include <string>

namespace douve::i18n {

// lang이 "en"이 아니면 그대로 돌려준다.
std::string translate(const std::string& text, const std::string& lang);

// 사전 원문(JSON)으로 번역기를 다시 만든다 (시험용). 보통은 내장 사전을 처음 쓸 때 읽는다.
void loadDictionary(const std::string& json);
// 내장 사전으로 되돌린다 (시험용)
void resetDictionary();

} // namespace douve::i18n
