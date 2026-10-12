#include "testing.h"
#include "util/i18n.h"

using namespace douve;

TEST(i18n_builtin_dictionary) {
    using i18n::translate;
    i18n::resetDictionary();
    CHECK(translate("로그인이 필요합니다", "ko") == "로그인이 필요합니다");
    CHECK_EQ(translate("로그인이 필요합니다", "en"), std::string("Sign-in required"));
    // 패턴 + 안쪽 재귀 (시간)
    CHECK_EQ(translate("🔴 [node1] 응답 없음 (마지막 접속 5분 전)", "en"),
             std::string("🔴 [node1] Not responding (last seen 5 min ago)"));
    CHECK_EQ(translate("✅ [node3] 해소: 메모리 사용률 91% (2시간 지속)", "en"),
             std::string("✅ [node3] Resolved: Memory usage 91% (lasted 2h)"));
    // 여러 줄 알림
    CHECK_EQ(translate("🛡️ [n2] 보안 이슈 2건\n• 🛡️ [n2] SSH 로그인: bob (1.2.3.4, publickey)\n확인: "
                       "https://m.example.com/security",
                       "en"),
             std::string("🛡️ [n2] 2 security issues\n• 🛡️ [n2] SSH login: bob (1.2.3.4, publickey)\n"
                         "Review: https://m.example.com/security"));
    // 사전에 없는 한국어·한국어 없는 문장은 그대로
    CHECK(translate("사전에 없는 문장", "en") == "사전에 없는 문장");
    CHECK(translate("plain text", "en") == "plain text");
    // " · " 나누기와 앞뒤 장식 유지
    CHECK_EQ(translate(" · 서비스 3개 · 응답 없음 1개", "en"),
             std::string(" · 3 services · 1 not responding"));
}

TEST(i18n_numeric_placeholder) {
    i18n::loadDictionary(R"({"{n}개": "{n} items", "{a} 님": "Mr. {a}"})");
    CHECK_EQ(i18n::translate("3개", "en"), std::string("3 items"));
    CHECK(i18n::translate("세개", "en") == "세개"); // 숫자만
    CHECK_EQ(i18n::translate("김 님", "en"), std::string("Mr. 김"));
    i18n::loadDictionary("{}");
    CHECK(i18n::translate("3개", "en") == "3개");
    i18n::resetDictionary();
}

TEST(i18n_plural) {
    i18n::resetDictionary();
    CHECK_EQ(i18n::translate("🛡️ [a] 보안 이슈 1건", "en"), std::string("🛡️ [a] 1 security issue"));
    CHECK_EQ(i18n::translate("🛡️ [a] 보안 이슈 3건", "en"), std::string("🛡️ [a] 3 security issues"));
}
