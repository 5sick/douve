#pragma once
// 의존성 없는 최소 테스트 하네스. TEST(이름) { CHECK(...); } 형태로 작성한다.

#include <functional>
#include <iostream>
#include <string>
#include <vector>

namespace douve::testing {

struct Case {
    const char* name;
    std::function<void()> fn;
};

inline std::vector<Case>& registry() {
    static std::vector<Case> cases;
    return cases;
}

inline int& failures() {
    static int n = 0;
    return n;
}

struct Registrar {
    Registrar(const char* name, std::function<void()> fn) {
        registry().push_back({name, std::move(fn)});
    }
};

inline void fail(const char* file, int line, const std::string& what) {
    std::cerr << file << ":" << line << ": FAIL: " << what << "\n";
    ++failures();
}

} // namespace douve::testing

#define DOUVE_CONCAT2(a, b) a##b
#define DOUVE_CONCAT(a, b) DOUVE_CONCAT2(a, b)
#define TEST(name)                                                                                 \
    static void DOUVE_CONCAT(test_, name)();                                                       \
    static ::douve::testing::Registrar DOUVE_CONCAT(reg_, name)(#name, DOUVE_CONCAT(test_, name)); \
    static void DOUVE_CONCAT(test_, name)()
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond))                                                                               \
            ::douve::testing::fail(__FILE__, __LINE__, #cond);                                     \
    } while (0)
#define CHECK_EQ(a, b)                                                                             \
    do {                                                                                           \
        if (!((a) == (b)))                                                                         \
            ::douve::testing::fail(__FILE__, __LINE__, #a " == " #b);                              \
    } while (0)
