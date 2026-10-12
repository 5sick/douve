#include "testing.h"

#include <cstring>

// 사용: douve_hub_tests [이름 필터]
int main(int argc, char** argv) {
    const char* filter = argc > 1 ? argv[1] : nullptr;
    int run = 0;
    for (auto& c : douve::testing::registry()) {
        if (filter && !std::strstr(c.name, filter))
            continue;
        int before = douve::testing::failures();
        c.fn();
        ++run;
        std::cout << (douve::testing::failures() == before ? "  ok   " : "  FAIL ") << c.name
                  << "\n";
    }
    std::cout << run << " tests, " << douve::testing::failures() << " failures\n";
    return douve::testing::failures() == 0 ? 0 : 1;
}
