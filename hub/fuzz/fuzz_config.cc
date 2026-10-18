// 설정 파일(hub.json) 파싱 퍼징
#include "config.h"

#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    std::string err;
    auto c = douve::parseConfig(std::string(reinterpret_cast<const char*>(data), size), err);
    if (c) {
        (void)c->origin();
        (void)c->effectiveRpId();
        (void)c->effectiveInternalUrl();
    }
    return 0;
}
