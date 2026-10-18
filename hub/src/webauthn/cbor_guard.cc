#include "webauthn/cbor_guard.h"

namespace douve::webauthn {

namespace {

struct Reader {
    const std::uint8_t* p;
    std::size_t left;
};

// 머리(주 형식·추가 정보·인자)를 읽는다. 인자가 없는 무한 길이면 indefinite=true.
bool head(Reader& r, int& major, std::uint64_t& arg, bool& indefinite) {
    if (r.left < 1)
        return false;
    const std::uint8_t b = *r.p++;
    --r.left;
    major = b >> 5;
    const int info = b & 0x1f;
    indefinite = false;
    if (info < 24) {
        arg = static_cast<std::uint64_t>(info);
        return true;
    }
    if (info >= 28 && info <= 30)
        return false; // 예약
    if (info == 31) {
        indefinite = true;
        return major >= 2 &&
               major <= 5; // 무한 길이는 문자열·배열·맵만 (7의 31은 break라 따로 처리)
    }
    const std::size_t n = static_cast<std::size_t>(1) << (info - 24);
    if (r.left < n)
        return false;
    arg = 0;
    for (std::size_t i = 0; i < n; ++i)
        arg = (arg << 8) | r.p[i];
    r.p += n;
    r.left -= n;
    return true;
}

bool isBreak(const Reader& r) {
    return r.left >= 1 && *r.p == 0xff;
}

bool item(Reader& r, int depth) {
    if (depth < 0)
        return false;
    int major = 0;
    std::uint64_t arg = 0;
    bool indefinite = false;
    if (!head(r, major, arg, indefinite))
        return false;
    switch (major) {
    case 0:
    case 1:
    case 7:
        return true;
    case 2:
    case 3:
        if (indefinite) {
            // 같은 형식의 확정 길이 조각들 + break
            while (!isBreak(r)) {
                int m = 0;
                std::uint64_t n = 0;
                bool ind = false;
                if (!head(r, m, n, ind) || m != major || ind || n > r.left)
                    return false;
                r.p += n;
                r.left -= n;
            }
            ++r.p;
            --r.left;
            return true;
        }
        if (arg > r.left)
            return false;
        r.p += arg;
        r.left -= arg;
        return true;
    case 4:
    case 5: {
        const std::uint64_t per = major == 5 ? 2 : 1;
        if (indefinite) {
            while (!isBreak(r)) {
                for (std::uint64_t k = 0; k < per; ++k)
                    if (!item(r, depth - 1))
                        return false;
            }
            ++r.p;
            --r.left;
            return true;
        }
        // 원소마다 최소 1바이트: 선언된 개수가 남은 바이트보다 많으면 불가능
        if (arg > r.left / per)
            return false;
        for (std::uint64_t i = 0; i < arg * per; ++i)
            if (!item(r, depth - 1))
                return false;
        return true;
    }
    case 6:
        return item(r, depth - 1);
    }
    return false;
}

} // namespace

bool cborWithinBounds(const std::uint8_t* data, std::size_t len, int maxDepth) {
    if (!data || len == 0)
        return false;
    Reader r{data, len};
    return item(r, maxDepth);
}

} // namespace douve::webauthn
