// 사용자 입력 검사 퍼징: 서비스·링크·알림 채널 검사, 번역 패턴 매칭
#include "cluster/channels.h"
#include "store/services.h"
#include "util/i18n.h"

#include <fuzzer/FuzzedDataProvider.h>

using namespace douve;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    FuzzedDataProvider p(data, size);
    Service s;
    s.name = p.ConsumeRandomLengthString(80);
    s.host = p.ConsumeRandomLengthString(120);
    s.upstream = p.ConsumeRandomLengthString(80);
    s.auth = p.ConsumeBool() ? "douve" : p.ConsumeRandomLengthString(10);
    s.pathPrefix = p.ConsumeRandomLengthString(40);
    s.kind = p.ConsumeBool() ? "proxy" : "redirect";
    s.redirectTo = p.ConsumeRandomLengthString(120);
    s.hostHeader = p.ConsumeRandomLengthString(60);
    s.publicPaths.push_back(p.ConsumeRandomLengthString(40));
    (void)validateService(s, "douve.example.com");
    (void)isLoopbackUpstream(s.upstream);
    Link l;
    l.name = p.ConsumeRandomLengthString(80);
    l.url = p.ConsumeRandomLengthString(200);
    l.icon = p.ConsumeRandomLengthString(70);
    (void)validateLink(l);
    Channel c;
    static const char* kinds[] = {"ntfy", "discord", "slack", "webhook", "x"};
    c.kind = kinds[p.ConsumeIntegralInRange<int>(0, 4)];
    c.config["url"] = p.ConsumeRandomLengthString(200);
    c.config["topic"] = p.ConsumeRandomLengthString(70);
    c.config["server"] = p.ConsumeRandomLengthString(80);
    if (validateChannel(c).empty())
        (void)channelRequest(c, p.ConsumeRandomLengthString(300), 1);
    (void)i18n::translate(p.ConsumeRemainingBytesAsString(), "en");
    return 0;
}
