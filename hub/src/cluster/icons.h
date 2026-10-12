#pragma once
// 홈 화면 아이콘: 후보 주소를 차례로 받아 첫 번째로 성공한 이미지를 디스크에 캐시한다.
// (브라우저 CSP는 img-src 'self'라 외부 이미지를 직접 쓰지 않고 Hub가 대신 받아 준다)

#include <functional>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace douve {

struct IconData {
    std::string contentType;
    std::string bytes;
};

class IconCache {
  public:
    explicit IconCache(std::string dir);
    // 캐시에 있으면 즉시, 없으면 sources를 차례로 받아 본다. 모두 실패하면 nullopt (하루 동안 다시
    // 시도 안 함).
    void get(const std::string& key, const std::vector<std::string>& sources,
             std::function<void(std::optional<IconData>)> cb);
    void forget(const std::string& key);

  private:
    void tryNext(std::string key, std::vector<std::string> sources, std::size_t i,
                 std::function<void(std::optional<IconData>)> cb);
    std::string pathFor(const std::string& key) const;
    std::string dir_;
};

// 이름으로 dashboard-icons 후보 이름을 고른다 (예: kuma → uptime-kuma)
std::vector<std::string> iconNameGuesses(const std::string& name);
std::string dashboardIconUrl(const std::string& name, bool svg);
// 응답이 아이콘으로 쓸 수 있는 이미지인지 (형식·크기)
bool acceptableIcon(const std::string& contentType, const std::string& bytes);

} // namespace douve
