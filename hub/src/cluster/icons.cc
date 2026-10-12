#include "cluster/icons.h"

#include "net/https_client.h"
#include "util/crypto.h"
#include "util/encoding.h"

#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>

namespace douve {

namespace {
constexpr std::size_t kMaxIcon = 512 * 1024;
constexpr std::int64_t kNegativeTtl = 86400;
} // namespace

IconCache::IconCache(std::string dir) : dir_(std::move(dir)) {
    std::error_code ec;
    std::filesystem::create_directories(dir_, ec);
}

std::string IconCache::pathFor(const std::string& key) const {
    return dir_ + "/" + toHex(sha256(key)).substr(0, 32);
}

void IconCache::forget(const std::string& key) {
    std::error_code ec;
    std::filesystem::remove(pathFor(key), ec);
}

void IconCache::get(const std::string& key, const std::vector<std::string>& sources,
                    std::function<void(std::optional<IconData>)> cb) {
    const std::string p = pathFor(key);
    std::ifstream in(p, std::ios::binary);
    if (in) {
        std::string type;
        std::getline(in, type);
        std::stringstream ss;
        ss << in.rdbuf();
        if (type == "-") {
            // 실패 기록: 하루 지나면 다시 시도
            std::error_code ec;
            auto age = std::chrono::duration_cast<std::chrono::seconds>(
                           std::filesystem::file_time_type::clock::now() -
                           std::filesystem::last_write_time(p, ec))
                           .count();
            if (age < kNegativeTtl)
                return cb(std::nullopt);
        } else {
            return cb(IconData{type, ss.str()});
        }
    }
    tryNext(key, sources, 0, std::move(cb));
}

void IconCache::tryNext(std::string key, std::vector<std::string> sources, std::size_t i,
                        std::function<void(std::optional<IconData>)> cb) {
    if (i >= sources.size()) {
        std::ofstream(pathFor(key), std::ios::binary | std::ios::trunc) << "-\n";
        return cb(std::nullopt);
    }
    const std::string url = sources[i];
    httpFetchAsync(
        url, std::nullopt,
        [this, key = std::move(key), sources = std::move(sources), i,
         cb = std::move(cb)](HttpResult r) mutable {
            std::string type = r.contentType.substr(0, r.contentType.find(';'));
            // 일부 서버는 favicon.ico를 octet-stream으로 준다
            if (type == "application/octet-stream" && sources[i].ends_with(".ico"))
                type = "image/x-icon";
            if (r.ok && r.status == 200 && acceptableIcon(type, r.body)) {
                std::ofstream out(pathFor(key), std::ios::binary | std::ios::trunc);
                out << type << "\n" << r.body;
                return cb(IconData{type, r.body});
            }
            tryNext(std::move(key), std::move(sources), i + 1, std::move(cb));
        },
        5);
}

bool acceptableIcon(const std::string& type, const std::string& bytes) {
    static const std::set<std::string> ok = {
        "image/png",  "image/svg+xml", "image/x-icon", "image/vnd.microsoft.icon",
        "image/jpeg", "image/webp",    "image/gif"};
    return ok.count(type) && !bytes.empty() && bytes.size() <= kMaxIcon;
}

std::vector<std::string> iconNameGuesses(const std::string& name) {
    static const std::map<std::string, std::string> alias = {
        {"kuma", "uptime-kuma"},  {"next", "nextcloud"},     {"nc", "nextcloud"},
        {"ha", "home-assistant"}, {"pihole", "pi-hole"},     {"vault", "vaultwarden"},
        {"bw", "vaultwarden"},    {"git", "gitea"},          {"jelly", "jellyfin"},
        {"grafana", "grafana"},   {"portainer", "portainer"}};
    std::vector<std::string> out;
    auto it = alias.find(name);
    if (it != alias.end())
        out.push_back(it->second);
    out.push_back(name);
    return out;
}

std::string dashboardIconUrl(const std::string& name, bool svg) {
    return std::string("https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/") +
           (svg ? "svg/" : "png/") + name + (svg ? ".svg" : ".png");
}

} // namespace douve
