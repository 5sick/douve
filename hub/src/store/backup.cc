#include "store/backup.h"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

namespace douve {

namespace fs = std::filesystem;

namespace {

std::string sqlQuote(const std::string& s) {
    std::string out = "'";
    for (char c : s) {
        out += c;
        if (c == '\'')
            out += '\'';
    }
    return out + "'";
}

std::string readFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return {};
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::string ymd(std::int64_t now) {
    std::time_t t = static_cast<std::time_t>(now);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[16];
    std::strftime(buf, sizeof buf, "%Y%m%d", &tm);
    return buf;
}

} // namespace

std::string writeBackup(Database& db, const std::string& configPath, const std::string& outPath,
                        const std::string& version, std::int64_t now) {
    std::error_code ec;
    if (fs::exists(outPath, ec))
        return "이미 있는 파일입니다: " + outPath;
    const std::string tmp = outPath + ".partial";
    fs::remove(tmp, ec);
    try {
        {
            // 만들기 전에 권한부터 좁힌다 (비밀이 들어 있음)
            const mode_t old = umask(0077);
            try {
                auto guard = db.lock();
                db.exec("VACUUM INTO " + sqlQuote(tmp));
            } catch (...) {
                umask(old);
                throw;
            }
            umask(old);
        }
        {
            Database b(tmp);
            b.exec("CREATE TABLE douve_backup (key TEXT PRIMARY KEY, value TEXT NOT NULL)");
            auto put = [&](const std::string& k, const std::string& v) {
                Statement(b, "INSERT INTO douve_backup (key, value) VALUES (?, ?)")
                    .bind(1, k)
                    .bind(2, v)
                    .run();
            };
            put("format", "douve-backup-1");
            put("version", version);
            put("created_at", std::to_string(now));
            put("schema", std::to_string(b.schemaVersion()));
            if (!configPath.empty())
                put("hub.json", readFile(configPath));
            b.exec("PRAGMA journal_mode = DELETE"); // 파일 하나로 (WAL 파일 남기지 않음)
        }
        fs::remove(tmp + "-wal", ec);
        fs::remove(tmp + "-shm", ec);
        ::chmod(tmp.c_str(), 0600);
        fs::rename(tmp, outPath);
    } catch (const std::exception& e) {
        fs::remove(tmp, ec);
        fs::remove(tmp + "-wal", ec);
        fs::remove(tmp + "-shm", ec);
        return std::string("백업 실패: ") + e.what();
    }
    return {};
}

std::optional<BackupInfo> readBackupInfo(const std::string& path, std::string& error) {
    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) {
        error = "백업 파일이 없습니다: " + path;
        return std::nullopt;
    }
    try {
        // 원본을 건드리지 않게 복사본을 연다 (Database는 열 때 WAL·마이그레이션을 건다)
        const std::string tmp = path + ".inspect";
        fs::copy_file(path, tmp, fs::copy_options::overwrite_existing);
        BackupInfo info;
        bool ok = false;
        {
            Database b(tmp);
            // 이름을 바꾸기 전(Moat) 백업도 읽는다: 표 moat_backup, 형식 moat-backup-1
            Statement t(b, "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN "
                           "('douve_backup', 'moat_backup') ORDER BY name LIMIT 1");
            const std::string table = t.step() ? t.text(0) : "douve_backup";
            Statement q(b, "SELECT key, value FROM " + table);
            while (q.step()) {
                const auto k = q.text(0), v = q.text(1);
                if (k == "format")
                    ok = v == "douve-backup-1" || v == "moat-backup-1";
                else if (k == "hub.json")
                    info.config = v;
                else if (k == "version")
                    info.version = v;
                else if (k == "created_at")
                    info.createdAt = std::atoll(v.c_str());
                else if (k == "schema")
                    info.schema = std::atoi(v.c_str());
            }
        }
        fs::remove(tmp, ec);
        fs::remove(tmp + "-wal", ec);
        fs::remove(tmp + "-shm", ec);
        if (!ok) {
            error = "Douve 백업 파일이 아닙니다";
            return std::nullopt;
        }
        return info;
    } catch (const std::exception& e) {
        error = std::string("백업 파일을 읽을 수 없습니다: ") + e.what();
        std::error_code ec2;
        fs::remove(path + ".inspect", ec2);
        return std::nullopt;
    }
}

std::string restoreDatabase(const std::string& backupPath, const std::string& dbPath,
                            std::int64_t now) {
    std::error_code ec;
    const std::string staged = dbPath + ".restoring";
    try {
        fs::create_directories(fs::path(dbPath).parent_path(), ec);
        fs::copy_file(backupPath, staged, fs::copy_options::overwrite_existing);
        {
            Database b(staged); // 이 douve-hub보다 새 스키마면 여기서 실패
            b.exec("DROP TABLE IF EXISTS douve_backup");
            b.exec("DROP TABLE IF EXISTS moat_backup");
            b.exec("PRAGMA wal_checkpoint(TRUNCATE)");
        }
        fs::remove(staged + "-wal", ec);
        fs::remove(staged + "-shm", ec);
        if (fs::exists(dbPath)) {
            const std::string keep = dbPath + ".before-restore-" + std::to_string(now);
            fs::rename(dbPath, keep);
            for (const char* sfx : {"-wal", "-shm"})
                if (fs::exists(dbPath + sfx))
                    fs::rename(dbPath + sfx, keep + sfx);
        }
        // 원래 DB 파일 소유자(DynamicUser)에 맞춘다 — 디렉터리 소유자를 따른다
        struct stat st{};
        if (::stat(fs::path(dbPath).parent_path().c_str(), &st) == 0)
            (void)::chown(staged.c_str(), st.st_uid, st.st_gid);
        ::chmod(staged.c_str(), 0600);
        fs::rename(staged, dbPath);
    } catch (const std::exception& e) {
        fs::remove(staged, ec);
        fs::remove(staged + "-wal", ec);
        fs::remove(staged + "-shm", ec);
        return std::string("복원 실패: ") + e.what();
    }
    return {};
}

std::optional<std::string> dailyBackup(Database& db, const std::string& configPath,
                                       const std::string& dir, const std::string& version,
                                       std::int64_t now, int keep, std::string& error) {
    std::error_code ec;
    fs::create_directories(dir, ec);
    ::chmod(dir.c_str(), 0700);
    const std::string path = (fs::path(dir) / ("auto-" + ymd(now) + ".db")).string();
    std::optional<std::string> made;
    if (!fs::exists(path, ec)) {
        error = writeBackup(db, configPath, path, version, now);
        if (!error.empty())
            return std::nullopt;
        made = path;
    }
    std::vector<std::string> autos;
    for (const auto& e : fs::directory_iterator(dir, ec)) {
        const auto name = e.path().filename().string();
        if (name.rfind("auto-", 0) == 0 && name.size() == 16 && name.substr(13) == ".db")
            autos.push_back(e.path().string());
    }
    std::sort(autos.begin(), autos.end());
    for (std::size_t i = 0; i + keep < autos.size(); ++i)
        fs::remove(autos[i], ec);
    return made;
}

} // namespace douve
