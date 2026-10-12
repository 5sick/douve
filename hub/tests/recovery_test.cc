#include "store/backup.h"
#include "store/recovery.h"
#include "store/repo.h"
#include "testing.h"

#include <filesystem>
#include <fstream>
#include <set>
#include <unistd.h>

using namespace douve;
namespace fs = std::filesystem;

TEST(recovery_codes_one_time_use) {
    Database db(":memory:");
    auto u = findOrCreateUser(db, "me@x.com", 1);
    auto other = findOrCreateUser(db, "you@x.com", 1);
    auto codes = generateRecoveryCodes(db, u.id, 100);
    CHECK(codes.size() == 10);
    std::set<std::string> uniq(codes.begin(), codes.end());
    CHECK(uniq.size() == 10);
    CHECK(codes[0].size() == 14 && codes[0][4] == '-' && codes[0][9] == '-');
    CHECK(recoveryStatus(db, u.id).remaining == 10);
    CHECK(recoveryStatus(db, u.id).createdAt == 100);

    // 대문자·공백·하이픈 없이 입력해도 같은 코드
    std::string typed;
    for (char c : codes[3])
        if (c != '-')
            typed += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    auto who = useRecoveryCode(db, " " + typed + " ", 200);
    CHECK(who && *who == u.id);
    CHECK(!useRecoveryCode(db, codes[3], 201)); // 한 번만
    CHECK(recoveryStatus(db, u.id).remaining == 9);
    CHECK(!useRecoveryCode(db, "aaaa-bbbb-cccc", 202));
    CHECK(!useRecoveryCode(db, "", 202));
    CHECK(!useRecoveryCode(db, codes[0] + "x", 202)); // 길이 다름

    // 다른 사용자 코드는 그 사용자
    auto oc = generateRecoveryCodes(db, other.id, 300);
    auto w2 = useRecoveryCode(db, oc[0], 301);
    CHECK(w2 && *w2 == other.id);

    // 새로 만들면 이전 코드는 모두 무효
    auto again = generateRecoveryCodes(db, u.id, 400);
    CHECK(!useRecoveryCode(db, codes[5], 401));
    CHECK(useRecoveryCode(db, again[5], 402).has_value());
    CHECK(recoveryStatus(db, u.id).remaining == 9);
    // DB에는 원문이 없다
    Statement q(db, "SELECT count(*) FROM recovery_codes WHERE code_hash = ?");
    q.bind(1, std::string(again[0]));
    CHECK(q.step() && q.int64(0) == 0);
}

TEST(backup_roundtrip) {
    const auto dir =
        fs::temp_directory_path() / ("douve-backup-test-" + std::to_string(::getpid()));
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto dbPath = (dir / "hub.db").string();
    const auto cfgPath = (dir / "hub.json").string();
    std::ofstream(cfgPath) << R"({"public_url":"https://douve.example.com"})";
    {
        Database db(dbPath);
        findOrCreateUser(db, "keep@x.com", 1);
        const auto out = (dir / "b1.db").string();
        CHECK(writeBackup(db, cfgPath, out, "v1", 500).empty());
        CHECK(!writeBackup(db, cfgPath, out, "v1", 500).empty()); // 덮어쓰지 않음
        CHECK((fs::status(out).permissions() & fs::perms::others_read) == fs::perms::none);
        std::string err;
        auto info = readBackupInfo(out, err);
        CHECK(info && info->version == "v1" && info->createdAt == 500);
        CHECK(info && info->config.find("douve.example.com") != std::string::npos);
        CHECK(!fs::exists(out + "-wal"));
        // 백업 뒤에 바뀐 내용은 복원하면 사라진다
        findOrCreateUser(db, "later@x.com", 2);
    }
    CHECK(restoreDatabase((dir / "b1.db").string(), dbPath, 600).empty());
    CHECK(fs::exists(dbPath + ".before-restore-600"));
    {
        Database db(dbPath);
        CHECK(findUserByEmail(db, "keep@x.com").has_value());
        CHECK(!findUserByEmail(db, "later@x.com").has_value());
        Statement q(db, "SELECT count(*) FROM sqlite_master WHERE name = 'douve_backup'");
        CHECK(q.step() && q.int64(0) == 0);
    }
    std::string err;
    std::ofstream(dir / "junk.db") << "not sqlite";
    CHECK(!readBackupInfo((dir / "junk.db").string(), err));
    // 자동 백업: 하루 하나, 최근 keep개
    {
        Database db(dbPath);
        const auto bdir = (dir / "backups").string();
        for (int d = 0; d < 5; ++d) {
            auto made = dailyBackup(db, cfgPath, bdir, "v1", 1700000000 + d * 86400, 3, err);
            CHECK(made.has_value());
        }
        CHECK(!dailyBackup(db, cfgPath, bdir, "v1", 1700000000 + 4 * 86400 + 60, 3, err));
        int n = 0;
        for (auto& e : fs::directory_iterator(bdir))
            n += e.path().filename().string().rfind("auto-", 0) == 0;
        CHECK(n == 3);
    }
    fs::remove_all(dir);
}

TEST(backup_reads_old_moat_format) {
    const auto dir = fs::temp_directory_path() / ("douve-oldbackup-" + std::to_string(::getpid()));
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto old = (dir / "old.db").string();
    {
        Database b(old);
        findOrCreateUser(b, "keep@x.com", 1);
        b.exec("CREATE TABLE moat_backup (key TEXT PRIMARY KEY, value TEXT NOT NULL)");
        b.exec("INSERT INTO moat_backup VALUES ('format','moat-backup-1'),('version','v0.1.0'),"
               "('created_at','42'),('hub.json','{}')");
        b.exec("PRAGMA journal_mode = DELETE");
    }
    std::string err;
    auto info = readBackupInfo(old, err);
    CHECK(info && info->version == "v0.1.0" && info->createdAt == 42);
    const auto dbPath = (dir / "hub.db").string();
    CHECK(restoreDatabase(old, dbPath, 7).empty());
    {
        Database db(dbPath);
        CHECK(findUserByEmail(db, "keep@x.com").has_value());
        Statement q(
            db, "SELECT count(*) FROM sqlite_master WHERE name IN ('moat_backup','douve_backup')");
        CHECK(q.step() && q.int64(0) == 0);
    }
    fs::remove_all(dir);
}
