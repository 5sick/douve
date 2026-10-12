#pragma once
// Hub 백업: DB 전체(VACUUM INTO) + 설정 파일 원문을 SQLite 파일 하나에 담는다.
// 비밀(세션 해시·텔레그램 토큰·Agent 키)이 들어 있으니 권한 600, 서버 밖 안전한 곳에 보관.

#include "store/db.h"

#include <cstdint>
#include <optional>
#include <string>

namespace douve {

// outPath가 이미 있으면 실패. 성공하면 빈 문자열, 아니면 이유.
std::string writeBackup(Database& db, const std::string& configPath, const std::string& outPath,
                        const std::string& version, std::int64_t now);

struct BackupInfo {
    std::string config; // hub.json 원문 (없을 수 있음)
    std::string version;
    std::int64_t createdAt = 0;
    int schema = 0;
};
// 백업 파일을 읽는다 (Douve 백업이 아니면 nullopt + error)
std::optional<BackupInfo> readBackupInfo(const std::string& path, std::string& error);

// 백업을 DB 경로에 복원한다: 기존 DB·WAL을 <db>.before-restore-<시각>으로 옮기고 백업을 복사(백업
// 표 제거). Hub가 꺼져 있어야 한다. 성공하면 빈 문자열.
std::string restoreDatabase(const std::string& backupPath, const std::string& dbPath,
                            std::int64_t now);

// 자동 백업: dir/auto-YYYYMMDD.db 하루 하나, 최근 keep개만 남긴다. 만들었으면 경로.
std::optional<std::string> dailyBackup(Database& db, const std::string& configPath,
                                       const std::string& dir, const std::string& version,
                                       std::int64_t now, int keep, std::string& error);

} // namespace douve
