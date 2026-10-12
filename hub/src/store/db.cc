#include "store/db.h"

#include <sqlite3.h>

#include <vector>

namespace douve {
namespace {

// 스키마 마이그레이션. 순서대로 적용되며, 이미 배포된 항목은 절대 수정하지 않고 새 항목을 추가한다.
const std::vector<const char*> kMigrations = {
    // v1: 1단계 로그인 관문
    R"sql(
    CREATE TABLE users (
        id            INTEGER PRIMARY KEY,
        email         TEXT NOT NULL UNIQUE,
        created_at    INTEGER NOT NULL,
        last_login_at INTEGER
    );
    CREATE TABLE passkeys (
        id              INTEGER PRIMARY KEY,
        user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        credential_id   BLOB NOT NULL UNIQUE,
        public_key_cose BLOB NOT NULL,
        sign_count      INTEGER NOT NULL DEFAULT 0,
        name            TEXT NOT NULL,
        transports      TEXT NOT NULL DEFAULT '',
        created_at      INTEGER NOT NULL,
        last_used_at    INTEGER
    );
    CREATE INDEX passkeys_user ON passkeys(user_id);
    CREATE TABLE sessions (
        token_hash          BLOB PRIMARY KEY,
        user_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        auth_method         TEXT NOT NULL,
        created_at          INTEGER NOT NULL,
        last_seen_at        INTEGER NOT NULL,
        idle_expires_at     INTEGER NOT NULL,
        absolute_expires_at INTEGER NOT NULL,
        reauth_at           INTEGER NOT NULL,
        ip                  TEXT NOT NULL DEFAULT '',
        user_agent          TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX sessions_user ON sessions(user_id);
    -- WebAuthn 챌린지·OIDC 상태처럼 짧게 쓰고 버리는 1회용 값
    CREATE TABLE pending (
        id         TEXT PRIMARY KEY,
        kind       TEXT NOT NULL,
        payload    TEXT NOT NULL,
        expires_at INTEGER NOT NULL
    );
    CREATE TABLE audit_log (
        id      INTEGER PRIMARY KEY,
        ts      INTEGER NOT NULL,
        user_id INTEGER,
        event   TEXT NOT NULL,
        ip      TEXT NOT NULL DEFAULT '',
        detail  TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX audit_ts ON audit_log(ts);
    )sql",
    // v2: 2단계 에이전트·클러스터
    R"sql(
    CREATE TABLE nodes (
        id            INTEGER PRIMARY KEY,
        name          TEXT NOT NULL UNIQUE,
        pubkey        BLOB NOT NULL UNIQUE,          -- Agent Ed25519 공개키 (32바이트)
        hostname      TEXT NOT NULL DEFAULT '',
        os            TEXT NOT NULL DEFAULT '',
        arch          TEXT NOT NULL DEFAULT '',
        agent_version TEXT NOT NULL DEFAULT '',
        created_at    INTEGER NOT NULL,
        last_seen_at  INTEGER,
        last_ip       TEXT NOT NULL DEFAULT '',
        inventory     TEXT NOT NULL DEFAULT '{}'     -- 마지막 인벤토리(JSON)
    );
    CREATE TABLE join_tokens (
        token_hash BLOB PRIMARY KEY,
        name       TEXT NOT NULL DEFAULT '',          -- 미리 정한 노드 이름 (비면 hostname)
        created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at    INTEGER,
        node_id    INTEGER REFERENCES nodes(id) ON DELETE SET NULL
    );
    -- 1분 평균. 30일 보관.
    CREATE TABLE metrics (
        node_id    INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
        ts         INTEGER NOT NULL,
        cpu        REAL NOT NULL,     -- %
        mem_used   INTEGER NOT NULL,  -- 바이트
        mem_total  INTEGER NOT NULL,
        swap_used  INTEGER NOT NULL,
        swap_total INTEGER NOT NULL,
        disk_used  INTEGER NOT NULL,  -- 루트 파일시스템
        disk_total INTEGER NOT NULL,
        net_rx     REAL NOT NULL,     -- 바이트/초
        net_tx     REAL NOT NULL,
        load1      REAL NOT NULL,
        PRIMARY KEY (node_id, ts)
    ) WITHOUT ROWID;
    CREATE TABLE alerts (
        id          INTEGER PRIMARY KEY,
        node_id     INTEGER REFERENCES nodes(id) ON DELETE CASCADE,
        rule        TEXT NOT NULL,    -- 예: offline, disk:/, unit:nginx.service
        message     TEXT NOT NULL,
        started_at  INTEGER NOT NULL,
        resolved_at INTEGER
    );
    CREATE INDEX alerts_open ON alerts(node_id, rule) WHERE resolved_at IS NULL;
    )sql",
    // v3: 3단계 입구(edge)·서비스 등록
    R"sql(
    ALTER TABLE nodes ADD COLUMN edge INTEGER NOT NULL DEFAULT 0;      -- 입구 역할 (공개 HTTPS 프록시)
    ALTER TABLE nodes ADD COLUMN mesh_address TEXT NOT NULL DEFAULT ''; -- WireGuard 주소 (업스트림 기본값)
    CREATE TABLE services (
        id           INTEGER PRIMARY KEY,
        name         TEXT NOT NULL UNIQUE,
        host         TEXT NOT NULL UNIQUE,              -- 공개 도메인
        node_id      INTEGER REFERENCES nodes(id) ON DELETE SET NULL, -- 서비스가 도는 노드 (상태 확인·알림용)
        upstream     TEXT NOT NULL,                     -- host:port (메시 주소)
        auth         TEXT NOT NULL DEFAULT 'douve',      -- douve(로그인 필요) | public
        public_paths TEXT NOT NULL DEFAULT '[]',        -- 로그인 없이 허용할 경로 접두사(JSON 배열)
        created_at   INTEGER NOT NULL,
        updated_at   INTEGER NOT NULL
    );
    )sql",
    // v4: 5단계 초대(패스키로 시작)·웹 설정
    R"sql(
    ALTER TABLE users ADD COLUMN allowed INTEGER NOT NULL DEFAULT 0; -- 초대로 허용된 사용자
    CREATE TABLE invites (
        token_hash BLOB PRIMARY KEY,
        email      TEXT NOT NULL,
        created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at    INTEGER
    );
    -- 웹에서 바꾸는 설정 (텔레그램, Google 등). 설정 파일 값보다 우선.
    CREATE TABLE settings (
        key        TEXT PRIMARY KEY,
        value      TEXT NOT NULL,
        updated_at INTEGER NOT NULL
    );
    )sql",
    // v5: 보안 감시 (사건 기록 + 지문별 이슈 상태)
    R"sql(
    CREATE TABLE security_events (
        id          INTEGER PRIMARY KEY,
        node_id     INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
        ts          INTEGER NOT NULL,
        kind        TEXT NOT NULL,
        severity    TEXT NOT NULL,              -- info | warn | crit
        fingerprint TEXT NOT NULL,
        summary     TEXT NOT NULL,
        fields      TEXT NOT NULL DEFAULT '{}',
        via         TEXT NOT NULL DEFAULT '',   -- Douve 터미널 사용자(이메일) 등 출처
        status      TEXT NOT NULL               -- open | ignored | auto | info
    );
    CREATE INDEX security_events_ts ON security_events(ts);
    CREATE TABLE security_issues (
        fingerprint TEXT PRIMARY KEY,
        node_id     INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
        kind        TEXT NOT NULL,
        severity    TEXT NOT NULL,
        summary     TEXT NOT NULL,
        first_seen  INTEGER NOT NULL,
        last_seen   INTEGER NOT NULL,
        count       INTEGER NOT NULL DEFAULT 1,
        status      TEXT NOT NULL,              -- open | acked(확인함, 다시 생기면 알림) | ignored(문제 없음, 앞으로 무시)
        acked_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
        acked_at    INTEGER,
        notified_at INTEGER
    );
    )sql",
    // v6: 홈 화면 (서비스 그룹·설명·아이콘, 외부 링크)
    R"sql(
    ALTER TABLE services ADD COLUMN grp TEXT NOT NULL DEFAULT '';
    ALTER TABLE services ADD COLUMN description TEXT NOT NULL DEFAULT '';
    ALTER TABLE services ADD COLUMN icon TEXT NOT NULL DEFAULT '';   -- 비우면 자동 (dashboard-icons 이름 추정 → favicon)
    ALTER TABLE services ADD COLUMN on_home INTEGER NOT NULL DEFAULT 1;
    ALTER TABLE services ADD COLUMN position INTEGER NOT NULL DEFAULT 0;
    CREATE TABLE links (
        id          INTEGER PRIMARY KEY,
        name        TEXT NOT NULL,
        url         TEXT NOT NULL,
        grp         TEXT NOT NULL DEFAULT '',
        description TEXT NOT NULL DEFAULT '',
        icon        TEXT NOT NULL DEFAULT '',
        position    INTEGER NOT NULL DEFAULT 0,
        created_at  INTEGER NOT NULL
    );
    )sql",
    // v7: 서비스 유형 확장 (경로 접두사 라우팅, 리다이렉트, https 업스트림, Host 헤더, 타임아웃).
    // 도메인 하나에 경로별 서비스를 두려고 UNIQUE(host) → UNIQUE(host, path_prefix)로 테이블을 다시
    // 만든다.
    R"sql(
    CREATE TABLE services_new (
        id           INTEGER PRIMARY KEY,
        name         TEXT NOT NULL UNIQUE,
        host         TEXT NOT NULL,
        path_prefix  TEXT NOT NULL DEFAULT '/',
        strip_prefix INTEGER NOT NULL DEFAULT 0,
        kind         TEXT NOT NULL DEFAULT 'proxy',   -- proxy | redirect
        redirect_to  TEXT NOT NULL DEFAULT '',
        node_id      INTEGER REFERENCES nodes(id) ON DELETE SET NULL,
        upstream     TEXT NOT NULL DEFAULT '',
        upstream_tls INTEGER NOT NULL DEFAULT 0,      -- 0 http, 1 https, 2 https(인증서 검증 안 함)
        host_header  TEXT NOT NULL DEFAULT '',        -- 비우면 원래 도메인 유지
        timeout      INTEGER NOT NULL DEFAULT 0,      -- 첫 응답까지 초 (0 = 제한 없음)
        auth         TEXT NOT NULL DEFAULT 'douve',
        public_paths TEXT NOT NULL DEFAULT '[]',
        created_at   INTEGER NOT NULL,
        updated_at   INTEGER NOT NULL,
        grp          TEXT NOT NULL DEFAULT '',
        description  TEXT NOT NULL DEFAULT '',
        icon         TEXT NOT NULL DEFAULT '',
        on_home      INTEGER NOT NULL DEFAULT 1,
        position     INTEGER NOT NULL DEFAULT 0,
        UNIQUE (host, path_prefix)
    );
    INSERT INTO services_new (id, name, host, node_id, upstream, auth, public_paths, created_at,
                              updated_at, grp, description, icon, on_home, position)
        SELECT id, name, host, node_id, upstream, auth, public_paths, created_at, updated_at, grp,
               description, icon, on_home, position FROM services;
    DROP TABLE services;
    ALTER TABLE services_new RENAME TO services;
    )sql",
    // v8: 서비스를 만든 곳 (web | node). 노드(douve-agent expose)는 자기가 만든 것만 바꿀 수 있다.
    R"sql(
    ALTER TABLE services ADD COLUMN origin TEXT NOT NULL DEFAULT 'web';
    )sql",
    // v9: 노드 연결 방식 (auto: 직통 시도 후 터널 | direct | tunnel)
    R"sql(
    ALTER TABLE nodes ADD COLUMN connect_mode TEXT NOT NULL DEFAULT 'auto';
    )sql",
    // v10: 복구 코드 (패스키·기기를 잃었을 때 한 번씩 쓰는 비상 로그인). 해시만 저장.
    R"sql(
    CREATE TABLE recovery_codes (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        code_hash BLOB NOT NULL UNIQUE,
        created_at INTEGER NOT NULL,
        used_at INTEGER
    );
    CREATE INDEX recovery_codes_user ON recovery_codes(user_id);
    )sql",
    // v11: 세션의 기기(브라우저) — 같은 기기에서 다시 로그인하면 그 기기의 이전 세션을 정리한다.
    // 기기 쿠키(douve_device) 원문은 저장하지 않고 SHA-256 hex만.
    R"sql(
    ALTER TABLE sessions ADD COLUMN device_hash TEXT NOT NULL DEFAULT '';
    )sql",
    // v12: 공유기 포트 자동 열기 (UPnP/NAT-PMP). 켜면 입구 노드의 80/443을 공유기에 요청한다.
    R"sql(
    ALTER TABLE nodes ADD COLUMN port_forward INTEGER NOT NULL DEFAULT 0;
    )sql",
    // v13: 알림 채널 (ntfy, Discord, Slack, 웹훅). config는 JSON (주소·토큰 등 비밀 포함).
    R"sql(
    CREATE TABLE notify_channels (
        id         INTEGER PRIMARY KEY,
        kind       TEXT NOT NULL,
        name       TEXT NOT NULL,
        config     TEXT NOT NULL DEFAULT '{}',
        enabled    INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL
    );
    )sql",
    // v14: 이름 변경(Moat → Douve) — 저장된 접근 정책 값 'moat'를 'douve'로
    R"sql(
    UPDATE services SET auth = 'douve' WHERE auth = 'moat';
    )sql",
};

[[noreturn]] void fail(sqlite3* db, const std::string& what) {
    throw DbError(what + ": " + (db ? sqlite3_errmsg(db) : "unknown"));
}

} // namespace

Statement::Statement(Database& db, const std::string& sql) : db_(db) {
    if (sqlite3_prepare_v2(db.handle(), sql.c_str(), static_cast<int>(sql.size()), &stmt_,
                           nullptr) != SQLITE_OK) {
        fail(db.handle(), "prepare");
    }
}

Statement::~Statement() {
    sqlite3_finalize(stmt_);
}

Statement& Statement::bind(int idx, std::int64_t v) {
    if (sqlite3_bind_int64(stmt_, idx, v) != SQLITE_OK)
        fail(db_.handle(), "bind");
    return *this;
}

Statement& Statement::bind(int idx, double v) {
    if (sqlite3_bind_double(stmt_, idx, v) != SQLITE_OK)
        fail(db_.handle(), "bind");
    return *this;
}

Statement& Statement::bind(int idx, const std::string& v) {
    if (sqlite3_bind_text(stmt_, idx, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT) !=
        SQLITE_OK)
        fail(db_.handle(), "bind");
    return *this;
}

Statement& Statement::bind(int idx, const Bytes& v) {
    // 빈 BLOB도 NULL이 아닌 빈 값으로 저장되도록 zeroblob 사용
    int rc = v.empty() ? sqlite3_bind_zeroblob(stmt_, idx, 0)
                       : sqlite3_bind_blob(stmt_, idx, v.data(), static_cast<int>(v.size()),
                                           SQLITE_TRANSIENT);
    if (rc != SQLITE_OK)
        fail(db_.handle(), "bind");
    return *this;
}

Statement& Statement::bindNull(int idx) {
    if (sqlite3_bind_null(stmt_, idx) != SQLITE_OK)
        fail(db_.handle(), "bind");
    return *this;
}

bool Statement::step() {
    int rc = sqlite3_step(stmt_);
    if (rc == SQLITE_ROW)
        return true;
    if (rc == SQLITE_DONE)
        return false;
    fail(db_.handle(), "step");
}

void Statement::run() {
    while (step()) {
    }
    sqlite3_reset(stmt_);
}

bool Statement::isNull(int col) const {
    return sqlite3_column_type(stmt_, col) == SQLITE_NULL;
}
std::int64_t Statement::int64(int col) const {
    return sqlite3_column_int64(stmt_, col);
}

double Statement::real(int col) const {
    return sqlite3_column_double(stmt_, col);
}

std::string Statement::text(int col) const {
    auto p = sqlite3_column_text(stmt_, col);
    return p ? std::string(reinterpret_cast<const char*>(p), sqlite3_column_bytes(stmt_, col))
             : std::string();
}

Bytes Statement::blob(int col) const {
    auto p = static_cast<const std::uint8_t*>(sqlite3_column_blob(stmt_, col));
    return p ? Bytes(p, p + sqlite3_column_bytes(stmt_, col)) : Bytes();
}

Database::Database(const std::string& path) {
    if (sqlite3_open_v2(path.c_str(), &db_,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                        nullptr) != SQLITE_OK) {
        std::string msg = db_ ? sqlite3_errmsg(db_) : "open";
        sqlite3_close(db_);
        throw DbError("DB 열기 실패 (" + path + "): " + msg);
    }
    sqlite3_busy_timeout(db_, 5000);
    exec("PRAGMA foreign_keys = ON");
    if (path != ":memory:")
        exec("PRAGMA journal_mode = WAL");
    migrate();
}

Database::~Database() {
    sqlite3_close(db_);
}

void Database::exec(const std::string& sql) {
    char* err = nullptr;
    if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "exec";
        sqlite3_free(err);
        throw DbError(msg);
    }
}

std::int64_t Database::lastInsertId() const {
    return sqlite3_last_insert_rowid(db_);
}
int Database::changes() const {
    return sqlite3_changes(db_);
}

int Database::schemaVersion() {
    Statement s(*this, "PRAGMA user_version");
    return s.step() ? static_cast<int>(s.int64(0)) : 0;
}

void Database::migrate() {
    auto guard = lock();
    int current = schemaVersion();
    if (current > static_cast<int>(kMigrations.size())) {
        throw DbError("DB 스키마(v" + std::to_string(current) +
                      ")가 이 douve-hub보다 새 버전입니다");
    }
    for (int v = current; v < static_cast<int>(kMigrations.size()); ++v) {
        exec("BEGIN");
        try {
            exec(kMigrations[v]);
            exec("PRAGMA user_version = " + std::to_string(v + 1));
            exec("COMMIT");
        } catch (...) {
            exec("ROLLBACK");
            throw;
        }
    }
}

Transaction::Transaction(Database& db) : db_(db), lock_(db.lock()) {
    db_.exec("BEGIN IMMEDIATE");
}

Transaction::~Transaction() {
    if (!done_) {
        try {
            db_.exec("ROLLBACK");
        } catch (...) {
        }
    }
}

void Transaction::commit() {
    db_.exec("COMMIT");
    done_ = true;
}

} // namespace douve
