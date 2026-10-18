#pragma once

#include "util/encoding.h"

#include <cstdint>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>

struct sqlite3;
struct sqlite3_stmt;

namespace douve {

struct DbError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

class Database;

// 준비된 SQL 문. 바인딩 인덱스는 1부터 (SQLite 규칙).
class Statement {
  public:
    Statement(Database& db, const std::string& sql);
    ~Statement();
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    Statement& bind(int idx, std::int64_t v);
    Statement& bind(int idx, double v);
    Statement& bind(int idx, int v) { return bind(idx, static_cast<std::int64_t>(v)); }
    Statement& bind(int idx, const std::string& v);
    Statement& bind(int idx, const Bytes& v);
    Statement& bindNull(int idx);
    template <typename T> Statement& bind(int idx, const std::optional<T>& v) {
        return v ? bind(idx, *v) : bindNull(idx);
    }

    // 결과 행이 있으면 true, 끝이면 false. 오류 시 DbError.
    bool step();
    void run(); // 결과 없는 문 실행 (step 후 reset)

    bool isNull(int col) const;
    std::int64_t int64(int col) const;
    double real(int col) const;
    std::string text(int col) const;
    Bytes blob(int col) const;

  private:
    Database& db_;
    sqlite3_stmt* stmt_ = nullptr;
};

// SQLite 연결 하나 + 뮤텍스. 개인 서버 규모에서는 단일 연결로 충분하다.
// 여러 문장을 묶을 때는 lock()으로 잡은 뒤 실행한다.
class Database {
  public:
    explicit Database(const std::string& path); // ":memory:" 가능
    ~Database();
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    void exec(const std::string& sql);
    std::int64_t lastInsertId() const;
    int changes() const;
    // 이미 트랜잭션 안인지 (BEGIN을 겹쳐 열지 않기 위해)
    bool inTransaction() const;
    int schemaVersion();

    std::unique_lock<std::recursive_mutex> lock() { return std::unique_lock(mutex_); }
    sqlite3* handle() const { return db_; }

  private:
    void migrate();
    sqlite3* db_ = nullptr;
    std::recursive_mutex mutex_;
};

// 트랜잭션 RAII: commit() 하지 않고 범위를 벗어나면 롤백.
class Transaction {
  public:
    explicit Transaction(Database& db);
    ~Transaction();
    void commit();

  private:
    Database& db_;
    std::unique_lock<std::recursive_mutex> lock_;
    bool done_ = false;
};

} // namespace douve
