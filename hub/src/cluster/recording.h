#pragma once
// 터미널 세션 녹화 (asciicast v2). 화면 출력만 기록하고 입력(비밀번호 등)은 기록하지 않는다.

#include <cstdint>
#include <fstream>
#include <string>

namespace douve {

// 바이트 조각을 UTF-8 경계에서 자른다. 끝의 불완전한 문자는 carry에 남겨 다음 조각 앞에 붙인다.
std::string takeCompleteUtf8(std::string& carry, const std::string& chunk);

class Recorder {
  public:
    static constexpr std::size_t kMaxBytes = 20 * 1024 * 1024;

    // path에 헤더를 쓴다. 실패하면 ok()가 false (녹화 없이 터미널은 계속).
    Recorder(const std::string& path, int cols, int rows, std::int64_t startUnix,
             const std::string& title);
    bool ok() const { return ok_; }
    void output(const std::string& bytes, double elapsedSeconds);
    void resize(int cols, int rows, double elapsedSeconds);
    std::size_t bytes() const { return written_; }
    bool truncated() const { return truncated_; }

  private:
    void line(const std::string& json);
    std::ofstream out_;
    std::string carry_;
    std::size_t written_ = 0;
    bool ok_ = false;
    bool truncated_ = false;
};

} // namespace douve
