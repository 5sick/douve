#pragma once

#include <map>
#include <set>
#include <string>
#include <vector>

namespace douve {

// 비상 출입구 CLI (Hub 서버의 root가 실행)
//   douve-hub recovery-codes --email 주소   일회용 복구 코드 10개 새로 만들기
//   douve-hub backup [--output 파일]        DB + 설정을 파일 하나로
//   douve-hub restore <파일>                Hub를 멈춘 뒤 복원
int runRecoveryCodes(const std::vector<std::string>& args);
int runBackup(const std::vector<std::string>& args);
int runRestore(const std::vector<std::string>& args);

} // namespace douve
