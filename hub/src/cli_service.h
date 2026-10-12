#pragma once

#include <string>
#include <vector>

namespace douve {

// `douve-hub service-add`: Hub 서버에서 root가 서비스를 등록한다 (기존 nginx 설정 가져오기 등).
// 접속 중인 입구에는 Hub가 다음 접속·변경 때 반영한다 (`systemctl restart douve-hub`로 즉시 반영).
int runServiceAdd(const std::vector<std::string>& args);

// `douve-hub node-set --name 노드 --edge on|off`: 노드를 입구로 지정·해제 (install.sh가 첫 노드에
// 사용). 접속 중인 Agent에는 다음 접속 때 반영된다.
int runNodeSet(const std::vector<std::string>& args);

} // namespace douve
