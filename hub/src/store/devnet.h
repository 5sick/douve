#pragma once
// 내부 길: Douve가 관리하는 기기용 WireGuard 망. 입구 Agent(package devnet)가 WireGuard·DNS·HTTPS를
// 맡고, Hub는 기기 등록(키·주소), 설정, 서비스별 권한을 만들어 라우팅 표에 실어 보낸다.
//
//   입구 내부 주소 10.201.0.1, 기기 10.201.0.2~254 (/32). 기기 설정의 DNS는 입구 주소라, 연결된
//   동안 내부 길에 있는 서비스 도메인은 입구로, 나머지는 원래대로 풀린다.

#include "store/db.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace douve {

inline constexpr const char* kDevnetAddress = "10.201.0.1";
inline constexpr const char* kDevnetSubnet = "10.201.0.0/24";

struct DevnetSettings {
    bool enabled = false;
    int port = 51821;       // UDP (클라우드 방화벽에서 열어야 함)
    std::string endpoint;   // 기기가 접속할 주소 (비우면 Hub 공개 주소의 호스트)
    std::string gatewayKey; // 입구 Agent가 알려 준 WireGuard 공개키 (base64)
    std::int64_t gatewayNode = 0;
};

DevnetSettings loadDevnet(Database& db);
void saveDevnet(Database& db, const DevnetSettings& s, std::int64_t now);
// 포트·주소 형식 검사 (문제가 있으면 이유)
std::string validateDevnet(const DevnetSettings& s);

struct Device {
    std::int64_t id = 0;
    std::int64_t userId = 0;
    std::string name;
    std::string pubkey; // WireGuard 공개키 (base64)
    std::string ip;
    std::int64_t createdAt = 0;
};

std::vector<Device> listDevices(Database& db);
std::vector<Device> listDevicesOf(Database& db, std::int64_t userId);
std::optional<Device> findDevice(Database& db, std::int64_t id);
// 빈 주소를 골라 저장한다. 주소가 다 찼거나 이름이 잘못되면 nullopt + error.
std::optional<Device> createDevice(Database& db, std::int64_t userId, const std::string& name,
                                   const std::string& pubkey, std::int64_t now, std::string& error);
bool deleteDevice(Database& db, std::int64_t id);

struct WgKeyPair {
    std::string privateKey, publicKey; // base64
};
WgKeyPair generateWgKeyPair();
bool validWgKey(const std::string& b64);

// 기기에 넣을 WireGuard 설정 (wg-quick 형식, QR로도 보여 준다)
std::string deviceConfig(const DevnetSettings& s, const std::string& endpointHost,
                         const std::string& privateKey, const std::string& ip);

} // namespace douve
