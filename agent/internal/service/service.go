// Package service는 Agent의 systemd 유닛을 설치한다.
package service

import (
	"fmt"
	"os"
)

const UnitPath = "/etc/systemd/system/douve-agent.service"

// Unit은 systemd 유닛 내용이다. 상태 수집에 root가 필요하므로(/proc/*/fd, Docker 소켓, wg)
// root로 돌되 쓰기 가능한 경로를 막는다.
func Unit(binary string) string {
	return fmt.Sprintf(`[Unit]
Description=Douve Agent (서버 상태 수집 · Hub 연결)
Documentation=https://github.com/5sick/douve
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=%s run
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
# 자동 업데이트(실행 파일 교체)와 상태 저장(라우팅 표·인증서)만 쓰기 허용
ReadWritePaths=/usr/local/bin
StateDirectory=douve-agent
StateDirectoryMode=0700
ProtectHome=read-only
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
MemoryMax=96M

[Install]
WantedBy=multi-user.target
`, binary)
}

// Installed는 설치된 유닛이 지금 버전의 내용과 같은지 확인한다.
func Installed(binary string) bool {
	b, err := os.ReadFile(UnitPath)
	return err == nil && string(b) == Unit(binary)
}

// Install은 유닛 파일을 쓴다 (daemon-reload·enable은 호출자가 한다).
func Install(binary string) error {
	return os.WriteFile(UnitPath, []byte(Unit(binary)), 0o644)
}
