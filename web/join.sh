#!/bin/sh
# Douve 서버 추가 스크립트. Hub 웹 화면의 "서버 추가"에서 보여주는 명령으로 실행한다:
#   curl -fsSL __DOUVE_HUB__/join.sh | sudo sh -s -- <토큰>
# 하는 일: Agent 바이너리 다운로드(체크섬 확인) → Hub에 등록 → systemd 서비스로 실행.
# 이미 등록된 서버에서 토큰 없이 실행하면 Agent와 systemd 유닛만 최신으로 바꾼다:
#   curl -fsSL __DOUVE_HUB__/join.sh | sudo sh
# 접속 주소를 바꾸려면(예: WireGuard 내부 주소) DOUVE_CONNECT_URL 환경변수를 지정한다.
set -eu

HUB="__DOUVE_HUB__"
CONNECT="${DOUVE_CONNECT_URL:-$HUB}"
TOKEN="${1:-}"

die() { echo "douve: $*" >&2; exit 1; }
# 메시지 언어: LANG 등이 ko로 시작하면 한국어
t() { case "${DOUVE_LANG:-${LC_ALL:-${LANG:-}}}" in ko*) printf '%s' "$1" ;; *) printf '%s' "$2" ;; esac; }

UPGRADE=0
if [ -z "$TOKEN" ]; then
    [ -f /etc/douve-agent/agent.json ] || die "$(t "토큰이 필요합니다. 사용법" "A token is required. Usage"): curl -fsSL $HUB/join.sh | sudo sh -s -- <token>"
    UPGRADE=1
fi
[ "$(id -u)" = 0 ] || die "$(t "root 권한이 필요합니다 (sudo로 실행하세요)" "Root privileges are required (run with sudo)")"
command -v systemctl >/dev/null 2>&1 || die "$(t "systemd가 필요합니다" "systemd is required")"
command -v curl >/dev/null 2>&1 || die "$(t "curl이 필요합니다" "curl is required")"
command -v sha256sum >/dev/null 2>&1 || die "$(t "sha256sum이 필요합니다" "sha256sum is required")"

case "$(uname -m)" in
    x86_64 | amd64) ARCH=amd64 ;;
    aarch64 | arm64) ARCH=arm64 ;;
    *) die "$(t "지원하지 않는 아키텍처" "Unsupported architecture"): $(uname -m)" ;;
esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

echo "douve: $(t "Agent 다운로드" "Downloading agent") (linux-$ARCH)"
curl -fsSL "$HUB/dl/douve-agent-linux-$ARCH" -o "$TMP/douve-agent"
curl -fsSL "$HUB/dl/SHA256SUMS" -o "$TMP/SHA256SUMS"
EXPECTED="$(grep " douve-agent-linux-$ARCH\$" "$TMP/SHA256SUMS" | cut -d' ' -f1)"
ACTUAL="$(sha256sum "$TMP/douve-agent" | cut -d' ' -f1)"
[ -n "$EXPECTED" ] && [ "$EXPECTED" = "$ACTUAL" ] || die "$(t "체크섬이 맞지 않습니다" "Checksum mismatch")"
chmod 755 "$TMP/douve-agent"
mv -f "$TMP/douve-agent" /usr/local/bin/douve-agent
command -v restorecon >/dev/null 2>&1 && restorecon /usr/local/bin/douve-agent || true

if [ "$UPGRADE" = 1 ]; then
    echo "douve: $(t "업그레이드 (등록 정보 유지)" "Upgrading (keeping registration)")"
else
    echo "douve: $(t "Hub에 등록" "Registering with the Hub")"
    /usr/local/bin/douve-agent join --hub "$CONNECT" --token "$TOKEN"
fi
/usr/local/bin/douve-agent install-service
systemctl daemon-reload
systemctl enable douve-agent >/dev/null 2>&1
systemctl restart douve-agent
echo "douve: $(t "완료" "Done") ($(/usr/local/bin/douve-agent version)). $(t "Hub 대시보드에서 이 서버가 보이는지 확인하세요." "Check that this server appears in the Hub dashboard.")"
