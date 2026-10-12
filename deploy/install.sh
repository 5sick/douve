#!/bin/sh
# Douve 설치: 빈 서버에서
#   curl -fsSL https://github.com/5sick/douve/releases/latest/download/install.sh | sudo sh
# 옵션은 그대로 넘어간다 (sh -s -- --mode tailscale --yes 등). 질문은 터미널(/dev/tty)에서 받는다.
set -eu

# 메시지 언어: LANG 등이 ko로 시작하면 한국어
t() { case "${DOUVE_LANG:-${LC_ALL:-${LANG:-}}}" in ko*) printf '%s' "$1" ;; *) printf '%s' "$2" ;; esac; }

RELEASE="${DOUVE_RELEASE:-https://github.com/5sick/douve/releases/latest/download}"

if [ "$(id -u)" -ne 0 ]; then
	echo "$(t "root 권한이 필요합니다" "Root privileges are required"): curl -fsSL .../install.sh | sudo sh" >&2
	exit 1
fi
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*)
	echo "$(t "지원하지 않는 CPU" "Unsupported CPU"): $(uname -m)" >&2
	exit 1
	;;
esac
command -v curl >/dev/null 2>&1 || {
	echo "$(t "curl이 필요합니다" "curl is required")" >&2
	exit 1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
name="douve-agent-linux-$arch"
curl -fsSL -o "$tmp/$name" "$RELEASE/$name"
curl -fsSL -o "$tmp/SHA256SUMS" "$RELEASE/SHA256SUMS"
want=$(awk -v n="$name" '$2 == n || $2 == "*" n { print $1 }' "$tmp/SHA256SUMS")
got=$(sha256sum "$tmp/$name" | awk '{ print $1 }')
if [ -z "$want" ] || [ "$want" != "$got" ]; then
	echo "$name: $(t "체크섬이 맞지 않습니다" "checksum mismatch")" >&2
	exit 1
fi
chmod 755 "$tmp/$name"
DOUVE_LANG="${DOUVE_LANG:-${LC_ALL:-${LANG:-}}}" "$tmp/$name" install --release "$RELEASE" "$@"
