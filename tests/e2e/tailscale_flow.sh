#!/bin/bash
# Tailscale 내부 전용 모드 E2E: tailscale serve가 붙이는 Tailscale-User-Login으로 로그인.
# 허용된 사용자만, 127.0.0.1에서 온 헤더만, 모드가 꺼져 있으면 무시.
# 사용: tests/e2e/tailscale_flow.sh [douve-hub 경로]
set -u
export DOUVE_LANG=ko # CLI 출력 언어 고정 (영어 확인은 따로)
HUB=${1:-build/hub/douve-hub}
P=18895
DIR=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$DIR"' EXIT
PASS=0; FAIL=0
ok()   { echo "  ok   $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL+1)); }
ss -ltn | grep -q ":$P " && { echo "포트 $P 사용 중"; exit 1; }
start() { # tailscale_auth(true|false)
    kill $(jobs -p) 2>/dev/null; wait 2>/dev/null
    cat > "$DIR/hub.json" <<JSON
{"public_url":"https://box.tail1234.ts.net","cookie_domain":"box.tail1234.ts.net","database_path":"$DIR/hub.db",
 "listen_address":"0.0.0.0","listen_port":$P,"allowed_emails":["me@example.com"],"tailscale_auth":$1}
JSON
    "$HUB" --config "$DIR/hub.json" >"$DIR/hub.log" 2>&1 &
    for _ in $(seq 50); do curl -sf "http://127.0.0.1:$P/healthz" >/dev/null && break; sleep 0.1; done
}
me() { curl -s -o /dev/null -w '%{http_code}' ${2:+-H "Tailscale-User-Login: $2"} "http://$1:$P/api/me"; }

echo "[tailscale_flow]"
start true
[ "$(me 127.0.0.1 Me@Example.com)" = 200 ] && ok "허용된 Tailscale 사용자 로그인 (대소문자 무시)" || bad "허용 사용자"
curl -s -H "Tailscale-User-Login: me@example.com" "http://127.0.0.1:$P/api/me" | grep -q '"auth_method":"tailscale"' && ok "로그인 방식 tailscale" || bad "방식 표시"
[ "$(me 127.0.0.1 intruder@example.com)" = 401 ] && ok "허용 목록 밖 사용자 거부" || bad "허용 밖"
[ "$(me 127.0.0.1)" = 401 ] && ok "헤더 없으면 로그인 아님" || bad "헤더 없음"
IP=$(hostname -I | awk '{print $1}')
[ "$(me "$IP" me@example.com)" = 401 ] && ok "127.0.0.1이 아닌 곳에서 온 헤더는 무시 ($IP)" || bad "원격 헤더 신뢰됨"
start false
[ "$(me 127.0.0.1 me@example.com)" = 401 ] && ok "모드가 꺼져 있으면 헤더 무시" || bad "모드 꺼짐"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
