#!/bin/bash
# Google 로그인 E2E: 가짜 Google 서버 + douve-hub를 띄우고 curl로 전체 흐름을 검증한다.
# 사용: tests/e2e/google_flow.sh [douve-hub 경로]
set -u
export DOUVE_LANG=ko # CLI 출력 언어 고정 (영어 확인은 따로)
HUB=${1:-build/hub/douve-hub}
DIR=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$DIR"' EXIT
HERE=$(cd "$(dirname "$0")" && pwd)
PASS=0; FAIL=0
ok()   { echo "  ok   $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL+1)); }

cat > "$DIR/hub.json" <<JSON
{"public_url":"http://localhost:18800","cookie_domain":"localhost","database_path":"$DIR/hub.db",
 "listen_port":18800,"allowed_emails":["test@example.com"],
 "google":{"client_id":"mock-client","client_secret":"s","auth_url":"http://127.0.0.1:18801/auth",
           "token_url":"http://127.0.0.1:18801/token","jwks_url":"http://127.0.0.1:18801/certs"}}
JSON

start_mock() { MOCK_EMAIL=$1 MOCK_TAMPER=${2:-0} python3 "$HERE/mock_google.py" 18801 & MOCK=$!; sleep 0.7; }
# 가짜 서버를 다시 띄우면 키가 바뀐다 → Hub의 JWKS 재조회 제한(10초)을 넘기기 위해 대기
restart_wait() { sleep 11; }
stop_mock() { kill $MOCK 2>/dev/null; wait $MOCK 2>/dev/null; }

"$HUB" --config "$DIR/hub.json" >"$DIR/hub.log" 2>&1 &
sleep 1

# 로그인 흐름을 따라가며 마지막 Location을 출력 (쿠키는 jar에 저장)
login() {
    rm -f "$DIR/jar"
    curl -s -c "$DIR/jar" -b "$DIR/jar" -o /dev/null -L --max-redirs 3 -w '%{url_effective}' \
        "http://localhost:18800/auth/google/start?rd=$1"
}

echo "[google_flow]"
start_mock test@example.com
final=$(login "/")
code=$(curl -s -b "$DIR/jar" -o /dev/null -w '%{http_code}' localhost:18800/auth/verify)
[ "$code" = 200 ] && ok "허용된 이메일 로그인 → 세션 유효" || bad "허용된 이메일 로그인 (verify=$code, final=$final)"
case "$final" in *"/account?setup=passkey"*) ok "패스키 없으면 등록 화면으로 안내" ;; *) bad "등록 안내 리다이렉트 ($final)";; esac
user=$(curl -s -b "$DIR/jar" -D - -o /dev/null localhost:18800/auth/verify | tr -d '\r' | sed -n 's/^x-douve-user: //Ip')
[ "$user" = test@example.com ] && ok "X-Douve-User 헤더" || bad "X-Douve-User ($user)"
grep -q "douve_session" "$DIR/jar" && ok "세션 쿠키 발급" || bad "세션 쿠키"
code=$(curl -s -b "$DIR/jar" -o /dev/null -w "%{http_code}" -X POST localhost:18800/auth/logout)
[ "$code" = 403 ] && ok "Origin 없는 로그아웃 요청 거부(CSRF)" || bad "CSRF 검사 ($code)"
curl -s -b "$DIR/jar" -c "$DIR/jar" -o /dev/null -X POST -H "Origin: http://localhost:18800" localhost:18800/auth/logout
code=$(curl -s -b "$DIR/jar" -o /dev/null -w '%{http_code}' localhost:18800/auth/verify)
[ "$code" = 401 ] && ok "로그아웃 후 세션 무효" || bad "로그아웃 ($code)"
stop_mock

restart_wait; start_mock intruder@example.com
final=$(login "/")
case "$final" in *"error=not_allowed"*) ok "허용 목록에 없는 이메일 거부" ;; *) bad "허용 외 이메일 ($final)";; esac
stop_mock

restart_wait; start_mock test@example.com 1
final=$(login "/")
case "$final" in *"error=google"*) ok "변조된 ID 토큰 거부" ;; *) bad "변조 토큰 ($final)";; esac
stop_mock

# state 재사용: 정상 흐름에서 받은 콜백 URL을 다시 호출하면 거부
start_mock test@example.com
rm -f "$DIR/jar"
cb=$(curl -s -o /dev/null -w '%{redirect_url}' "$(curl -s -o /dev/null -w '%{redirect_url}' localhost:18800/auth/google/start)")
curl -s -o /dev/null "$cb"
again=$(curl -s -o /dev/null -w '%{redirect_url}' "$cb")
case "$again" in *"error=state"*) ok "state 재사용 거부" ;; *) bad "state 재사용 ($again)";; esac
stop_mock

final=$(curl -s -o /dev/null -w '%{redirect_url}' "localhost:18800/auth/google/callback?state=forged&code=x")
case "$final" in *"error=state"*) ok "위조 state 거부" ;; *) bad "위조 state ($final)";; esac

events=$(sqlite3 "$DIR/hub.db" "SELECT group_concat(event, ',') FROM (SELECT event FROM audit_log ORDER BY id)")
case "$events" in *login*logout*login_denied*login_failed*) ok "감사 로그 기록 ($events)" ;; *) bad "감사 로그 ($events)";; esac

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
