#!/bin/bash
# 비상 출입구 E2E: 복구 코드(CLI·웹 생성, 일회용, 알림, 재인증, 허용 사용자만, 속도 제한) + 백업·복원.
# 사용: tests/e2e/recovery_flow.sh [douve-hub 경로]
set -u
export DOUVE_LANG=ko # CLI 출력 언어 고정 (영어 확인은 따로)
HUB=${1:-build/hub/douve-hub}
HP=18870; TP=18871; WP=18872
BASE="http://localhost:$HP"
DIR=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$DIR"' EXIT
PASS=0; FAIL=0
ok()   { echo "  ok   $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL+1)); }
for p in $HP $TP $WP; do ss -ltn | grep -q ":$p " && { echo "포트 $p 사용 중"; exit 1; }; done

cat > "$DIR/tg.py" <<'PY'
import sys, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        q = urllib.parse.parse_qs(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode())
        open(sys.argv[2], "a").write(q.get("text", [""])[0] + "\n")
        self.send_response(200); self.end_headers(); self.wfile.write(b'{"ok":true}')
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
python3 "$DIR/tg.py" $TP "$DIR/tg.log" &
# 알림 채널(웹훅)로도 같은 알림이 가는지
cat > "$DIR/hook.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        open(sys.argv[2], "a").write(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode() + "\n")
        self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
python3 "$DIR/hook.py" $WP "$DIR/hook.log" &
cat > "$DIR/hub.json" <<JSON
{"public_url":"$BASE","cookie_domain":"localhost","database_path":"$DIR/hub.db","listen_port":$HP,
 "allowed_emails":["me@example.com"],
 "telegram":{"api_url":"http://127.0.0.1:$TP","bot_token":"1:x","chat_id":"1"}}
JSON
start_hub() {
    "$HUB" --config "$DIR/hub.json" >>"$DIR/hub.log" 2>&1 & HUB_PID=$!
    for _ in $(seq 50); do curl -sf "$BASE/healthz" >/dev/null && break; sleep 0.1; done
}
start_hub
python3 - "$DIR/hub.db" <<'PY'
import hashlib, sqlite3, sys, time
db = sqlite3.connect(sys.argv[1]); now = int(time.time())
db.execute("INSERT INTO users (id, email, created_at, allowed) VALUES (1, 'me@example.com', ?, 1)", (now,))
db.execute("INSERT INTO users (id, email, created_at, allowed) VALUES (2, 'gone@example.com', ?, 0)", (now,))
db.execute("INSERT INTO notify_channels (kind, name, config, enabled, created_at) VALUES ('webhook', 'hook', ?, 1, ?)",
           ('{"url":"http://127.0.0.1:18872/h"}', now))
for tok, re in (("rec-fresh-session-0123456789abcdef", now), ("rec-stale-session-0123456789abcdef", now - 3600)):
    db.execute("INSERT INTO sessions VALUES (?, 1, 'passkey', ?, ?, ?, ?, ?, '', '', '')",
               (hashlib.sha256(tok.encode()).digest(), now, now, now + 3600, now + 7200, re))
db.commit()
PY
F=rec-fresh-session-0123456789abcdef; S=rec-stale-session-0123456789abcdef
post() { curl -s -X POST -H "Cookie: douve_session=$1" -H "Origin: $BASE" -H 'Content-Type: application/json' -d "$3" "$BASE$2"; }
# 복구 로그인: 응답 본문 + 받은 세션 쿠키
recover() {
    curl -s -D "$DIR/h" -o "$DIR/b" -w '%{http_code}' -X POST -H "Origin: ${2:-$BASE}" -H 'Content-Type: application/json' \
        -d "{\"code\":\"$1\"}" "$BASE/auth/recovery"
}
cookie() { grep -i '^set-cookie: douve_session=' "$DIR/h" | sed 's/^[^=]*=\([^;]*\).*/\1/'; }

echo "[recovery_flow]"
"$HUB" recovery-codes --email ME@example.com --config "$DIR/hub.json" >"$DIR/codes" 2>/dev/null
[ "$(wc -l <"$DIR/codes")" = 10 ] && grep -Eq '^[a-z2-9]{4}-[a-z2-9]{4}-[a-z2-9]{4}$' "$DIR/codes" \
    && ok "CLI로 복구 코드 10개" || bad "CLI 코드 ($(cat "$DIR/codes"))"
C1=$(sed -n 1p "$DIR/codes"); C2=$(sed -n 2p "$DIR/codes")
sqlite3 "$DIR/hub.db" "SELECT count(*) FROM recovery_codes WHERE code_hash = CAST('$C1' AS BLOB)" | grep -qx 0 \
    && ok "DB에는 원문 없음" || bad "원문 저장"

[ "$(recover "$C1" http://evil.example)" = 403 ] && ok "다른 출처 거부" || bad "출처 검사"
[ "$(recover aaaa-bbbb-cccc)" = 401 ] && ok "틀린 코드 거부" || bad "틀린 코드"
code=$(recover "$(tr a-z A-Z <<<"${C1//-/ }")")
SESS=$(cookie)
[ "$code" = 200 ] && [ -n "$SESS" ] && ok "복구 코드로 로그인 (대문자·공백 입력)" || bad "복구 로그인 ($code $(cat "$DIR/b"))"
grep -q '"remaining":9' "$DIR/b" && ok "남은 코드 수" || bad "남은 수 ($(cat "$DIR/b"))"
curl -s -H "Cookie: douve_session=$SESS" "$BASE/api/me" | grep -q 'me@example.com' && ok "복구 세션으로 접속" || bad "복구 세션"
curl -s -H "Cookie: douve_session=$SESS" "$BASE/api/sessions" | grep -q '"auth_method":"recovery"' && ok "세션 방식 = 복구 코드" || bad "세션 방식"
[ "$(recover "$C1")" = 401 ] && ok "같은 코드 재사용 거부" || bad "재사용"
for _ in $(seq 30); do grep -q "복구 코드로 로그인" "$DIR/tg.log" 2>/dev/null && break; sleep 0.1; done
grep -q "복구 코드로 로그인: me@example.com" "$DIR/tg.log" && ok "복구 로그인 알림" || bad "알림 ($(cat "$DIR/tg.log" 2>/dev/null))"
for _ in $(seq 30); do grep -q "복구 코드로 로그인" "$DIR/hook.log" 2>/dev/null && break; sleep 0.1; done
grep -q '"source":"douve".*복구 코드로 로그인: me@example.com' "$DIR/hook.log" && ok "같은 알림이 웹훅 채널로도" || bad "채널 알림 ($(cat "$DIR/hook.log" 2>/dev/null))"
sqlite3 "$DIR/hub.db" "SELECT group_concat(event) FROM audit_log" | grep -q 'recovery_login' && ok "감사 로그" || bad "감사 로그"

# 복구 세션은 바로 재인증된 상태 → 새 패스키 등록·코드 재발급 가능
out=$(post "$SESS" /api/account/recovery/generate '{}')
echo "$out" | python3 -c 'import json,sys; assert len(json.load(sys.stdin)["codes"])==10' 2>/dev/null \
    && ok "복구 세션에서 코드 새로 만들기" || bad "복구 세션 재발급 ($out)"
NEW=$(echo "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["codes"][0])')
[ "$(recover "$C2")" = 401 ] && ok "새로 만들면 이전 코드 무효" || bad "이전 코드 무효"
out=$(post $S /api/account/recovery/generate '{}')
case "$out" in *reauth_required*) ok "웹 생성은 패스키 재확인 필요" ;; *) bad "재확인 ($out)";; esac
curl -s -H "Cookie: douve_session=$F" "$BASE/api/account/recovery" | grep -q '"remaining":10' && ok "상태 API" || bad "상태 API"

# 허용되지 않은 사용자(gone)의 코드는 로그인 불가
"$HUB" recovery-codes --email gone@example.com --config "$DIR/hub.json" >"$DIR/gone" 2>/dev/null
[ "$(recover "$(head -1 "$DIR/gone")")" = 401 ] && ok "허용되지 않은 사용자 거부" || bad "허용 목록"

# 백업 → 변경 → 복원
"$HUB" backup --output "$DIR/b1.db" --config "$DIR/hub.json" >/dev/null 2>&1 && [ -s "$DIR/b1.db" ] \
    && ok "douve-hub backup (실행 중)" || bad "backup"
[ "$(stat -c %a "$DIR/b1.db")" = 600 ] && ok "백업 파일 권한 600" || bad "권한 $(stat -c %a "$DIR/b1.db")"
"$HUB" backup --output "$DIR/b1.db" --config "$DIR/hub.json" >/dev/null 2>&1 && bad "기존 파일 덮어씀" || ok "기존 백업 덮어쓰지 않음"
kill $HUB_PID; wait $HUB_PID 2>/dev/null
sqlite3 "$DIR/hub.db" "INSERT INTO users (email, created_at) VALUES ('later@example.com', 1)"
cp "$DIR/hub.json" "$DIR/hub.json.orig"; echo '{}' >"$DIR/hub.json"
"$HUB" restore "$DIR/b1.db" --config "$DIR/hub.json" --force >"$DIR/restore.log" 2>&1 && ok "douve-hub restore" || bad "restore ($(cat "$DIR/restore.log"))"
cmp -s "$DIR/hub.json" "$DIR/hub.json.orig" && ok "설정 파일도 복원" || bad "설정 복원 ($(cat "$DIR/hub.json"))"
ls "$DIR"/hub.db.before-restore-* >/dev/null 2>&1 && ok "기존 DB 보존" || bad "기존 DB 보존"
start_hub
[ "$(sqlite3 "$DIR/hub.db" "SELECT count(*) FROM users WHERE email='later@example.com'")" = 0 ] && ok "백업 시점으로 복원" || bad "복원 내용"
[ "$(recover "$NEW")" = 200 ] && ok "복원 뒤에도 복구 코드 사용" || bad "복원 후 코드"
"$HUB" restore "$DIR/hub.json" --config "$DIR/hub.json" --force >/dev/null 2>&1 && bad "백업 아닌 파일 복원" || ok "백업이 아닌 파일 거부"

# 같은 기기(douve_device 쿠키)에서 다시 로그인하면 그 기기의 이전 세션은 정리된다
"$HUB" recovery-codes --email me@example.com --config "$DIR/hub.json" >"$DIR/codes2" 2>/dev/null
dev_login() {
    curl -s -D "$DIR/h" -o /dev/null -w '%{http_code}' -X POST -H "Origin: $BASE" -H 'Content-Type: application/json' \
        ${2:+-H "Cookie: douve_device=$2"} -d "{\"code\":\"$1\"}" "$BASE/auth/recovery"
}
nsess() { sqlite3 "$DIR/hub.db" "SELECT count(*) FROM sessions WHERE user_id = 1"; }
dev_login "$(sed -n 1p "$DIR/codes2")" >/dev/null
DEV=$(grep -i '^set-cookie: douve_device=' "$DIR/h" | sed 's/^[^=]*=\([^;]*\).*/\1/')
grep -i '^set-cookie: douve_device=' "$DIR/h" | grep -qi 'httponly' && [ ${#DEV} -ge 22 ] && ok "기기 쿠키 발급 (HttpOnly)" || bad "기기 쿠키 ($(grep -i set-cookie "$DIR/h"))"
grep -i '^set-cookie: douve_device=' "$DIR/h" | grep -qi 'domain=' && bad "기기 쿠키가 하위 도메인까지 전송됨" || ok "기기 쿠키는 Hub 주소에만"
n1=$(nsess)
dev_login "$(sed -n 2p "$DIR/codes2")" "$DEV" >/dev/null
n2=$(nsess)
[ "$n2" = "$n1" ] && ok "같은 기기 재로그인 → 세션 수 그대로 ($n2)" || bad "같은 기기 세션 누적 ($n1 → $n2)"
dev_login "$(sed -n 3p "$DIR/codes2")" "another-device-0123456789abcdef" >/dev/null
[ "$(nsess)" = "$((n2 + 1))" ] && ok "다른 기기 로그인은 새 세션" || bad "다른 기기 ($(nsess))"

# 속도 제한 (로그인 시도와 같은 한도)
for _ in $(seq 35); do last=$(recover zzzz-zzzz-zzzz); done
[ "$last" = 429 ] && ok "반복 시도 제한" || bad "속도 제한 ($last)"

echo "$PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
