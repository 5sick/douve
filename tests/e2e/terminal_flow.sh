#!/bin/bash
# 웹 터미널 E2E: douve-hub + douve-agent(현재 계정 셸) + 실제 Chromium(xterm.js).
# 티켓 권한 검사 → 브라우저에서 명령 실행 → 종료 → 감사 로그·녹화 → 녹화 재생.
# 사용: tests/e2e/terminal_flow.sh [douve-hub 경로] [dist 디렉터리]
set -u
export DOUVE_LANG=ko # CLI 출력 언어 고정 (영어 확인은 따로)
HUB=$(realpath "${1:-build/hub/douve-hub}")
DIST=$(cd "${2:-dist}" && pwd)
AGENT="$DIST/douve-agent-linux-$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"
HERE=$(cd "$(dirname "$0")" && pwd)
HP=18850
BASE="http://localhost:$HP"
DIR=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$DIR"' EXIT
PASS=0; FAIL=0
ok()   { echo "  ok   $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL+1)); }
ss -ltn | grep -q ":$HP " && { echo "포트 $HP 사용 중"; exit 1; }

cat > "$DIR/hub.json" <<JSON
{"public_url":"$BASE","cookie_domain":"localhost","database_path":"$DIR/db/hub.db",
 "listen_port":$HP,"allowed_emails":["test@example.com"],"agent_dir":"$DIST"}
JSON
mkdir -p "$DIR/db"
"$HUB" --config "$DIR/hub.json" >"$DIR/hub.log" 2>&1 &
for _ in $(seq 50); do curl -sf "$BASE/healthz" >/dev/null && break; sleep 0.1; done
mksession() { python3 - "$DIR/db/hub.db" "$1" "$2" <<'PY'
import hashlib, sqlite3, sys, time
db = sqlite3.connect(sys.argv[1]); now = int(time.time())
db.execute("INSERT OR IGNORE INTO users (id, email, created_at) VALUES (1, 'test@example.com', ?)", (now,))
db.execute("INSERT INTO sessions VALUES (?, 1, 'passkey', ?, ?, ?, ?, ?, '', '', '')",
           (hashlib.sha256(sys.argv[2].encode()).digest(), now, now, now + 3600, now + 7200, now - int(sys.argv[3])))
db.commit()
PY
}
FRESH=term-fresh-session-0123456789abcdef; STALE=term-stale-session-0123456789abcdef
OLD=term-old-session-0123456789abcdefgh
mksession $FRESH 0; mksession $STALE 120; mksession $OLD 600
post() { curl -s -X POST -H "Cookie: douve_session=$1" -H "Origin: $BASE" -H 'Content-Type: application/json' -d "$3" "$BASE$2"; }

TOKEN=$("$HUB" join-token --config "$DIR/hub.json" --name term1 2>/dev/null | awk '{print $NF}')
"$AGENT" join --dir "$DIR/agent" --hub "http://127.0.0.1:$HP" --token "$TOKEN" >/dev/null 2>&1
STATE_DIRECTORY="$DIR/state" "$AGENT" run --dir "$DIR/agent" >"$DIR/agent.log" 2>&1 &
AGENT_PID=$!
ME=$(id -un)
for _ in $(seq 100); do curl -s -H "Cookie: douve_session=$FRESH" "$BASE/api/nodes/1" | grep -q "\"$ME\"" && break; sleep 0.1; done

echo "[terminal_flow]"
curl -s -H "Cookie: douve_session=$FRESH" "$BASE/api/nodes/1" | grep -q "\"terminal_users\":\[\"$ME\"\]" && ok "허용 계정 보고 ($ME)" || bad "허용 계정"
out=$(post $STALE /api/terminal/ticket "{\"node_id\":1,\"user\":\"$ME\"}")
case "$out" in *reauth_required*) ok "패스키 재확인(60초) 없으면 티켓 거부" ;; *) bad "재확인 ($out)";; esac
out=$(post $FRESH /api/terminal/ticket '{"node_id":1,"user":"root"}')
case "$out" in *error*) ok "허용되지 않은 계정(root) 거부" ;; *) bad "root ($out)";; esac
out=$(curl -s -X POST -H "Cookie: douve_session=$FRESH" -H 'Content-Type: application/json' -d "{\"node_id\":1,\"user\":\"$ME\"}" "$BASE/api/terminal/ticket")
case "$out" in *error*) ok "Origin 없는 티켓 요청 거부(CSRF)" ;; *) bad "CSRF ($out)";; esac

cd "$HERE/browser" && BASE=$BASE SESSION=$FRESH NODE=1 ME=$ME node terminal_flow.mjs
rc=$?; cd - >/dev/null
[ $rc = 0 ] && ok "브라우저 터미널 흐름 (위 항목)" || bad "브라우저 터미널 흐름"

ev=$(sqlite3 "$DIR/db/hub.db" "SELECT group_concat(event, ',') FROM (SELECT event FROM audit_log WHERE event LIKE 'terminal%' OR event = 'recording_viewed' ORDER BY id)")
case "$ev" in *terminal_opened*terminal_closed*recording_viewed*) ok "감사 로그 ($ev)" ;; *) bad "감사 로그 ($ev)";; esac
rec=$(ls "$DIR"/db/recordings/*.cast 2>/dev/null | head -1)
[ -n "$rec" ] && grep -q "douve-42" "$rec" && ok "출력 녹화(asciicast)" || bad "녹화 ($rec)"
grep -q "secret-input-xyz" "$rec" 2>/dev/null && bad "숨김 입력이 녹화에 남음" || ok "입력은 녹화하지 않음 (read -s 값 없음)"
name=$(basename "$rec")
out=$(post $OLD /api/terminal/recordings/delete "{\"names\":[\"$name\"]}")
case "$out" in *reauth_required*) ok "녹화 삭제는 패스키 재확인 필요" ;; *) bad "삭제 재확인 ($out)";; esac
out=$(post $FRESH /api/terminal/recordings/delete "{\"names\":[\"$name\",\"../hub.db\"]}")
case "$out" in *'"removed":1'*) ok "녹화 삭제 (경로 조작 이름은 무시)" ;; *) bad "삭제 ($out)";; esac
[ ! -e "$rec" ] && [ -e "$DIR/db/hub.db" ] && ok "녹화 파일 삭제됨, DB 무사" || bad "파일 상태"
sqlite3 "$DIR/db/hub.db" "SELECT count(*) FROM audit_log WHERE event='recording_deleted'" | grep -q '^1$' && ok "삭제 감사 로그" || bad "삭제 감사 로그"
[ "$(stat -c %a "$DIR/db/recordings")" = 700 ] && ok "녹화 폴더 권한 700" || bad "녹화 폴더 권한"
sleep 0.5; [ -z "$(pgrep -P $AGENT_PID)" ] && ok "종료 후 셸 프로세스 정리" || bad "셸 프로세스 남음 ($(pgrep -a -P $AGENT_PID))"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
