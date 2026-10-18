#!/bin/bash
# 보안 감시 E2E: Hub + Agent(시험용 journald 파일·감시 파일) + 가짜 텔레그램.
# 첫 발생 알림 → 반복은 조용 → "문제 없음" 후 무시 → 관리 계정 sudo는 기록만 → 중요 파일 변경 알림 → 다시 알리기.
# 사용: tests/e2e/security_flow.sh [douve-hub 경로] [dist 디렉터리]
set -u
export DOUVE_LANG=ko # CLI 출력 언어 고정 (영어 확인은 따로)
HUB=${1:-build/hub/douve-hub}
DIST=$(cd "${2:-dist}" && pwd)
AGENT="$DIST/douve-agent-linux-$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"
HP=18880; TP=18881
BASE="http://localhost:$HP"
DIR=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$DIR"' EXIT
PASS=0; FAIL=0
ok()   { echo "  ok   $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL+1)); }
for p in $HP $TP; do ss -ltn | grep -q ":$p " && { echo "포트 $p 사용 중"; exit 1; }; done

cat > "$DIR/tg.py" <<'PY'
import sys, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        q = urllib.parse.parse_qs(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode())
        open(sys.argv[2], "a").write(q.get("text", [""])[0].replace("\n", " ") + "\n")
        self.send_response(200); self.end_headers(); self.wfile.write(b'{"ok":true}')
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
python3 "$DIR/tg.py" $TP "$DIR/tg.log" &
cat > "$DIR/hub.json" <<JSON
{"public_url":"$BASE","cookie_domain":"localhost","database_path":"$DIR/hub.db","listen_port":$HP,"agent_dir":"$DIST",
 "telegram":{"bot_token":"123456789:AAAbbbCCCdddEEEfffGGGhhhIIIjjjKKK","chat_id":"1","api_url":"http://127.0.0.1:$TP"}}
JSON
"$HUB" --config "$DIR/hub.json" >"$DIR/hub.log" 2>&1 &
for _ in $(seq 50); do curl -sf "$BASE/healthz" >/dev/null && break; sleep 0.1; done
python3 - "$DIR/hub.db" <<'PY'
import hashlib, sqlite3, sys, time
db = sqlite3.connect(sys.argv[1]); now = int(time.time())
db.execute("INSERT INTO users (id, email, created_at, allowed, role) VALUES (1, 'me@example.com', ?, 1, 'admin')", (now,))
db.execute("INSERT INTO sessions VALUES (?, 1, 'passkey', ?, ?, ?, ?, ?, '', '', '')",
           (hashlib.sha256(b"sec-fresh-session-0123456789abcdef").digest(), now, now, now + 3600, now + 7200, now))
db.commit()
PY
S="douve_session=sec-fresh-session-0123456789abcdef"
post() { curl -s -X POST -H "Cookie: $S" -H "Origin: $BASE" -H 'Content-Type: application/json' -d "$2" "$BASE$1"; }
issues() { curl -s -H "Cookie: $S" "$BASE/api/security"; }
J="$DIR/journal"; W="$DIR/authorized_keys"
echo "key1" > "$W"; : > "$J"
ME=$(id -un)
# root로 돌면(CI 컨테이너) Agent는 sudo 그룹의 일반 계정(uid 1000+)만 관리 계정으로 본다 → 하나 만든다
if [ "$(id -u)" = 0 ]; then
    getent group sudo >/dev/null || groupadd sudo
    id -u douveci >/dev/null 2>&1 || useradd -m -u 1500 -G sudo -s /bin/bash douveci
    ME=douveci
fi
jl() { python3 -c 'import json,sys,time; print(json.dumps({"SYSLOG_IDENTIFIER":sys.argv[1],"MESSAGE":sys.argv[2],"__REALTIME_TIMESTAMP":str(int(time.time()*1e6)),"__CURSOR":"c"}))' "$1" "$2" >> "$J"; }
wait_tg() { for _ in $(seq 60); do [ "$(wc -l < "$DIR/tg.log" 2>/dev/null || echo 0)" -ge "$1" ] && return 0; sleep 0.1; done; return 1; }
wait_text() { for _ in $(seq 60); do grep -q "$1" "$DIR/tg.log" 2>/dev/null && return 0; sleep 0.1; done; return 1; }

TOKEN=$("$HUB" join-token --config "$DIR/hub.json" --name sec1 2>/dev/null | awk '{print $NF}')
"$AGENT" join --dir "$DIR/agent" --hub "http://127.0.0.1:$HP" --token "$TOKEN" >/dev/null 2>&1
DOUVE_TEST_JOURNAL_FILE="$J" DOUVE_TEST_WATCH_FILES="$W" DOUVE_TEST_SECURITY_INTERVAL=500ms STATE_DIRECTORY="$DIR/state" \
    "$AGENT" run --dir "$DIR/agent" >"$DIR/agent.log" 2>&1 &
for _ in $(seq 100); do curl -s -H "Cookie: $S" "$BASE/api/nodes/1" | grep -q "\"$ME\"" && break; sleep 0.1; done
sleep 1
: > "$DIR/tg.log" # 등록 알림("서버 추가됨") 제외

echo "[security_flow]"
jl sshd-session "Accepted publickey for monitor from 10.200.0.2 port 40000 ssh2: ED25519 SHA256:x"
wait_tg 1 && grep -q "SSH 로그인: monitor" "$DIR/tg.log" && ok "새 SSH 로그인 → 텔레그램 알림" || bad "첫 알림 ($(cat "$DIR/tg.log" 2>/dev/null))"
grep -q "$BASE/security" "$DIR/tg.log" && ok "알림에 확인 링크" || bad "링크"
jl sshd-session "Accepted publickey for monitor from 10.200.0.2 port 40001 ssh2: ED25519 SHA256:x"
jl sshd-session "Accepted publickey for monitor from 10.200.0.2 port 40002 ssh2: ED25519 SHA256:x"
sleep 1.5
[ "$(wc -l < "$DIR/tg.log")" = 1 ] && ok "같은 이슈 반복은 다시 알리지 않음" || bad "반복 알림 ($(cat "$DIR/tg.log"))"
issues | python3 -c 'import json,sys; i=[x for x in json.load(sys.stdin)["issues"] if x["kind"]=="ssh_login"][0]; assert i["count"]==3 and i["status"]=="open"' \
    && ok "이슈 묶음 (3회, 열림)" || bad "이슈 묶음"
FP=$(issues | python3 -c 'import json,sys; print([x for x in json.load(sys.stdin)["issues"] if x["kind"]=="ssh_login"][0]["fingerprint"])')
out=$(curl -s -X POST -H "Cookie: $S" -H 'Content-Type: application/json' -d "{\"fingerprints\":[\"$FP\"],\"mode\":\"ignore\"}" "$BASE/api/security/resolve")
case "$out" in *error*) ok "Origin 없는 처리 요청 거부(CSRF)" ;; *) bad "CSRF ($out)";; esac
out=$(post /api/security/resolve "{\"fingerprints\":[\"$FP\"],\"mode\":\"ignore\"}")
case "$out" in *'"updated":1'*) ok "문제 없음(무시) 처리" ;; *) bad "무시 ($out)";; esac
jl sshd-session "Accepted publickey for monitor from 10.200.0.2 port 40003 ssh2: ED25519 SHA256:x"
jl sudo "   $ME : TTY=pts/9 ; PWD=/home ; USER=root ; COMMAND=/bin/systemctl restart x"
sleep 1.5
[ "$(wc -l < "$DIR/tg.log")" = 1 ] && ok "무시한 이슈·관리 계정 sudo는 알리지 않음" || bad "조용해야 함 ($(cat "$DIR/tg.log"))"
issues | python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(e["kind"]=="sudo" and e["status"]=="info" for e in d["events"]) and not any(i["kind"]=="sudo" for i in d["issues"])' \
    && ok "관리 계정 sudo는 기록만 (이슈 아님)" || bad "sudo 분류"
jl sudo "monitor :  PWD=/home/monitor ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
echo "key2" >> "$W"
wait_text "중요 파일 변경" && wait_text "sudo: monitor" \
    && ok "관리 계정 아닌 sudo·authorized_keys 변경 알림" || bad "중요 알림 ($(cat "$DIR/tg.log"))"
grep -q "🚨" "$DIR/tg.log" && ok "심각 이슈 표시" || bad "심각 표시"
out=$(post /api/security/reopen "{\"fingerprint\":\"$FP\"}")
jl sshd-session "Accepted publickey for monitor from 10.200.0.2 port 40004 ssh2: ED25519 SHA256:x"
wait_text "다시 발생" && ok "다시 알리기 → 다음 발생 때 알림" || bad "재개 ($out / $(tail -1 "$DIR/tg.log"))"
ev=$(sqlite3 "$DIR/hub.db" "SELECT group_concat(event, ',') FROM audit_log")
case "$ev" in *security_ignored*security_reopened*) ok "감사 로그" ;; *) bad "감사 로그 ($ev)";; esac

# 기능 끄기: SSH 감시를 끄면 Agent가 보고하지 않고, 터미널을 끄면 티켓 거부
got=$(curl -s -H "Cookie: $S" "$BASE/api/settings")
echo "$got" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["agent_expose"] is True and d["features"]["security"]["ssh"] is True' \
    && ok "설정 조회에 기능·노드 공개 상태" || bad "설정 조회 ($got)"
out=$(post /api/settings/save '{"features":{"monitoring":true,"service_checks":true,"terminal":false,"security":{"ssh":false,"sudo":true,"account":true,"files":true,"ports":true}}}')
case "$out" in *'"ok"'*) ok "기능 설정 저장" ;; *) bad "기능 저장 ($out)";; esac
for _ in $(seq 50); do grep -q "기능 설정 갱신" "$DIR/agent.log" && break; sleep 0.1; done
grep -q "기능 설정 갱신" "$DIR/agent.log" && ok "접속 중인 Agent에 즉시 반영" || bad "Agent 반영"
before=$(sqlite3 "$DIR/hub.db" "SELECT count(*) FROM security_events WHERE kind='ssh_login'")
jl sshd-session "Accepted publickey for root from 203.0.113.9 port 1 ssh2: ED25519 SHA256:x"
sleep 1.5
after=$(sqlite3 "$DIR/hub.db" "SELECT count(*) FROM security_events WHERE kind='ssh_login'")
[ "$before" = "$after" ] && ok "SSH 감시를 끄면 보고하지 않음" || bad "SSH 끄기 ($before → $after)"
out=$(post /api/terminal/options "{\"node_id\":1,\"user\":\"$ME\"}")
echo "$out" | python3 -c 'import json,sys; assert "꺼져" in json.load(sys.stdin)["error"]' && ok "웹 터미널을 끄면 열기 요청 거부" || bad "터미널 끄기 ($out)"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
