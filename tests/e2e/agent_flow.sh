#!/bin/bash
# Agent E2E: douve-hub + 실제 douve-agent 프로세스로 join → 접속 → 메트릭 → 삭제 흐름을 검증한다.
# 사용: tests/e2e/agent_flow.sh [douve-hub 경로] [dist 디렉터리]
set -u
export DOUVE_LANG=ko # CLI 출력 언어 고정 (영어 확인은 따로)
HUB=${1:-build/hub/douve-hub}
DIST=$(cd "${2:-dist}" && pwd)
AGENT="$DIST/douve-agent-linux-$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"
PORT=18810
BASE="http://localhost:$PORT"
DIR=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$DIR"' EXIT
PASS=0; FAIL=0
ok()   { echo "  ok   $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL+1)); }

if ss -ltn | grep -q ":$PORT "; then echo "포트 $PORT 사용 중"; exit 1; fi

# Hub가 배포하는 Agent 릴리스 (자동 업데이트 시험 때 VERSION만 바꾼다)
mkdir -p "$DIR/rel"; cp "$DIST"/douve-agent-linux-* "$DIST/SHA256SUMS" "$DIR/rel/"
"$AGENT" version | awk '{print $2}' > "$DIR/rel/VERSION"
cat > "$DIR/hub.json" <<JSON
{"public_url":"$BASE","cookie_domain":"localhost","database_path":"$DIR/hub.db",
 "listen_port":$PORT,"allowed_emails":["test@example.com"],"agent_dir":"$DIR/rel"}
JSON
"$HUB" --config "$DIR/hub.json" >"$DIR/hub.log" 2>&1 &
for _ in $(seq 50); do curl -sf "$BASE/healthz" >/dev/null && break; sleep 0.1; done

# 로그인 세션을 DB에 직접 만든다 (로그인 자체는 google_flow·passkey_flow가 검증)
mksession() { # 토큰 reauth_at
    python3 - "$DIR/hub.db" "$1" "$2" <<'PY'
import hashlib, sqlite3, sys, time
db = sqlite3.connect(sys.argv[1]); now = int(time.time())
db.execute("INSERT OR IGNORE INTO users (id, email, created_at, role) VALUES (1, 'test@example.com', ?, 'admin')", (now,))
db.execute("INSERT INTO sessions VALUES (?, 1, 'passkey', ?, ?, ?, ?, ?, '', '', '')",
           (hashlib.sha256(sys.argv[2].encode()).digest(), now, now, now + 3600, now + 7200, int(sys.argv[3])))
db.commit()
PY
}
mksession fresh-session-token-0123456789abcdef "$(date +%s)"
mksession stale-session-token-0123456789abcdef 1000
C="Cookie: douve_session=fresh-session-token-0123456789abcdef"
O="Origin: $BASE"
api() { curl -s -H "$C" "$@"; }

echo "[agent_flow]"
# 인증 전 메시지: 형식이 틀려도 Hub가 죽으면 안 된다 (Json 예외가 이벤트 루프 밖으로 새던 문제)
WS=$(dirname "$0")/ws_send.py
python3 "$WS" "localhost:$PORT" /api/agent/connect '{"type":[1]}' >/dev/null 2>&1
python3 "$WS" "localhost:$PORT" /api/agent/connect '{"type":"auth","node_id":"x","sig":{}}' >/dev/null 2>&1
python3 "$WS" "localhost:$PORT" /api/agent/connect "$(printf '[%.0s' $(seq 3000))" >/dev/null 2>&1
sleep 0.3
curl -sf "$BASE/healthz" >/dev/null && ok "형식이 틀린 Agent 메시지에도 Hub 유지" || bad "형식이 틀린 메시지로 Hub 종료"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$C" -H 'Content-Type: application/json' -d '{}' "$BASE/api/nodes/join-token")
[ "$code" = 403 ] && ok "Origin 없는 토큰 발급 거부(CSRF)" || bad "CSRF ($code)"
out=$(curl -s -X POST -H "Cookie: douve_session=stale-session-token-0123456789abcdef" -H "$O" -H 'Content-Type: application/json' -d '{}' "$BASE/api/nodes/join-token")
case "$out" in *reauth_required*) ok "패스키 재확인 없으면 토큰 발급 거부" ;; *) bad "재확인 ($out)";; esac
out=$(api -X POST -H "$O" -H 'Content-Type: application/json' -d '{"name":"Test Node"}' "$BASE/api/nodes/join-token")
TOKEN=$(echo "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' 2>/dev/null)
CMD=$(echo "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["command"])' 2>/dev/null)
[ -n "$TOKEN" ] && ok "join 토큰 발급" || bad "토큰 발급 ($out)"
case "$CMD" in "curl -fsSL $BASE/join.sh | sudo sh -s -- $TOKEN") ok "설치 명령 형식" ;; *) bad "설치 명령 ($CMD)";; esac

script=$(curl -s "$BASE/join.sh")
case "$script" in *"HUB=\"$BASE\""*) ok "join.sh에 Hub 주소 치환" ;; *) bad "join.sh";; esac
echo "$script" | sh -n && ok "join.sh 문법 (sh -n)" || bad "join.sh 문법"
expected=$(grep "$(basename "$AGENT")\$" "$DIST/SHA256SUMS" | cut -d' ' -f1)
actual=$(curl -s "$BASE/dl/$(basename "$AGENT")" | sha256sum | cut -d' ' -f1)
[ -n "$expected" ] && [ "$expected" = "$actual" ] && ok "Agent 바이너리 다운로드·체크섬" || bad "다운로드 체크섬"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/dl/hub.json")
[ "$code" = 404 ] && ok "허용 목록 외 파일 다운로드 거부" || bad "다운로드 제한 ($code)"

A="$DIR/agent"
"$AGENT" join --dir "$A" --hub "http://127.0.0.1:$PORT" --token "$TOKEN" >"$DIR/join.log" 2>&1 \
    && ok "douve-agent join" || bad "join ($(cat "$DIR/join.log"))"
[ "$(stat -c %a "$A/key")" = 600 ] && ok "개인키 권한 600" || bad "키 권한"
"$AGENT" join --dir "$DIR/agent2" --hub "http://127.0.0.1:$PORT" --token "$TOKEN" >/dev/null 2>&1 \
    && bad "토큰 재사용이 허용됨" || ok "토큰 재사용 거부"
"$AGENT" join --dir "$DIR/agent3" --hub "http://douve.example.com" --token x >/dev/null 2>&1 \
    && bad "공용 http 허용됨" || ok "공용 인터넷 평문 http 거부"

# CLI로 만든 토큰 (웹 화면 없이 서버 추가)
cmd=$("$HUB" join-token --config "$DIR/hub.json" --name cli-node --connect-url "http://127.0.0.1:$PORT" 2>/dev/null)
CLI_TOKEN=${cmd##* }
case "$cmd" in *"DOUVE_CONNECT_URL=http://127.0.0.1:$PORT sh -s -- "*) ok "join-token CLI 명령 형식" ;; *) bad "CLI 명령 ($cmd)";; esac
"$AGENT" join --dir "$DIR/cli" --hub "http://127.0.0.1:$PORT" --token "$CLI_TOKEN" >/dev/null 2>&1 \
    && ok "CLI 토큰으로 등록" || bad "CLI 토큰 등록"

"$AGENT" run --dir "$A" >"$DIR/agent.log" 2>&1 &
AGENT_PID=$!
connected=""; latest=""
for _ in $(seq 150); do
    out=$(api "$BASE/api/nodes")
    connected=$(echo "$out" | python3 -c 'import json,sys; n=[x for x in json.load(sys.stdin)["nodes"] if x["name"]=="test-node"]; print(n[0]["connected"] if n else "")' 2>/dev/null)
    latest=$(echo "$out" | python3 -c 'import json,sys; n=[x for x in json.load(sys.stdin)["nodes"] if x["name"]=="test-node"]; print("y" if n and n[0]["latest"] else "")' 2>/dev/null)
    [ "$latest" = y ] && break
    sleep 0.1
done
[ "$connected" = True ] && ok "Agent 서명 인증·접속" || bad "접속 ($(tail -3 "$DIR/agent.log"))"
[ "$latest" = y ] && ok "메트릭 수신" || bad "메트릭 ($out)"
names=$(echo "$out" | python3 -c 'import json,sys; print(",".join(x["name"] for x in json.load(sys.stdin)["nodes"]))' 2>/dev/null)
[ "$names" = "cli-node,test-node" ] && ok "토큰에 지정한 노드 이름" || bad "이름 ($names)"
detail=$(api "$BASE/api/nodes/1")
echo "$detail" | python3 -c 'import json,sys; d=json.load(sys.stdin)["inventory"]; assert d["system"]["cpus"]>0 and isinstance(d["ports"], list)' 2>/dev/null \
    && ok "인벤토리 수신 (시스템·포트)" || bad "인벤토리"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/nodes")
[ "$code" = 401 ] && ok "로그인 없이 노드 목록 거부" || bad "노드 목록 인증 ($code)"

# 다른 키로 같은 노드 ID 사칭
cp -r "$A" "$DIR/fake"; head -c 32 /dev/urandom > "$DIR/fake/key"
timeout 5 "$AGENT" run --dir "$DIR/fake" >"$DIR/fake.log" 2>&1
grep -q "거부" "$DIR/fake.log" && ok "다른 키로 사칭 거부" || bad "사칭 ($(tail -2 "$DIR/fake.log"))"
n=$(sqlite3 "$DIR/hub.db" "SELECT count(*) FROM audit_log WHERE event='agent_auth_failed'")
[ "$n" -ge 1 ] && ok "인증 실패 감사 로그" || bad "감사 로그 ($n)"
connected=$(api "$BASE/api/nodes" | python3 -c 'import json,sys; print([x for x in json.load(sys.stdin)["nodes"] if x["name"]=="test-node"][0]["connected"])')
[ "$connected" = True ] && ok "사칭 시도가 정상 접속을 끊지 않음" || bad "정상 접속 끊김"

# 노드 삭제 → 접속 종료, 재접속 거부
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Cookie: douve_session=stale-session-token-0123456789abcdef" -H "$O" -H 'Content-Type: application/json' -d '{"id":1}' "$BASE/api/nodes/delete")
[ "$code" = 403 ] && ok "재확인 없이 노드 삭제 거부" || bad "삭제 재확인 ($code)"
out=$(api -X POST -H "$O" -H 'Content-Type: application/json' -d '{"id":1}' "$BASE/api/nodes/delete")
case "$out" in *'"ok"'*) ok "노드 삭제" ;; *) bad "삭제 ($out)";; esac
for _ in $(seq 50); do grep -q "거부" "$DIR/agent.log" && break; sleep 0.1; done
grep -q "거부" "$DIR/agent.log" && ok "삭제된 노드 재접속 거부" || bad "삭제 후 재접속 ($(tail -3 "$DIR/agent.log"))"
kill $AGENT_PID 2>/dev/null

# 자동 업데이트: Hub의 버전이 다르면 Agent가 받아서 교체한 뒤 같은 PID에서 새 실행 파일로 exec (입구 끊김 최소화).
# 교체된 실행 파일도 같은 지시를 받지만 1시간 내 같은 체크섬은 건너뛰고 접속을 유지해야 한다.
# Agent는 SHA256SUMS가 믿는 키로 서명되어 있어야만 받는다 (Hub를 믿지 않음).
mkdir -p "$DIR/bin"; cp "$AGENT" "$DIR/bin/douve-agent"
echo "e2e-next" > "$DIR/rel/VERSION"
rm -f "$DIR/rel/SHA256SUMS.minisig"
STATE_DIRECTORY="$DIR/state" timeout 4 "$DIR/bin/douve-agent" run --dir "$DIR/cli" >"$DIR/unsigned.log" 2>&1
grep -q "서명 없는 릴리스는 받지 않습니다" "$DIR/unsigned.log" && cmp -s "$DIR/bin/douve-agent" "$AGENT" \
    && ok "서명 없는 업데이트 거부" || bad "서명 없는 업데이트 ($(tail -3 "$DIR/unsigned.log"))"
SIGN="$DIST/douve-sign"
"$SIGN" keygen "$DIR/other.key" "$DIR/other.pub" >/dev/null
"$SIGN" sign "$DIR/other.key" "$DIR/rel/SHA256SUMS" e2e-next >/dev/null
STATE_DIRECTORY="$DIR/state" timeout 4 "$DIR/bin/douve-agent" run --dir "$DIR/cli" >"$DIR/untrusted.log" 2>&1
grep -q "신뢰하는 키로 만든 서명이 아닙니다" "$DIR/untrusted.log" && ok "믿지 않는 키의 서명 거부" || bad "다른 키 ($(tail -3 "$DIR/untrusted.log"))"
"$SIGN" keygen "$DIR/test.key" "$DIR/test.pub" >/dev/null
"$SIGN" sign "$DIR/test.key" "$DIR/rel/SHA256SUMS" e2e-next >/dev/null
cp "$DIR/test.pub" "$DIR/cli/trusted-keys"
rm -f "$DIR/state/last-update.json"
STATE_DIRECTORY="$DIR/state" timeout 8 "$DIR/bin/douve-agent" run --dir "$DIR/cli" >"$DIR/upd.log" 2>&1
rc=$?
grep -q "새 버전으로 재시작" "$DIR/upd.log" && [ "$(grep -c 'douve-agent 시작' "$DIR/upd.log")" = 2 ] \
    && ok "자동 업데이트 → 같은 프로세스에서 새 실행 파일로 교체" || bad "자동 업데이트 ($(tail -4 "$DIR/upd.log"))"
cmp -s "$DIR/bin/douve-agent" "$AGENT" && [ -x "$DIR/bin/douve-agent" ] && ok "교체된 실행 파일 체크섬·권한" || bad "교체 파일"
grep -q "최근에 같은 업데이트" "$DIR/upd.log" && [ $rc = 124 ] && [ "$(grep -c 'Hub 접속 완료' "$DIR/upd.log")" -ge 2 ] \
    && ok "같은 업데이트 반복 방지 (교체 후에도 접속 유지)" || bad "반복 방지 (rc=$rc)"
grep -q "Agent 업데이트 지시" "$DIR/hub.log" && ok "Hub 업데이트 지시 로그" || bad "Hub 로그"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
