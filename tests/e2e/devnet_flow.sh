#!/bin/bash
# 내부 길(기기 WireGuard) E2E: douve-hub + 입구 douve-agent + 가짜 업스트림 + 시험용 기기(probe).
# 켜기 → 기기 등록(설정 파일) → 기기 DNS·HTTPS로 내부 전용 앱 → 공개 입구에는 없음 → 권한 → 기기 삭제
# → Hub가 꺼져도 저장된 표로 계속.
# 사용: tests/e2e/devnet_flow.sh [douve-hub 경로] [dist 디렉터리]
set -u
export DOUVE_LANG=ko
HUB=$(realpath "${1:-build/hub/douve-hub}")
DIST=$(cd "${2:-dist}" && pwd)
AGENT="$DIST/douve-agent-linux-$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"
HERE=$(cd "$(dirname "$0")" && pwd)
HP=18860; EP=18861; UP=18862; WP=18863
BASE="http://localhost:$HP"
DIR=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$DIR"' EXIT
PASS=0; FAIL=0
ok()   { echo "  ok   $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL+1)); }
for p in $HP $EP $UP; do ss -ltn | grep -q ":$p " && { echo "포트 $p 사용 중"; exit 1; }; done
ss -lun | grep -q ":$WP " && { echo "UDP $WP 사용 중"; exit 1; }

# 시험 기기: CI는 미리 빌드한 것(PROBE), 아니면 여기서 빌드
if [ -n "${PROBE:-}" ]; then cp "$PROBE" "$DIR/probe" && chmod +x "$DIR/probe"
else (cd "$HERE/../../agent" && go build -o "$DIR/probe" ./internal/devnet/probe) || { echo "probe 빌드 실패"; exit 1; }; fi

cat > "$DIR/up.py" <<'PY'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        b = json.dumps({"host": self.headers.get("Host"), "user": self.headers.get("X-Douve-User", "")}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
python3 "$DIR/up.py" $UP &
# 입구 인증서 (시험용 자체 서명: 내부 길 HTTPS도 입구 인증서를 쓴다)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=test \
  -addext "subjectAltName=DNS:*.example.test,DNS:localhost" -keyout "$DIR/key.pem" -out "$DIR/cert.pem" 2>/dev/null

cat > "$DIR/hub.json" <<JSON
{"public_url":"$BASE","cookie_domain":"localhost","database_path":"$DIR/hub.db",
 "listen_port":$HP,"allowed_emails":["test@example.com"],"agent_dir":"$DIST"}
JSON
start_hub() { "$HUB" --config "$DIR/hub.json" >>"$DIR/hub.log" 2>&1 & HUB_PID=$!; for _ in $(seq 50); do curl -sf "$BASE/healthz" >/dev/null && break; sleep 0.1; done; }
start_hub
python3 - "$DIR/hub.db" <<'PY'
import hashlib, sqlite3, sys, time
db = sqlite3.connect(sys.argv[1]); now = int(time.time())
db.execute("INSERT INTO users (id, email, created_at, role) VALUES (1, 'test@example.com', ?, 'admin')", (now,))
db.execute("INSERT INTO users (id, email, created_at, role, allowed) VALUES (2, 'app@example.com', ?, 'app', 1)", (now,))
for uid, tok in ((1, b"devnet-admin-session-0123456789abcdef"), (2, b"devnet-appuser-session-0123456789abcd")):
    db.execute("INSERT INTO sessions VALUES (?, ?, 'passkey', ?, ?, ?, ?, ?, '', '', '')",
               (hashlib.sha256(tok).digest(), uid, now, now, now + 3600, now + 7200, now))
db.commit()
PY
ADMIN="douve_session=devnet-admin-session-0123456789abcdef"
APPU="douve_session=devnet-appuser-session-0123456789abcd"
post() { curl -s -X POST -H "Cookie: $1" -H "Origin: $BASE" -H 'Content-Type: application/json' -d "$3" "$BASE$2"; }
jq_() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
# 시험 기기는 실행할 때마다 새로 핸드셰이크한다. WireGuard는 같은 키의 핸드셰이크가 20ms 안에 다시 오면
# (재전송 공격 방지) 버리고 5초 뒤 재시도하므로 사이를 조금 둔다 (실제 기기에서는 생기지 않는 간격)
probe() { sleep 0.1; "$DIR/probe" -conf "$1" -url "$2" -endpoint "127.0.0.1:$WP" -timeout "${3:-5s}"; }

echo "[devnet_flow]"
A="$DIR/agent"
TOKEN=$("$HUB" join-token --config "$DIR/hub.json" --name edge1 2>/dev/null | awk '{print $NF}')
"$AGENT" join --dir "$A" --hub "http://127.0.0.1:$HP" --token "$TOKEN" >/dev/null 2>&1 || bad "join"
echo "{\"http_addr\":\"127.0.0.1:$EP\",\"serve_plain\":true,\"fallback_certs\":[{\"cert\":\"$DIR/cert.pem\",\"key\":\"$DIR/key.pem\"}]}" > "$A/edge.json"
start_agent() { STATE_DIRECTORY="$DIR/state" "$AGENT" run --dir "$A" >>"$DIR/agent.log" 2>&1 & AGENT_PID=$!; }
start_agent
for _ in $(seq 50); do grep -q "Hub 접속 완료" "$DIR/agent.log" && break; sleep 0.1; done
post "$ADMIN" /api/nodes/edge '{"id":1,"edge":true}' >/dev/null

# 꺼져 있으면 기기 추가 불가
out=$(post "$ADMIN" /api/devices/create '{"name":"폰"}')
case "$out" in *error*) ok "꺼져 있으면 기기 추가 거부" ;; *) bad "꺼짐 ($out)";; esac
out=$(post "$APPU" /api/devnet/update "{\"enabled\":true,\"port\":$WP}")
case "$out" in *error*) ok "관리자만 내부 길 설정" ;; *) bad "설정 권한 ($out)";; esac
out=$(post "$ADMIN" /api/devnet/update "{\"enabled\":true,\"port\":$WP}")
case "$out" in *'"enabled":true'*) ok "내부 길 켜기" ;; *) bad "켜기 ($out)";; esac
for _ in $(seq 100); do curl -s -H "Cookie: $ADMIN" "$BASE/api/devnet" | grep -q '"ready":true' && break; sleep 0.1; done
st=$(curl -s -H "Cookie: $ADMIN" "$BASE/api/devnet")
echo "$st" | grep -q '"ready":true' && ok "입구가 WireGuard 키를 알림 → 준비됨" || bad "준비 ($st)"
for _ in $(seq 50); do grep -q "내부 길 시작" "$DIR/agent.log" && break; sleep 0.1; done
grep -q "내부 길 시작" "$DIR/agent.log" && ok "입구에서 내부 길 시작 (UDP $WP)" || bad "내부 길 시작 ($(grep devnet "$DIR/agent.log" | tail -2))"

# 서비스: 내부 전용 / 외부 전용 / 둘 다
mk() { post "$ADMIN" /api/services/create "{\"name\":\"$1\",\"host\":\"$1.example.test\",\"node_id\":1,\"upstream\":\"127.0.0.1:$UP\",\"auth\":\"douve\",\"internal\":$2,\"external\":$3}"; }
out=$(mk inapp true false); case "$out" in *'"ok"'*) ok "내부 전용 서비스" ;; *) bad "내부 전용 ($out)";; esac
INID=$(echo "$out" | jq_ 'd["id"]')
mk outapp false true | grep -q '"ok"' && ok "외부 전용 서비스" || bad "외부 전용"
mk both true true | grep -q '"ok"' && ok "내부+외부 서비스" || bad "둘 다"
out=$(mk none false false); case "$out" in *error*) ok "둘 다 끄면 거부" ;; *) bad "둘 다 끔 ($out)";; esac

# 공개 입구: 내부 전용은 없는 도메인 (404), 외부는 로그인으로
for _ in $(seq 50); do grep -q both.example.test "$DIR/state/routes.json" 2>/dev/null && break; sleep 0.1; done
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: inapp.example.test" "http://127.0.0.1:$EP/")
[ "$code" = 404 ] && ok "내부 전용 앱은 공개 입구에 없음 (404)" || bad "공개 입구 내부 전용 ($code)"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: outapp.example.test" "http://127.0.0.1:$EP/")
[ "$code" = 302 ] && ok "외부 앱은 공개 입구에서 로그인으로" || bad "외부 앱 ($code)"

# 기기 등록 (관리자): 설정 파일 = 개인키 포함, DB에는 공개키만
out=$(post "$ADMIN" /api/devices/create '{"name":"내 폰"}')
echo "$out" | jq_ 'd["config"]' > "$DIR/me.conf"
grep -q "^PrivateKey = " "$DIR/me.conf" && grep -q "^DNS = 10.201.0.1" "$DIR/me.conf" && grep -q "^AllowedIPs = 10.201.0.0/24" "$DIR/me.conf" \
  && ok "기기 설정 파일 (개인키·DNS·내부 길만)" || bad "설정 파일 ($out)"
PRIV=$(grep "^PrivateKey" "$DIR/me.conf" | awk '{print $3}')
sqlite3 "$DIR/hub.db" "SELECT count(*) FROM devices WHERE pubkey = '$PRIV'" | grep -q '^0$' && ! grep -rq "$PRIV" "$DIR/hub.db" \
  && ok "Hub DB에 개인키 없음" || bad "개인키가 DB에"
for _ in $(seq 50); do grep -q "10.201.0.2" "$DIR/state/routes.json" 2>/dev/null && break; sleep 0.1; done

r=$(probe "$DIR/me.conf" https://inapp.example.test/)
case "$r" in "200 "*'"host": "inapp.example.test"'*'"user": "test@example.com"'*) ok "기기에서 내부 전용 앱 (DNS → 입구, 로그인 없이 신원 전달)" ;; *) bad "내부 앱 ($r)";; esac
r=$(probe "$DIR/me.conf" https://both.example.test/)
case "$r" in "200 "*) ok "내부+외부 앱도 기기에서는 내부 길로" ;; *) bad "둘 다 ($r)";; esac
r=$(probe "$DIR/me.conf" https://localhost/healthz)
case "$r" in "200 "*) ok "Douve 화면도 내부 길로" ;; *) bad "Hub 내부 길 ($r)";; esac
r=$(probe "$DIR/me.conf" https://outapp.example.test/ 3s)
case "$r" in "200 "*) bad "외부 전용 앱이 내부 길에 있음 ($r)" ;; *) ok "외부 전용 앱은 내부 길에 없음 (DNS가 넘김)" ;; esac
curl -s -H "Cookie: $ADMIN" "$BASE/api/devices" | grep -q '"last_handshake":[1-9]' || sleep 31
curl -s -H "Cookie: $ADMIN" "$BASE/api/devices" | grep -q '"last_handshake":[1-9]' && ok "기기 연결 상태 보고" || bad "연결 상태 ($(curl -s -H "Cookie: $ADMIN" "$BASE/api/devices"))"

# 앱 사용자: 허락받은 앱만
out=$(post "$APPU" /api/devices/create '{"name":"앱 사용자 폰"}')
echo "$out" | jq_ 'd["config"]' > "$DIR/app.conf"
for _ in $(seq 50); do grep -q "10.201.0.3" "$DIR/state/routes.json" 2>/dev/null && break; sleep 0.1; done
r=$(probe "$DIR/app.conf" https://inapp.example.test/)
case "$r" in "403 "*) ok "권한 없는 앱은 403" ;; *) bad "권한 없음 ($r)";; esac
post "$ADMIN" /api/users/update "{\"id\":2,\"role\":\"app\",\"nodes\":[],\"services\":[$INID]}" >/dev/null
sleep 0.5
r=$(probe "$DIR/app.conf" https://inapp.example.test/)
case "$r" in "200 "*'app@example.com'*) ok "권한을 주면 바로 열림" ;; *) bad "권한 부여 ($r)";; esac
APPDEV=$(curl -s -H "Cookie: $APPU" "$BASE/api/devices" | jq_ 'd["devices"][0]["id"]')
out=$(post "$APPU" /api/devices/delete '{"id":1}')
case "$out" in *error*) ok "남의 기기는 못 지움" ;; *) bad "남의 기기 삭제 ($out)";; esac
post "$APPU" /api/devices/delete "{\"id\":$APPDEV}" >/dev/null
sleep 0.5
r=$(probe "$DIR/app.conf" https://inapp.example.test/ 3s)
case "$r" in ERR*) ok "지운 기기는 바로 연결 안 됨" ;; *) bad "지운 기기 ($r)";; esac

# Hub가 꺼져도 입구는 저장된 표로 내부 길을 계속 연다 (Agent 재시작 포함)
kill $HUB_PID; wait $HUB_PID 2>/dev/null
kill $AGENT_PID; wait $AGENT_PID 2>/dev/null
start_agent
sleep 1
r=$(probe "$DIR/me.conf" https://inapp.example.test/ 8s)
case "$r" in "200 "*) ok "Hub 없이 저장된 표로 내부 길 (재시작 후 같은 키)" ;; *) bad "Hub 없이 ($r)";; esac

ev=$(sqlite3 "$DIR/hub.db" "SELECT group_concat(event, ',') FROM (SELECT event FROM audit_log WHERE event LIKE 'dev%' ORDER BY id)")
case "$ev" in devnet_updated,device_added,device_added,device_removed) ok "감사 로그 ($ev)" ;; *) bad "감사 로그 ($ev)";; esac

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
