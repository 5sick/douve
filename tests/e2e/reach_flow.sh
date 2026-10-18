#!/bin/bash
# 연결 진단 E2E: douve-hub + Agent 둘(입구 A, 서버 B) + 가짜 STUN(서버마다 다른 공인 주소).
# 진단 보고 → 외부 접속 검증(A가 B의 공인 주소로 22·80·443 시험) → 저장 → 길(입구·터널) → 입구 443 알림.
# 사용: tests/e2e/reach_flow.sh [douve-hub 경로] [dist 디렉터리]
set -u
export DOUVE_LANG=ko
HUB=$(realpath "${1:-build/hub/douve-hub}")
DIST=$(cd "${2:-dist}" && pwd)
AGENT="$DIST/douve-agent-linux-$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"
HP=18880; EP=18881; SA=18882; SB=18883; UP=18884
BASE="http://localhost:$HP"
DIR=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$DIR"' EXIT
PASS=0; FAIL=0
ok()   { echo "  ok   $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL+1)); }
for p in $HP $EP $UP; do ss -ltn | grep -q ":$p " && { echo "포트 $p 사용 중"; exit 1; }; done

# 가짜 STUN: 무엇을 물어도 정해진 공인 주소 (RFC 5389 XOR-MAPPED-ADDRESS)
cat > "$DIR/stun.py" <<'PY'
import socket, struct, sys
port, ip = int(sys.argv[1]), sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", port))
MAGIC = 0x2112A442
while True:
    b, a = s.recvfrom(1500)
    if len(b) < 20: continue
    xip = struct.unpack(">I", socket.inet_aton(ip))[0] ^ MAGIC
    attr = struct.pack(">HHBBHI", 0x0020, 8, 0, 1, 40000 ^ (MAGIC >> 16), xip)
    s.sendto(struct.pack(">HH", 0x0101, len(attr)) + b[4:20] + attr, a)
PY
python3 "$DIR/stun.py" $SA 203.0.113.10 &
python3 "$DIR/stun.py" $SB 203.0.113.20 &
python3 -m http.server $UP --bind 127.0.0.1 --directory "$DIR" >/dev/null 2>&1 &

cat > "$DIR/hub.json" <<JSON
{"public_url":"$BASE","cookie_domain":"localhost","database_path":"$DIR/hub.db",
 "listen_port":$HP,"allowed_emails":["test@example.com"],"agent_dir":"$DIST",
 "tunnel_url":"ws://127.0.0.1:$EP/_douve/tunnel"}
JSON
"$HUB" --config "$DIR/hub.json" >"$DIR/hub.log" 2>&1 &
for _ in $(seq 50); do curl -sf "$BASE/healthz" >/dev/null && break; sleep 0.1; done
python3 - "$DIR/hub.db" <<'PY'
import hashlib, sqlite3, sys, time
db = sqlite3.connect(sys.argv[1]); now = int(time.time())
db.execute("INSERT INTO users (id, email, created_at, role) VALUES (1, 'test@example.com', ?, 'admin')", (now,))
db.execute("INSERT INTO users (id, email, created_at, role, allowed) VALUES (2, 'app@example.com', ?, 'app', 1)", (now,))
for uid, tok in ((1, b"reach-admin-session-0123456789abcdef"), (2, b"reach-app-session-0123456789abcdefgh")):
    db.execute("INSERT INTO sessions VALUES (?, ?, 'passkey', ?, ?, ?, ?, ?, '', '', '')",
               (hashlib.sha256(tok).digest(), uid, now, now, now + 3600, now + 7200, now))
db.commit()
PY
ADMIN="douve_session=reach-admin-session-0123456789abcdef"
APPU="douve_session=reach-app-session-0123456789abcdefgh"
post() { curl -s -X POST -H "Cookie: $1" -H "Origin: $BASE" -H 'Content-Type: application/json' -d "$3" "$BASE$2"; }
reach() { # 노드이름 파이썬식(n = 그 노드)
    curl -s -H "Cookie: $ADMIN" "$BASE/api/reach" | NODE="$1" EXPR="$2" python3 -c 'import json,os,sys
d = {x["name"]: x for x in json.load(sys.stdin)["nodes"]}
n = d.get(os.environ["NODE"], {})
try: print(eval(os.environ["EXPR"]))
except Exception: print("")'
}

echo "[reach_flow]"
start_agent() { # 이름 STUN포트 [edge.json]
    local A="$DIR/$1" T
    T=$("$HUB" join-token --config "$DIR/hub.json" --name "$1" 2>/dev/null | awk '{print $NF}')
    "$AGENT" join --dir "$A" --hub "http://127.0.0.1:$HP" --token "$T" >/dev/null 2>&1 || bad "join $1"
    [ -n "${3:-}" ] && echo "$3" > "$A/edge.json"
    DOUVE_TEST_STUN="127.0.0.1:$2,127.0.0.1:$2" STATE_DIRECTORY="$DIR/state-$1" "$AGENT" run --dir "$A" >"$DIR/$1.log" 2>&1 &
    for _ in $(seq 50); do grep -q "Hub 접속 완료" "$DIR/$1.log" && break; sleep 0.1; done
}
start_agent nodea $SA "{\"http_addr\":\"127.0.0.1:$EP\",\"serve_plain\":true}"
start_agent nodeb $SB
post "$ADMIN" /api/nodes/edge '{"id":1,"edge":true}' >/dev/null
out=$(post "$ADMIN" /api/services/create "{\"name\":\"bapp\",\"host\":\"bapp.localhost\",\"node_id\":2,\"upstream\":\"127.0.0.1:$UP\",\"auth\":\"public\"}")
case "$out" in *'"ok"'*) ok "B에 서비스 (127.0.0.1 → 입구가 터널로)" ;; *) bad "서비스 ($out)";; esac

# 진단 보고 (첫 진단은 40초 뒤라 바로 요청)
for n in 1 2; do post "$ADMIN" /api/reach/run "{\"node_id\":$n}" >/dev/null; done
for _ in $(seq 100); do [ "$(reach nodeb "n.get('report',{}).get('stun',{}).get('public_ip')")" = 203.0.113.20 ] && [ "$(reach nodea "n.get('report',{}).get('stun',{}).get('public_ip')")" = 203.0.113.10 ] && break; sleep 0.1; done
[ "$(reach nodeb "n['report']['stun']['public_ip']")" = 203.0.113.20 ] && ok "STUN 공인 주소 보고" || bad "STUN ($(reach nodeb "n.get('report')"))"
[ "$(reach nodeb "n['report']['stun']['nat']")" = cone ] && ok "NAT 종류 (일반 NAT)" || bad "NAT ($(reach nodeb "n['report']['stun']"))"

# 외부 접속 검증: A(입구)가 B의 공인 주소로 시험
out=$(post "$ADMIN" /api/reach/run '{"node_id":2}')
echo "$out" | python3 -c "import json,sys; v=json.load(sys.stdin)['verify']; assert v['tested'] and v['tester']=='nodea' and v['host']=='203.0.113.20' and sorted(p['port'] for p in v['ports'])==[22,80,443]" \
  && ok "A가 B의 공인 주소로 22·80·443 시험" || bad "검증 ($out)"
[ "$(reach nodeb "n['verify']['tester']")" = nodea ] && ok "검증 결과 저장" || bad "검증 저장"
grep -q "reach_probe\|Probe" "$DIR/nodeb.log" && bad "B가 자기 자신을 시험함" || ok "시험은 다른 서버에서"
# 길: A는 입구, B는 터널 (입구가 다음 진단 때 터널 목록을 알림)
for _ in $(seq 50); do grep -q "터널" "$DIR/nodeb.log" && break; sleep 0.1; done
post "$ADMIN" /api/reach/run '{"node_id":1}' >/dev/null
for _ in $(seq 50); do [ "$(reach nodeb "n['path']")" = tunnel ] && break; sleep 0.2; done
[ "$(reach nodea "n['path']")" = edge ] && [ "$(reach nodeb "n['path']")" = tunnel ] && ok "길: A 입구, B 터널" || bad "길 ($(reach nodea "n['path']") $(reach nodeb "n['path']"))"
# 입구 443이 밖에서 안 열리면 두 번째에 알림 (상태가 바뀔 때만)
post "$ADMIN" /api/reach/run '{"node_id":1}' >/dev/null
grep -q "알림: 입구 서버 nodea에 인터넷에서 HTTPS(443)로 접속할 수 없습니다" "$DIR/hub.log" && ok "입구 443 알림 (두 번 연속 실패)" || bad "입구 알림 ($(grep 알림 "$DIR/hub.log" | tail -2))"
post "$ADMIN" /api/reach/run '{"node_id":1}' >/dev/null
[ "$(grep -c "알림: 입구 서버 nodea" "$DIR/hub.log")" = 1 ] && ok "같은 상태는 다시 알리지 않음" || bad "중복 알림"
# 권한
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Cookie: $APPU" "$BASE/api/reach")
[ "$code" = 403 ] && ok "앱 사용자는 진단 못 봄" || bad "앱 사용자 ($code)"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
