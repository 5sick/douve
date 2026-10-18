#!/bin/bash
# 입구(edge) E2E: douve-hub + edge 역할 douve-agent(TLS 없는 시험 모드) + 가짜 업스트림.
# 서비스 등록 → 라우팅 표 전송 → 로그인 보호·예외 경로·공개 → Hub 장애 시 동작 → 재시작 후 저장된 표로 서비스.
# 사용: tests/e2e/edge_flow.sh [douve-hub 경로] [dist 디렉터리]
set -u
export DOUVE_LANG=ko # CLI 출력 언어 고정 (영어 확인은 따로)
HUB=${1:-build/hub/douve-hub}
DIST=$(cd "${2:-dist}" && pwd)
AGENT="$DIST/douve-agent-linux-$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"
HP=18840; EP=18841; UP=18842; AP=18843; NP=18844
BASE="http://localhost:$HP"
DIR=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$DIR"' EXIT
PASS=0; FAIL=0
ok()   { echo "  ok   $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL+1)); }
for p in $HP $EP $UP $AP $NP; do ss -ltn | grep -q ":$p " && { echo "포트 $p 사용 중"; exit 1; }; done

# 가짜 업스트림: 받은 요청 정보를 JSON으로
cat > "$DIR/up.py" <<'PY'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        b = json.dumps({"host": self.headers.get("Host"), "path": self.path,
                        "cookie": self.headers.get("Cookie", ""), "user": self.headers.get("X-Douve-User", ""),
                        "realip": self.headers.get("X-Real-IP", "")}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
python3 "$DIR/up.py" $UP &
# 가짜 공유기 (NAT-PMP): 열린 포트를 파일에 기록
cat > "$DIR/natpmp.py" <<'PY'
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", int(sys.argv[1])))
maps = set()
while True:
    b, a = s.recvfrom(64)
    if len(b) == 2 and b[1] == 0:
        s.sendto(bytes([0, 128, 0, 0]) + b"\0\0\0\1" + bytes([203, 0, 113, 50]), a)
    elif len(b) == 12 and b[1] in (1, 2):
        port, life = struct.unpack(">H", b[4:6])[0], struct.unpack(">I", b[8:12])[0]
        key = ("udp" if b[1] == 1 else "tcp") + "/" + str(port)
        (maps.discard if life == 0 else maps.add)(key)
        open(sys.argv[2], "w").write(" ".join(sorted(maps)))
        s.sendto(bytes([0, 128 + b[1], 0, 0, 0, 0, 0, 1]) + b[4:6] + b[4:6] + b[8:12], a)
PY
python3 "$DIR/natpmp.py" $NP "$DIR/router" &
python3 -m http.server $AP --bind 127.0.0.1 --directory "$DIR" >/dev/null 2>&1 & # 아직 공개하지 않은 앱

cat > "$DIR/hub.json" <<JSON
{"public_url":"$BASE","cookie_domain":"localhost","database_path":"$DIR/hub.db",
 "listen_port":$HP,"allowed_emails":["test@example.com"],"agent_dir":"$DIST",
 "tunnel_url":"ws://127.0.0.1:$EP/_douve/tunnel"}
JSON
start_hub() { "$HUB" --config "$DIR/hub.json" >>"$DIR/hub.log" 2>&1 & HUB_PID=$!; for _ in $(seq 50); do curl -sf "$BASE/healthz" >/dev/null && break; sleep 0.1; done; }
start_hub

python3 - "$DIR/hub.db" <<'PY'
import hashlib, sqlite3, sys, time
db = sqlite3.connect(sys.argv[1]); now = int(time.time())
db.execute("INSERT INTO users (id, email, created_at, role) VALUES (1, 'test@example.com', ?, 'admin')", (now,))
db.execute("INSERT INTO sessions VALUES (?, 1, 'passkey', ?, ?, ?, ?, ?, '', '', '')",
           (hashlib.sha256(b"edge-session-token-0123456789abcdef").digest(), now, now, now + 3600, now + 7200, now))
db.commit()
PY
SESSION="douve_session=edge-session-token-0123456789abcdef"
post() { curl -s -X POST -H "Cookie: $SESSION" -H "Origin: $BASE" -H 'Content-Type: application/json' -d "$2" "$BASE$1"; }
edge() { # host path [cookie] → "코드 Location 본문"
    curl -s -o "$DIR/body" -w '%{http_code} %{redirect_url}' -H "Host: $1" ${3:+-H "Cookie: $3"} "http://127.0.0.1:$EP$2"
}
jget() { python3 -c "import json,sys; print(json.load(open('$DIR/body')).get('$1',''))" 2>/dev/null; }

echo "[edge_flow]"
A="$DIR/agent"
TOKEN=$("$HUB" join-token --config "$DIR/hub.json" --name edge1 2>/dev/null | awk '{print $NF}')
"$AGENT" join --dir "$A" --hub "http://127.0.0.1:$HP" --token "$TOKEN" >/dev/null 2>&1 || bad "join"
echo "{\"http_addr\":\"127.0.0.1:$EP\",\"serve_plain\":true}" > "$A/edge.json"
DOUVE_TEST_NATPMP=127.0.0.1:$NP STATE_DIRECTORY="$DIR/state" "$AGENT" run --dir "$A" >"$DIR/agent.log" 2>&1 & AGENT_PID=$!
for _ in $(seq 50); do grep -q "Hub 접속 완료" "$DIR/agent.log" && break; sleep 0.1; done

out=$(post /api/nodes/edge '{"id":1,"edge":true}')
case "$out" in *'"ok"'*) ok "입구(edge) 지정" ;; *) bad "edge 지정 ($out)";; esac
out=$(post /api/services/create "{\"name\":\"app\",\"host\":\"app.localhost\",\"node_id\":1,\"upstream\":\"127.0.0.1:$UP\",\"auth\":\"douve\",\"public_paths\":[\"/hook/\"]}")
case "$out" in *'"ok"'*) ok "보호 서비스 등록" ;; *) bad "서비스 등록 ($out)";; esac
out=$(post /api/services/create "{\"name\":\"open\",\"host\":\"open.localhost\",\"node_id\":1,\"upstream\":\"127.0.0.1:$UP\",\"auth\":\"public\"}")
case "$out" in *'"ok"'*) ok "공개 서비스 등록" ;; *) bad "공개 등록 ($out)";; esac
out=$(post /api/services/create '{"name":"evil","host":"localhost","upstream":"127.0.0.1:1"}')
case "$out" in *error*) ok "Hub 도메인 가로채기 거부" ;; *) bad "Hub 도메인 ($out)";; esac
out=$(curl -s -X POST -H "Cookie: $SESSION" -H 'Content-Type: application/json' -d '{"name":"x","host":"x.localhost","upstream":"127.0.0.1:1"}' "$BASE/api/services/create")
case "$out" in *'"error"'*) ok "Origin 없는 서비스 등록 거부(CSRF)" ;; *) bad "CSRF ($out)";; esac

for _ in $(seq 50); do [ -f "$DIR/state/routes.json" ] && grep -q open.localhost "$DIR/state/routes.json" && break; sleep 0.1; done
grep -q open.localhost "$DIR/state/routes.json" 2>/dev/null && ok "라우팅 표 수신·저장" || bad "라우팅 표 저장"
for _ in $(seq 50); do r=$(edge app.localhost /x); [ "${r%% *}" != 000 ] && break; sleep 0.1; done

r=$(edge app.localhost "/page?a=1&b=2")
case "$r" in "302 $BASE/login?rd=http%3A%2F%2Fapp.localhost%2Fpage%3Fa%3D1%26b%3D2") ok "로그인 없으면 Hub 로그인으로 (rd 전체 보존)" ;; *) bad "리다이렉트 ($r)";; esac
r=$(edge app.localhost /page "$SESSION; theme=dark")
[ "${r%% *}" = 200 ] && [ "$(jget user)" = test@example.com ] && ok "로그인 세션 통과 + X-Douve-User" || bad "세션 통과 ($r $(cat "$DIR/body"))"
c=$(jget cookie); case "$c" in *douve_session*) bad "업스트림에 세션 쿠키 노출 ($c)" ;; *theme=dark*) ok "업스트림에 세션 쿠키 미전달, 다른 쿠키 유지" ;; *) bad "쿠키 ($c)";; esac
[ "$(jget host)" = "app.localhost" ] && ok "Host 유지" || bad "Host ($(jget host))"
r=$(edge app.localhost /hook/abc)
[ "${r%% *}" = 200 ] && ok "예외 경로는 로그인 없이" || bad "예외 경로 ($r)"
r=$(edge app.localhost /hookx)
[ "${r%% *}" = 302 ] && ok "예외 경로 접두사 경계 (/hookx는 보호)" || bad "접두사 경계 ($r)"
r=$(edge open.localhost / "$SESSION")
[ "${r%% *}" = 200 ] && [ -z "$(jget user)" ] && [ -z "$(jget cookie)" ] && ok "공개 서비스 (쿠키·사용자 헤더 없음)" || bad "공개 ($r)"
r=$(edge localhost /healthz)
[ "${r%% *}" = 200 ] && grep -q '"ok"' "$DIR/body" && ok "Hub 자신도 입구로 접근" || bad "Hub 경로 ($r)"
r=$(edge nope.localhost /)
[ "${r%% *}" = 404 ] && ok "등록 안 된 도메인 404" || bad "미등록 ($r)"

# 경로 접두사(같은 도메인에 두 번째 서비스) + 리다이렉트
out=$(post /api/services/create "{\"name\":\"app-api\",\"host\":\"app.localhost\",\"path_prefix\":\"/v1/\",\"strip_prefix\":true,\"node_id\":1,\"upstream\":\"127.0.0.1:$UP\",\"auth\":\"douve\"}")
case "$out" in *'"ok"'*) ok "같은 도메인에 경로 접두사 서비스 추가" ;; *) bad "경로 서비스 ($out)";; esac
out=$(post /api/services/create '{"name":"go","host":"go.localhost","kind":"redirect","redirect_to":"https://example.com/"}')
case "$out" in *'"ok"'*) ok "리다이렉트 서비스 추가" ;; *) bad "리다이렉트 ($out)";; esac
for _ in $(seq 30); do r=$(edge go.localhost "/x?y=1"); [ "${r%% *}" = 302 ] && break; sleep 0.1; done
[ "$r" = "302 https://example.com/x?y=1" ] && ok "리다이렉트 (경로·쿼리 유지)" || bad "리다이렉트 ($r)"
r=$(edge app.localhost "/v1/users?q=1" "$SESSION")
[ "${r%% *}" = 200 ] && [ "$(jget path)" = "/users?q=1" ] && ok "경로 접두사 라우팅·접두사 제거" || bad "접두사 ($r $(cat "$DIR/body"))"
post /api/services/delete '{"id":4}' >/dev/null; post /api/services/delete '{"id":3}' >/dev/null

svc=$(curl -s -H "Cookie: $SESSION" "$BASE/api/services")
echo "$svc" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert len(d["services"])==2 and d["edges"][0]["connected"]' 2>/dev/null \
    && ok "서비스 목록 API" || bad "서비스 목록 ($svc)"

apps=$(curl -s -H "Cookie: $SESSION" "$BASE/api/apps")
echo "$apps" | UP=$UP python3 -c '
import json,os,sys
d=json.load(sys.stdin); up=int(os.environ["UP"])
a=[x for x in d["apps"] if x["port"]==up]
assert a and a[0]["published"] and a[0]["published"]["name"]=="app", a
assert all(x["port"]!=22 for x in d["apps"])' 2>"$DIR/apps.err" \
    && ok "실행 중인 앱 API (공개 여부 표시)" || bad "앱 API ($(cat "$DIR/apps.err") $apps)"
if [ -d "$(dirname "$0")/browser/node_modules" ]; then
    out=$(cd "$(dirname "$0")/browser" && BASE=$BASE SESSION=$SESSION APP_PORT=$AP SHOT=${SHOT:-} node apps_flow.mjs 2>&1)
    echo "$out"
    PASS=$((PASS + $(grep -c '^  ok' <<<"$out"))); FAIL=$((FAIL + $(grep -c '^  FAIL' <<<"$out")))
    # 처리한 보안 이슈·열린 이슈도 영어로 보이는지 (화면에 문구가 생기도록 하나씩)
    sqlite3 "$DIR/hub.db" "INSERT OR IGNORE INTO security_issues VALUES ('t|1|a',1,'sudo','warn','sudo: bob → root: /usr/bin/id',1,1,2,'acked',1,1,NULL),
        ('t|1|b',1,'ssh_login','warn','SSH 로그인: bob (192.0.2.1, publickey)',1,1,1,'open',NULL,NULL,NULL)"
    out=$(cd "$(dirname "$0")/browser" && BASE=$BASE SESSION=$SESSION node i18n_flow.mjs 2>&1)
    echo "$out"
    PASS=$((PASS + $(grep -c '^  ok' <<<"$out"))); FAIL=$((FAIL + $(grep -c '^  FAIL' <<<"$out")))
fi

out=$(post /api/services/update '{"id":1,"auth":"public"}')
for _ in $(seq 30); do r=$(edge app.localhost /page); [ "${r%% *}" = 200 ] && break; sleep 0.1; done
[ "${r%% *}" = 200 ] && ok "정책 변경(공개) 즉시 반영" || bad "정책 변경 ($out / $r)"
out=$(post /api/services/delete '{"id":1}')
for _ in $(seq 30); do r=$(edge app.localhost /page); [ "${r%% *}" = 404 ] && break; sleep 0.1; done
[ "${r%% *}" = 404 ] && ok "서비스 삭제 즉시 반영" || bad "삭제 ($out / $r)"
post /api/services/create "{\"name\":\"app\",\"host\":\"app.localhost\",\"node_id\":1,\"upstream\":\"127.0.0.1:$UP\",\"auth\":\"douve\"}" >/dev/null
for _ in $(seq 30); do r=$(edge app.localhost /page); [ "${r%% *}" = 302 ] && break; sleep 0.1; done

# 노드에서 바로 공개 (douve-agent expose) — 업스트림은 127.0.0.1에만 열려 있지만 이 노드가 입구라 허용
X="env STATE_DIRECTORY=$DIR/state $AGENT"
out=$($X expose $UP --name exp --public 2>&1)
case "$out" in *"공개됨: https://exp.localhost"*) ok "douve-agent expose → 공개 URL" ;; *) bad "expose ($out)";; esac
for _ in $(seq 30); do r=$(edge exp.localhost /hello); [ "${r%% *}" = 200 ] && break; sleep 0.1; done
[ "${r%% *}" = 200 ] && ok "노드에서 공개한 서비스 접속" || bad "expose 접속 ($r)"
$X exposed 2>&1 | grep -q "exp " && ok "douve-agent exposed 목록" || bad "exposed 목록"
out=$($X expose $UP --name evil --host evil.example.com 2>&1)
case "$out" in *"아래 도메인만"*) ok "기본 도메인 밖 공개 거부" ;; *) bad "도메인 제한 ($out)";; esac
out=$(DOUVE_LANG=en $X expose $UP --name evil --host evil.example.com 2>&1)
case "$out" in *"Servers can only publish domains under"*) ok "CLI 영어 (Hub 오류도 영어)" ;; *) bad "CLI 영어 ($out)";; esac
curl -s -H "Host: nowhere.localhost" -H "Accept-Language: en-US" "http://127.0.0.1:$EP/" | grep -q "Unknown address" && ok "입구 오류 화면 영어 (Accept-Language)" || bad "입구 오류 영어"
curl -s -H "Host: nowhere.localhost" -H "Accept-Language: ko-KR" "http://127.0.0.1:$EP/" | grep -q "알 수 없는 주소" && ok "입구 오류 화면 한국어" || bad "입구 오류 한국어"
out=$($X expose $UP --name app 2>&1)
case "$out" in *"이미 있습니다"*) ok "웹에서 만든 서비스는 노드가 덮어쓸 수 없음" ;; *) bad "덮어쓰기 ($out)";; esac
$X unexpose exp >/dev/null 2>&1
for _ in $(seq 30); do r=$(edge exp.localhost /hello); [ "${r%% *}" = 404 ] && break; sleep 0.1; done
[ "${r%% *}" = 404 ] && ok "douve-agent unexpose" || bad "unexpose ($r)"
post /api/settings/save '{"agent_expose":false}' >/dev/null
out=$($X expose $UP --name exp2 2>&1)
case "$out" in *"꺼져 있습니다"*) ok "설정에서 끄면 노드 공개 거부" ;; *) bad "설정 끄기 ($out)";; esac
grep -q "service_exposed" <<<"$(sqlite3 "$DIR/hub.db" "SELECT group_concat(event) FROM audit_log")" && ok "공개 감사 로그" || bad "감사 로그"

# 공유기 포트 자동 열기: 켜면 입구 노드가 공유기(가짜 NAT-PMP)에 80/443을 요청하고 결과를 보고
out=$(post /api/nodes/portforward '{"id":1,"on":true}')
for _ in $(seq 50); do [ "$(cat "$DIR/router" 2>/dev/null)" = "tcp/443 tcp/80" ] && break; sleep 0.1; done
[ "$(cat "$DIR/router" 2>/dev/null)" = "tcp/443 tcp/80" ] && ok "공유기에 80·443 요청 (NAT-PMP)" || bad "공유기 포트 ($out / $(cat "$DIR/router" 2>/dev/null))"
for _ in $(seq 50); do
    pm=$(curl -s -H "Cookie: $SESSION" "$BASE/api/nodes/1")
    echo "$pm" | python3 -c 'import json,sys; p=json.load(sys.stdin)["portmap"]; assert p["gateway"]=="natpmp" and p["external_ip"]=="203.0.113.50" and all(m["ok"] for m in p["mappings"]) and len(p["mappings"])==2' 2>/dev/null && break
    sleep 0.1
done
echo "$pm" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["port_forward"] and d["portmap"]["gateway"]=="natpmp"' 2>/dev/null \
    && ok "공유기 상태 보고 (종류·외부 주소·포트별 결과)" || bad "공유기 상태 ($pm)"
post /api/nodes/portforward '{"id":1,"on":false}' >/dev/null
for _ in $(seq 50); do [ -z "$(cat "$DIR/router")" ] && break; sleep 0.1; done
[ -z "$(cat "$DIR/router")" ] && ok "끄면 공유기 포트 닫음" || bad "포트 닫기 ($(cat "$DIR/router"))"
grep -q '"port_forward_on"\|port_forward_on' <<<"$(sqlite3 "$DIR/hub.db" "SELECT group_concat(event) FROM audit_log")" && ok "공유기 포트 감사 로그" || bad "감사 로그"

# Agent 터널: 입구가 아닌 두 번째 서버(home)의 서비스를 터널로만 연결 (직통 길이 없는 집 서버 가정)
post /api/settings/save '{"agent_expose":true}' >/dev/null
T2=$("$HUB" join-token --config "$DIR/hub.json" --name home 2>/dev/null | awk '{print $NF}')
"$AGENT" join --dir "$DIR/agent2" --hub "http://127.0.0.1:$HP" --token "$T2" >/dev/null 2>&1
STATE_DIRECTORY="$DIR/state2" "$AGENT" run --dir "$DIR/agent2" >"$DIR/agent2.log" 2>&1 &
for _ in $(seq 100); do grep -q "Hub 접속 완료" "$DIR/agent2.log" && break; sleep 0.1; done
# 연결 방식이 직통(direct)이어도 127.0.0.1 업스트림은 그 노드 안에서만 닿으니 터널로 간다
post /api/nodes/connect '{"id":2,"mode":"direct"}' >/dev/null
out=$(post /api/services/create "{\"name\":\"homeapp\",\"host\":\"homeapp.localhost\",\"node_id\":2,\"upstream\":\"127.0.0.1:$UP\",\"auth\":\"public\"}")
case "$out" in *'"ok"'*) ok "두 번째 서버 서비스 등록 (직통 + 127.0.0.1 업스트림)" ;; *) bad "home 서비스 ($out)";; esac
for _ in $(seq 100); do grep -q "터널 연결됨" "$DIR/agent2.log" && break; sleep 0.1; done
grep -q "터널 연결됨" "$DIR/agent2.log" && ok "Agent가 입구로 터널 연결 (루프백 업스트림이면 직통 모드여도)" || bad "터널 연결 ($(tail -3 "$DIR/agent2.log"))"
grep -q "터널 연결됨" "$DIR/agent.log" && bad "입구 노드가 자기에게 터널을 염" || ok "입구 노드는 터널 없음"
for _ in $(seq 50); do r=$(edge homeapp.localhost /via-tunnel); [ "${r%% *}" = 200 ] && break; sleep 0.1; done
[ "${r%% *}" = 200 ] && [ "$(jget path)" = "/via-tunnel" ] && ok "터널로 서비스 접속" || bad "터널 접속 ($r)"
grep -q "터널 연결" "$DIR/agent.log" && ok "입구 쪽 터널 수락 로그" || bad "입구 로그"
post /api/services/delete "{\"id\":$(sqlite3 "$DIR/hub.db" "SELECT id FROM services WHERE name='homeapp'")}" >/dev/null
for _ in $(seq 100); do grep -q "터널 끊김" "$DIR/agent.log" && break; sleep 0.1; done
grep -q "터널 끊김" "$DIR/agent.log" && ok "서비스가 없어지면 터널을 닫음" || bad "터널 닫기 (home log: $(tail -5 "$DIR/agent2.log") || hub: $(tail -4 "$DIR/hub.log"))"
kill %?"agent2" 2>/dev/null; pkill -f "run --dir $DIR/agent2" 2>/dev/null

# Hub 장애: 보호 서비스는 막히고(fail-closed) 공개 서비스는 계속
kill $HUB_PID; wait $HUB_PID 2>/dev/null
r=$(edge app.localhost /page "douve_session=another-token-0123456789abcdefghij")
[ "${r%% *}" = 502 ] && ok "Hub 장애 시 보호 서비스 차단(fail-closed)" || bad "Hub 장애 보호 ($r)"
r=$(edge open.localhost /)
[ "${r%% *}" = 200 ] && ok "Hub 장애 중에도 공개 서비스 유지" || bad "Hub 장애 공개 ($r)"
kill $AGENT_PID; wait $AGENT_PID 2>/dev/null
STATE_DIRECTORY="$DIR/state" "$AGENT" run --dir "$A" >"$DIR/agent2.log" 2>&1 & AGENT_PID=$!
for _ in $(seq 50); do r=$(edge open.localhost /); [ "${r%% *}" = 200 ] && break; sleep 0.1; done
[ "${r%% *}" = 200 ] && ok "Hub 없이 재시작해도 저장된 표로 서비스" || bad "저장된 표 ($r)"

start_hub
for _ in $(seq 100); do grep -q "Hub 접속 완료" "$DIR/agent2.log" && break; sleep 0.1; done
out=$(post /api/nodes/edge '{"id":1,"edge":false}')
for _ in $(seq 30); do r=$(edge open.localhost /); [ "${r%% *}" = 000 ] && break; sleep 0.1; done
[ "${r%% *}" = 000 ] && ok "입구 해제 시 수신 중지" || bad "입구 해제 ($out / $r)"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
