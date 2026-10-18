#!/bin/bash
# 역할·권한 E2E: 관리자 / 운영자(서버 1만) / 앱 사용자(앱 하나만)로 같은 API를 불러 서버 쪽에서
# 막히는지 확인한다. 화면에서 숨기는 것과 별개로 API가 닫혀 있어야 한다.
# 사용: tests/e2e/rbac_flow.sh [douve-hub 경로]
set -u
export DOUVE_LANG=ko
HUB=${1:-build/hub/douve-hub}
HP=18870
BASE="http://localhost:$HP"
DIR=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$DIR"' EXIT
PASS=0; FAIL=0
ok()   { echo "  ok   $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL+1)); }
ss -ltn | grep -q ":$HP " && { echo "포트 $HP 사용 중"; exit 1; }

cat > "$DIR/hub.json" <<JSON
{"public_url":"$BASE","cookie_domain":"localhost","database_path":"$DIR/hub.db","listen_port":$HP}
JSON
"$HUB" --config "$DIR/hub.json" >"$DIR/hub.log" 2>&1 &
for _ in $(seq 50); do curl -sf "$BASE/healthz" >/dev/null && break; sleep 0.1; done
python3 - "$DIR/hub.db" <<'PY'
import hashlib, os, sqlite3, sys, time
db = sqlite3.connect(sys.argv[1]); now = int(time.time())
for uid, email, role in ((1, "admin@example.com", "admin"), (2, "op@example.com", "operator"), (3, "app@example.com", "app")):
    db.execute("INSERT INTO users (id, email, created_at, allowed, role) VALUES (?, ?, ?, 1, ?)", (uid, email, now, role))
    tok = f"rbac-{role}-session-0123456789abcdef"
    db.execute("INSERT INTO sessions VALUES (?, ?, 'passkey', ?, ?, ?, ?, ?, '', '', '')",
               (hashlib.sha256(tok.encode()).digest(), uid, now, now, now + 3600, now + 7200, now))
for nid, name, mesh in ((1, "web1", "10.9.0.1"), (2, "db1", "10.9.0.2")):
    db.execute("INSERT INTO nodes (id, name, pubkey, created_at, mesh_address) VALUES (?, ?, ?, ?, ?)",
               (nid, name, os.urandom(32), now, mesh))
db.execute("INSERT INTO user_grants VALUES (2, 'node', 1)")
db.commit()
PY
A=rbac-admin-session-0123456789abcdef; OP=rbac-operator-session-0123456789abcdef; AP=rbac-app-session-0123456789abcdef
get()  { curl -s -o /dev/null -w '%{http_code}' -H "Cookie: douve_session=$1" "$BASE$2"; }
body() { curl -s -H "Cookie: douve_session=$1" "$BASE$2"; }
post() { curl -s -X POST -H "Cookie: douve_session=$1" -H "Origin: $BASE" -H 'Content-Type: application/json' -d "$3" "$BASE$2"; }
code() { curl -s -o /dev/null -w '%{http_code}' -X POST -H "Cookie: douve_session=$1" -H "Origin: $BASE" -H 'Content-Type: application/json' -d "$3" "$BASE$2"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)" 2>/dev/null; }

echo "[rbac_flow]"
# 관리자가 서버별 서비스 두 개를 만든다
S1=$(post $A /api/services/create '{"name":"wiki","host":"wiki.localhost","upstream":"10.9.0.1:3000","node_id":1}' | jget 'd["id"]')
S2=$(post $A /api/services/create '{"name":"pgadmin","host":"pg.localhost","upstream":"10.9.0.2:5050","node_id":2}' | jget 'd["id"]')
[ -n "$S1" ] && [ -n "$S2" ] && ok "관리자: 서비스 생성" || bad "서비스 생성 ($S1 $S2)"
sqlite3 "$DIR/hub.db" "INSERT INTO user_grants VALUES (3, 'service', $S1)"

# 경로별 역할 (표에 없는 경로는 관리자 전용)
f0=$FAIL
for p in /api/settings /api/channels /api/users /api/security /api/terminal/recordings; do
    [ "$(get $OP $p)" = 403 ] && [ "$(get $AP $p)" = 403 ] && [ "$(get $A $p)" = 200 ] \
        || bad "관리자 전용 $p (op $(get $OP $p) app $(get $AP $p) admin $(get $A $p))"
done
[ $FAIL = $f0 ] && ok "설정·알림·사용자·보안·녹화는 관리자만"
[ "$(code $OP /api/nodes/delete '{"id":1}')" = 403 ] && [ "$(code $OP /api/invites/create '{"email":"x@example.com"}')" = 403 ] \
    && ok "운영자: 서버 삭제·초대 불가" || bad "운영자 쓰기 권한"
[ "$(get $AP /api/nodes)" = 403 ] && [ "$(get $AP /api/services)" = 403 ] && [ "$(get $AP /api/nodes/1)" = 403 ] \
    && ok "앱 사용자: 서버·서비스 화면 불가" || bad "앱 사용자 서버 접근"
[ "$(get $AP /api/me)" = 200 ] && [ "$(get $AP /api/passkeys)" = 200 ] && ok "앱 사용자: 내 계정은 가능" || bad "내 계정"

# 운영자: 허락된 서버만
ids=$(body $OP /api/nodes | jget '[n["id"] for n in d["nodes"]]')
[ "$ids" = "[1]" ] && ok "운영자: 서버 목록에 허락된 서버만" || bad "운영자 서버 목록 ($ids)"
[ "$(get $OP /api/nodes/1)" = 200 ] && [ "$(get $OP /api/nodes/2)" = 404 ] && [ "$(get $OP /api/nodes/2/metrics)" = 404 ] \
    && ok "운영자: 다른 서버 상세·그래프 불가" || bad "운영자 서버 상세"
out=$(body $OP /api/nodes); case "$out" in *'"nodes"'*) echo "$out" | grep -q security_open && bad "운영자에게 보안 이슈 수" || ok "운영자: 보안 이슈 수 숨김" ;; *) bad "운영자 서버 목록 응답 ($out)";; esac
svc=$(body $OP /api/services | jget '[s["name"] for s in d["services"]]')
[ "$svc" = "['wiki']" ] && ok "운영자: 허락된 서버의 서비스만" || bad "운영자 서비스 목록 ($svc)"
[ "$(code $OP /api/terminal/options '{"node_id":2,"user":"root"}')" = 404 ] && ok "운영자: 다른 서버 터미널 불가" || bad "운영자 터미널"
# 서비스 관리: 자기 서버의 포트만
out=$(post $OP /api/services/create '{"name":"blog","host":"blog.localhost","upstream":"10.9.0.1:8080","node_id":1}')
case "$out" in *'"ok":true'*) ok "운영자: 자기 서버 서비스 생성" ;; *) bad "운영자 생성 ($out)";; esac
f0=$FAIL
for b in '{"name":"x1","host":"x1.localhost","upstream":"10.9.0.2:5432","node_id":1}' \
         '{"name":"x2","host":"x2.localhost","upstream":"10.9.0.2:5432","node_id":2}' \
         '{"name":"x3","host":"x3.localhost","upstream":"127.0.0.1:8700","node_id":1}' \
         '{"name":"x4","host":"x4.localhost","upstream":"10.9.0.1:80","node_id":1,"kind":"redirect","redirect_to":"https://evil.example.org"}' \
         '{"name":"x5","host":"x5.localhost","upstream":"10.9.0.1:80"}'; do
    c=$(code $OP /api/services/create "$b")
    [ "$c" = 403 ] || bad "운영자가 막혀야 하는 서비스 ($c $b)"
done
[ $FAIL = $f0 ] && ok "운영자: 다른 서버·Hub·리다이렉트·노드 없는 서비스 불가"
[ "$(code $OP /api/services/update "{\"id\":$S2,\"auth\":\"public\"}")" = 404 ] && [ "$(code $OP /api/services/delete "{\"id\":$S2}")" = 404 ] \
    && ok "운영자: 다른 서버 서비스 수정·삭제 불가" || bad "운영자 수정"
[ "$(code $OP /api/services/update "{\"id\":$S1,\"upstream\":\"10.9.0.2:5432\"}")" = 403 ] \
    && ok "운영자: 서비스를 다른 서버로 돌릴 수 없음" || bad "업스트림 바꾸기"

# 앱 사용자: 허락된 앱만 (입구가 묻는 /auth/verify)
vcode() { curl -s -o /dev/null -w '%{http_code}' -H "Cookie: douve_session=$1" "$BASE/auth/verify$2"; }
[ "$(vcode $AP "?service=$S1")" = 200 ] && [ "$(vcode $AP "?service=$S2")" = 403 ] && [ "$(vcode $AP "")" = 403 ] \
    && ok "앱 사용자: 허락된 앱만 통과" || bad "앱 확인 ($(vcode $AP "?service=$S1") $(vcode $AP "?service=$S2") $(vcode $AP ""))"
[ "$(vcode $OP "?service=$S1")" = 200 ] && [ "$(vcode $OP "?service=$S2")" = 403 ] && ok "운영자: 자기 서버의 앱만 통과" || bad "운영자 앱"
[ "$(vcode $A "?service=$S2")" = 200 ] && [ "$(vcode $A "")" = 200 ] && ok "관리자: 모든 앱" || bad "관리자 앱"
[ "$(vcode nope "?service=$S1")" = 401 ] && ok "로그인 안 하면 401" || bad "401"
items=$(body $AP /api/home | jget '[i["name"] for i in d["items"]]')
[ "$items" = "['wiki']" ] && ok "앱 사용자 홈: 허락된 앱만" || bad "홈 ($items)"
[ "$(body $AP /api/summary | jget 'd["servers"]')" = 0 ] && ok "앱 사용자 요약: 서버 수 0" || bad "요약"
[ "$(get $AP "/api/icons/service/$S2")" = 404 ] && ok "앱 사용자: 다른 앱 아이콘 불가" || bad "아이콘"

# 사용자 관리 (관리자, 패스키 재확인)
out=$(post $A /api/users/update '{"id":3,"role":"operator","nodes":[2,99]}')
case "$out" in *'"nodes":[2]'*) ok "역할 변경 (없는 서버 id는 버림)" ;; *) bad "역할 변경 ($out)";; esac
[ "$(vcode $AP "?service=$S2")" = 200 ] && ok "바꾼 권한이 바로 적용" || bad "즉시 적용"
out=$(post $A /api/users/update '{"id":1,"role":"app"}' | jget 'd.get("error","")')
case "$out" in *"마지막 관리자"*) ok "마지막 관리자는 강등 불가" ;; *) bad "마지막 관리자 ($out)";; esac
out=$(post $A /api/users/update '{"id":3,"role":"root"}')
case "$out" in *error*) ok "모르는 역할 거부" ;; *) bad "역할 검사 ($out)";; esac
[ "$(code $OP /api/users/update '{"id":2,"role":"admin"}')" = 403 ] && ok "운영자가 자기 권한을 올릴 수 없음" || bad "권한 상승"
out=$(post $A /api/users/delete '{"id":1}' | jget 'd.get("error","")')
case "$out" in *"자기 자신"*) ok "자기 자신 삭제 불가" ;; *) bad "자기 삭제 ($out)";; esac
out=$(post $A /api/users/delete '{"id":3}')
case "$out" in *'"ok"'*) ok "사용자 삭제" ;; *) bad "삭제 ($out)";; esac
[ "$(get $AP /api/me)" = 401 ] && ok "삭제된 사용자의 세션은 끊김" || bad "삭제 후 세션"
ev=$(sqlite3 "$DIR/hub.db" "SELECT group_concat(event, ',') FROM audit_log")
case "$ev" in *user_access_changed*user_deleted*) ok "권한 변경·삭제 감사 기록" ;; *) bad "감사 ($ev)";; esac
out=$(post $A /api/invites/create '{"email":"new@example.com","role":"operator","nodes":[1]}')
role=$(sqlite3 "$DIR/hub.db" "SELECT role || ' ' || grants FROM invites WHERE email = 'new@example.com'")
[ "$role" = 'operator {"nodes":[1],"services":[]}' ] && ok "초대에 역할·권한 저장" || bad "초대 역할 ($role $out)"
post $A /api/invites/create '{"email":"def@example.com"}' >/dev/null
[ "$(sqlite3 "$DIR/hub.db" "SELECT role FROM invites WHERE email = 'def@example.com'")" = app ] \
    && ok "역할을 정하지 않은 초대는 가장 좁은 권한(app)" || bad "초대 기본 역할"

# 화면 (Playwright가 있으면)
if [ -d "$(dirname "$0")/browser/node_modules/playwright" ]; then
    sqlite3 "$DIR/hub.db" "INSERT INTO users (id, email, created_at, allowed, role) VALUES (4, 'app2@example.com', $(date +%s), 1, 'app'); INSERT INTO user_grants VALUES (4, 'service', $S1)"
    python3 - "$DIR/hub.db" <<'PY'
import hashlib, sqlite3, sys, time
db = sqlite3.connect(sys.argv[1]); now = int(time.time())
db.execute("INSERT INTO sessions VALUES (?, 4, 'passkey', ?, ?, ?, ?, ?, '', '', '')",
           (hashlib.sha256(b"rbac-app2-session-0123456789abcdef").digest(), now, now, now + 3600, now + 7200, now))
db.commit()
PY
    out=$(cd "$(dirname "$0")/browser" && BASE=$BASE ADMIN=$A OP=$OP APP=rbac-app2-session-0123456789abcdef SHOT=${SHOT:-} node rbac_flow.mjs 2>&1)
    echo "$out" | grep -E '^  (ok|FAIL)'
    PASS=$((PASS + $(echo "$out" | grep -c '^  ok'))); FAIL=$((FAIL + $(echo "$out" | grep -c '^  FAIL')))
    echo "$out" | grep -qE '^  (ok|FAIL)' || bad "브라우저 시험 실행 ($out)"
fi

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
