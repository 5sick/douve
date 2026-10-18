#!/bin/bash
# 보안 점검표 E2E: douve-hub + douve-agent(가짜 서버 파일·명령) + 소프트웨어 패스키(softkey.py).
# 점검 → 결과 저장 → 고치기(패스키 서명 → Hub 확인 → Agent가 다시 확인 → 실행) → 다시 점검 → 감사 로그.
# 사용: tests/e2e/checkup_flow.sh [douve-hub 경로] [dist 디렉터리]
set -u
export DOUVE_LANG=ko
HUB=$(realpath "${1:-build/hub/douve-hub}")
DIST=$(cd "${2:-dist}" && pwd)
AGENT="$DIST/douve-agent-linux-$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"
HERE=$(cd "$(dirname "$0")" && pwd)
HP=18870
BASE="http://localhost:$HP"
DIR=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$DIR"' EXIT
PASS=0; FAIL=0
ok()   { echo "  ok   $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL+1)); }
ss -ltn | grep -q ":$HP " && { echo "포트 $HP 사용 중"; exit 1; }

# 가짜 서버 (Ubuntu): 비밀번호 SSH 켜짐, 자동 업데이트 없음
R="$DIR/root"; mkdir -p "$R/etc/ssh/sshd_config.d" "$R/usr/sbin" "$R/state" "$DIR/bin"
printf 'ID=ubuntu\nID_LIKE=debian\n' > "$R/etc/os-release"
: > "$R/usr/sbin/sshd"
printf 'Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\nPermitRootLogin no\nUsePAM yes\n' > "$R/etc/ssh/sshd_config"
cat > "$DIR/bin/sshd" <<SH
#!/bin/sh
# 가짜 sshd: -T는 (Douve 설정 파일이 있으면 그 값이 먼저) 적용 값, -t는 검사 통과
if [ "\$1" = -t ]; then exit 0; fi
pw=yes; grep -qs '^PasswordAuthentication no' "$R/etc/ssh/sshd_config.d/00-douve.conf" && pw=no
printf 'passwordauthentication %s\nkbdinteractiveauthentication no\npermitrootlogin no\nusepam yes\n' \$pw
SH
cat > "$DIR/bin/dpkg-query" <<SH
#!/bin/sh
[ -f "$R/state/uu" ] && { echo "install ok installed"; exit 0; }; exit 1
SH
cat > "$DIR/bin/apt-get" <<SH
#!/bin/sh
touch "$R/state/uu"; echo "\$@" >> "$R/state/apt.log"
SH
cat > "$DIR/bin/systemctl" <<'SH'
#!/bin/sh
case "$1" in is-active) echo inactive; exit 3;; *) exit 0;; esac
SH
cat > "$DIR/bin/timedatectl" <<'SH'
#!/bin/sh
printf 'NTP=yes\nNTPSynchronized=yes\n'
SH
chmod +x "$DIR/bin/"*

cat > "$DIR/hub.json" <<JSON
{"public_url":"$BASE","cookie_domain":"localhost","database_path":"$DIR/hub.db",
 "listen_port":$HP,"allowed_emails":["test@example.com"],"agent_dir":"$DIST"}
JSON
"$HUB" --config "$DIR/hub.json" >"$DIR/hub.log" 2>&1 &
for _ in $(seq 50); do curl -sf "$BASE/healthz" >/dev/null && break; sleep 0.1; done
read -r CID COSE < <(python3 "$HERE/softkey.py" new "$DIR/key.json")
python3 - "$DIR/hub.db" "$CID" "$COSE" <<'PY'
import hashlib, sqlite3, sys, time
db = sqlite3.connect(sys.argv[1]); now = int(time.time())
db.execute("INSERT INTO users (id, email, created_at, role) VALUES (1, 'test@example.com', ?, 'admin')", (now,))
db.execute("INSERT INTO users (id, email, created_at, role, allowed) VALUES (2, 'app@example.com', ?, 'app', 1)", (now,))
db.execute("INSERT INTO passkeys (user_id, credential_id, public_key_cose, name, created_at) VALUES (1, ?, ?, '시험 키', ?)",
           (bytes.fromhex(sys.argv[2]), bytes.fromhex(sys.argv[3]), now))
for uid, tok in ((1, b"checkup-admin-session-0123456789abcd"), (2, b"checkup-app-session-0123456789abcdef")):
    db.execute("INSERT INTO sessions VALUES (?, ?, 'passkey', ?, ?, ?, ?, ?, '', '', '')",
               (hashlib.sha256(tok).digest(), uid, now, now, now + 3600, now + 7200, now))
db.commit()
PY
ADMIN="douve_session=checkup-admin-session-0123456789abcd"
APPU="douve_session=checkup-app-session-0123456789abcdef"
post() { curl -s -X POST -H "Cookie: $1" -H "Origin: $BASE" -H 'Content-Type: application/json' -d "$3" "$BASE$2"; }
get() { curl -s -H "Cookie: $ADMIN" "$BASE$1"; }
status_of() { get /api/checkup | python3 -c "import json,sys; d=json.load(sys.stdin); r={x['id']:x for x in d['nodes'][0].get('results',[])}; x=r.get('$1',{}); print(x.get('status',''), 'fixable' if x.get('fixable') else '')"; }
sign() { python3 "$HERE/softkey.py" sign "$DIR/key.json" "$BASE" localhost; }
fix() { # check → 고치기 결과 JSON
    local opts cred rid
    opts=$(post "$ADMIN" /api/checkup/fix/options "{\"node_id\":1,\"check\":\"$1\"}")
    cred=$(echo "$opts" | sign) || { echo "$opts"; return; }
    rid=$(post "$ADMIN" /api/checkup/fix "{\"pending\":\"$(echo "$opts" | python3 -c 'import json,sys; print(json.load(sys.stdin)["pending"])')\",\"credential\":$cred}" \
          | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("rid") or d)')
    for _ in $(seq 100); do st=$(get "/api/checkup/fix/status?rid=$rid"); case "$st" in *'"done":true'*) echo "$st"; return;; esac; sleep 0.1; done
    echo "시간 초과 $rid $st"
}

echo "[checkup_flow]"
A="$DIR/agent"
TOKEN=$("$HUB" join-token --config "$DIR/hub.json" --name box1 2>/dev/null | awk '{print $NF}')
"$AGENT" join --dir "$A" --hub "http://127.0.0.1:$HP" --token "$TOKEN" >/dev/null 2>&1 || bad "join"
PATH="$DIR/bin:$PATH" DOUVE_TEST_CHECKUP_ROOT="$R" STATE_DIRECTORY="$DIR/state" "$AGENT" run --dir "$A" >"$DIR/agent.log" 2>&1 &
for _ in $(seq 50); do grep -q "Hub 접속 완료" "$DIR/agent.log" && break; sleep 0.1; done
for _ in $(seq 50); do grep -q "터미널 신뢰 목록 갱신" "$DIR/agent.log" && break; sleep 0.1; done

out=$(post "$ADMIN" /api/checkup/run '{"node_id":1}')
case "$out" in *'"ok"'*) ok "다시 점검 요청" ;; *) bad "점검 요청 ($out)";; esac
for _ in $(seq 50); do [ -n "$(status_of ssh_password)" ] && break; sleep 0.1; done
[ "$(status_of ssh_password)" = "fail fixable" ] && ok "비밀번호 SSH 켜짐 → 위험, 고칠 수 있음" || bad "ssh_password ($(status_of ssh_password))"
[ "$(status_of ssh_root)" = "ok " ] && ok "root 로그인 막힘 → 정상" || bad "ssh_root ($(status_of ssh_root))"
[ "$(status_of auto_updates)" = "fail fixable" ] && ok "자동 업데이트 없음 → 위험" || bad "auto_updates ($(status_of auto_updates))"
[ "$(status_of time_sync)" = "ok " ] && ok "시간 동기화 정상" || bad "time_sync ($(status_of time_sync))"

out=$(post "$ADMIN" /api/checkup/fix/options '{"node_id":1,"check":"ssh_match"}')
case "$out" in *error*) ok "고칠 수 없는 항목 거부" ;; *) bad "ssh_match 고치기 ($out)";; esac
out=$(post "$APPU" /api/checkup/fix/options '{"node_id":1,"check":"ssh_password"}')
case "$out" in *error*) ok "앱 사용자는 고치기 불가" ;; *) bad "앱 사용자 ($out)";; esac
# 다른 항목용 서명으로 고치기 → Hub가 거부
opts=$(post "$ADMIN" /api/checkup/fix/options '{"node_id":1,"check":"ssh_password"}')
other=$(post "$ADMIN" /api/checkup/fix/options '{"node_id":1,"check":"auto_updates"}')
cred=$(echo "$other" | sign)
out=$(post "$ADMIN" /api/checkup/fix "{\"pending\":\"$(echo "$opts" | python3 -c 'import json,sys; print(json.load(sys.stdin)["pending"])')\",\"credential\":$cred}")
case "$out" in *'"rid"'*) bad "다른 항목 서명 통과 ($out)" ;; *) ok "다른 항목용 서명은 거부" ;; esac
[ ! -f "$R/etc/ssh/sshd_config.d/00-douve.conf" ] && ok "거부된 요청으로 바뀐 것 없음" || bad "설정이 바뀜"

st=$(fix ssh_password)
case "$st" in *'"ok":true'*) ok "패스키로 승인 → 서버가 서명 확인 후 비밀번호 SSH 끔" ;; *) bad "고치기 ($st)";; esac
grep -q "^PasswordAuthentication no" "$R/etc/ssh/sshd_config.d/00-douve.conf" && ok "설정 파일 00-douve.conf" || bad "설정 파일"
grep -q "보안 점검표 고치기.*by=test@example.com" "$DIR/agent.log" && ok "Agent 기록에 승인한 사람" || bad "Agent 기록"
for _ in $(seq 50); do [ "$(status_of ssh_password)" = "ok " ] && break; sleep 0.1; done
[ "$(status_of ssh_password)" = "ok " ] && ok "고친 뒤 다시 점검 → 정상" || bad "다시 점검 ($(status_of ssh_password))"
st=$(fix auto_updates)
case "$st" in *'"ok":true'*) ok "자동 보안 업데이트 설치·켜기" ;; *) bad "자동 업데이트 ($st)";; esac
grep -qs 'Unattended-Upgrade "1"' "$R/etc/apt/apt.conf.d/20auto-upgrades" && ok "20auto-upgrades" || bad "20auto-upgrades"

ev=$(sqlite3 "$DIR/hub.db" "SELECT group_concat(event, ',') FROM (SELECT event FROM audit_log WHERE event LIKE 'checkup%' ORDER BY id)")
case "$ev" in checkup_fix_requested,checkup_fixed,checkup_fix_requested,checkup_fixed) ok "감사 로그 ($ev)" ;; *) bad "감사 로그 ($ev)";; esac

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
