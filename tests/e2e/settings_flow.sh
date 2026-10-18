#!/bin/bash
# 웹 설정 E2E: 텔레그램 설정 저장(패스키 재확인·형식 검사·비밀값 숨김) → 가짜 텔레그램으로 테스트 발송 → 초대 링크.
# 사용: tests/e2e/settings_flow.sh [douve-hub 경로]
set -u
export DOUVE_LANG=ko # CLI 출력 언어 고정 (영어 확인은 따로)
HUB=${1:-build/hub/douve-hub}
HP=18860; TP=18861
BASE="http://localhost:$HP"
DIR=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$DIR"' EXIT
PASS=0; FAIL=0
ok()   { echo "  ok   $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL+1)); }
for p in $HP $TP; do ss -ltn | grep -q ":$p " && { echo "포트 $p 사용 중"; exit 1; }; done

# 가짜 텔레그램: 받은 요청을 파일에 남긴다. chat_id=bad면 400
cat > "$DIR/tg.py" <<'PY'
import sys, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        q = urllib.parse.parse_qs(body)
        open(sys.argv[2], "a").write(self.path + " " + q.get("chat_id", [""])[0] + " " + q.get("text", [""])[0] + "\n")
        code = 400 if q.get("chat_id", [""])[0] == "-1" else 200
        self.send_response(code); self.end_headers(); self.wfile.write(b'{"ok":true}')
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
python3 "$DIR/tg.py" $TP "$DIR/tg.log" &
cat > "$DIR/hub.json" <<JSON
{"public_url":"$BASE","cookie_domain":"localhost","database_path":"$DIR/hub.db","listen_port":$HP,
 "telegram":{"api_url":"http://127.0.0.1:$TP"}}
JSON
"$HUB" --config "$DIR/hub.json" >"$DIR/hub.log" 2>&1 &
for _ in $(seq 50); do curl -sf "$BASE/healthz" >/dev/null && break; sleep 0.1; done
python3 - "$DIR/hub.db" <<'PY'
import hashlib, sqlite3, sys, time
db = sqlite3.connect(sys.argv[1]); now = int(time.time())
db.execute("INSERT INTO users (id, email, created_at, allowed, role) VALUES (1, 'me@example.com', ?, 1, 'admin')", (now,))
for tok, re in (("set-fresh-session-0123456789abcdef", now), ("set-stale-session-0123456789abcdef", now - 3600)):
    db.execute("INSERT INTO sessions VALUES (?, 1, 'passkey', ?, ?, ?, ?, ?, '', '', '')",
               (hashlib.sha256(tok.encode()).digest(), now, now, now + 3600, now + 7200, re))
db.commit()
PY
post() { curl -s -X POST -H "Cookie: douve_session=$1" -H "Origin: $BASE" -H 'Content-Type: application/json' -d "$3" "$BASE$2"; }
F=set-fresh-session-0123456789abcdef; S=set-stale-session-0123456789abcdef
TOKEN=123456789:AAAbbbCCCdddEEEfffGGGhhhIIIjjjKKK

echo "[settings_flow]"
out=$(post $S /api/settings/save "{\"telegram\":{\"bot_token\":\"$TOKEN\",\"chat_id\":\"42\"}}")
case "$out" in *reauth_required*) ok "설정 저장은 패스키 재확인 필요" ;; *) bad "재확인 ($out)";; esac
out=$(post $F /api/settings/save '{"telegram":{"bot_token":"nope","chat_id":"42"}}')
case "$out" in *error*) ok "잘못된 봇 토큰 거부" ;; *) bad "형식 검사 ($out)";; esac
out=$(post $F /api/settings/save "{\"telegram\":{\"bot_token\":\"$TOKEN\",\"chat_id\":\"42\"}}")
case "$out" in *'"ok"'*) ok "텔레그램 설정 저장" ;; *) bad "저장 ($out)";; esac
got=$(curl -s -H "Cookie: douve_session=$F" "$BASE/api/settings")
echo "$got" | grep -q "$TOKEN" && bad "봇 토큰이 API에 노출됨" || ok "봇 토큰은 일부만 표시"
echo "$got" | grep -q '"enabled":true' && ok "알림 활성 표시" || bad "활성 표시 ($got)"
out=$(post $F /api/settings/telegram-test '{}')
case "$out" in *'"ok"'*) ok "테스트 발송 성공" ;; *) bad "테스트 발송 ($out)";; esac
grep -q "/bot$TOKEN/sendMessage 42 \[Douve\] 테스트" "$DIR/tg.log" && ok "가짜 텔레그램이 받은 내용" || bad "수신 ($(cat "$DIR/tg.log"))"
post $F /api/settings/save '{"telegram":{"chat_id":"-1"}}' >/dev/null
out=$(post $F /api/settings/telegram-test '{}')
case "$out" in *chat*) ok "잘못된 chat id 안내" ;; *) bad "실패 안내 ($out)";; esac
out=$(post $F /api/settings/save '{"telegram":{"clear":true}}')
grep -q '"enabled": false' <<<"$(curl -s -H "Cookie: douve_session=$F" "$BASE/api/settings" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["telegram"]))')" \
    && ok "텔레그램 끄기" || bad "끄기"
out=$(post $F /api/invites/create '{"email":"friend@example.com"}')
case "$out" in *"$BASE/invite#"*) ok "웹에서 초대 링크 생성" ;; *) bad "초대 ($out)";; esac
ev=$(sqlite3 "$DIR/hub.db" "SELECT group_concat(event, ',') FROM audit_log")
case "$ev" in *settings_changed*invite_created*) ok "감사 로그" ;; *) bad "감사 로그 ($ev)";; esac
curl -s "$BASE/auth/methods" | grep -q '"google":false' && ok "Google 미설정 표시" || bad "methods"

# 알림 채널: 웹훅(서명)·ntfy — 가짜 서버가 받은 요청을 확인
cat > "$DIR/hook.py" <<'PY'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        rec = {"path": self.path, "body": body, "sig": self.headers.get("X-Douve-Signature", ""),
               "ts": self.headers.get("X-Douve-Timestamp", ""), "prio": self.headers.get("Priority", ""),
               "auth": self.headers.get("Authorization", ""), "title": self.headers.get("Title", "")}
        open(sys.argv[2], "a").write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.send_response(500 if self.path == "/broken" else 200); self.end_headers()
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
WP=18862
python3 "$DIR/hook.py" $WP "$DIR/hook.log" &
sleep 0.3
out=$(post $S /api/channels/create "{\"kind\":\"webhook\",\"name\":\"hook\",\"config\":{\"url\":\"http://127.0.0.1:$WP/douve\",\"secret\":\"s3cr3t\"}}")
case "$out" in *reauth_required*) ok "채널 추가는 패스키 재확인 필요" ;; *) bad "채널 재확인 ($out)";; esac
out=$(post $F /api/channels/create '{"kind":"discord","config":{"url":"https://evil.example/api/webhooks/1/a"}}')
case "$out" in *error*) ok "Discord가 아닌 주소 거부" ;; *) bad "주소 검사 ($out)";; esac
out=$(post $F /api/channels/create "{\"kind\":\"webhook\",\"name\":\"hook\",\"config\":{\"url\":\"http://127.0.0.1:$WP/douve\",\"secret\":\"s3cr3t\"}}")
HID=$(echo "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["channel"]["id"])' 2>/dev/null)
[ -n "$HID" ] && ok "웹훅 채널 추가" || bad "웹훅 추가 ($out)"
out=$(post $F /api/channels/create "{\"kind\":\"ntfy\",\"name\":\"phone\",\"config\":{\"server\":\"http://127.0.0.1:$WP\",\"topic\":\"douve-secret-topic\",\"token\":\"tk_x\"}}")
NID=$(echo "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["channel"]["id"])' 2>/dev/null)
list=$(curl -s -H "Cookie: douve_session=$F" "$BASE/api/channels")
echo "$list" | grep -q 's3cr3t\|douve-secret-topic\|tk_x' && bad "채널 목록에 비밀 노출" || ok "채널 목록은 비밀을 가림"
out=$(post $F /api/channels/test "{\"id\":$HID}")
case "$out" in *'"ok"'*) ok "웹훅 테스트 발송" ;; *) bad "웹훅 테스트 ($out)";; esac
python3 - "$DIR/hook.log" <<'PY' && ok "웹훅 본문·HMAC 서명" || bad "웹훅 서명 ($(cat "$DIR/hook.log"))"
import hashlib, hmac, json, sys
r = [json.loads(l) for l in open(sys.argv[1]) if '"/douve"' in l][-1]
body = json.loads(r["body"])
assert body["source"] == "douve" and "테스트" in body["text"]
want = "sha256=" + hmac.new(b"s3cr3t", (r["ts"] + "." + r["body"]).encode(), hashlib.sha256).hexdigest()
assert r["sig"] == want, (r["sig"], want)
PY
out=$(post $F /api/channels/test "{\"id\":$NID}")
grep -q '"/douve-secret-topic".*"auth": "Bearer tk_x".*"title": "Douve"' "$DIR/hook.log" && ok "ntfy 토픽·토큰·제목" || bad "ntfy ($out $(cat "$DIR/hook.log"))"
out=$(post $F /api/channels/create "{\"kind\":\"webhook\",\"name\":\"broken\",\"config\":{\"url\":\"http://127.0.0.1:$WP/broken\"}}")
BID=$(echo "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["channel"]["id"])' 2>/dev/null)
out=$(post $F /api/channels/test "{\"id\":$BID}")
case "$out" in *"HTTP 500"*) ok "실패한 채널은 이유 표시" ;; *) bad "실패 표시 ($out)";; esac
post $F /api/channels/toggle "{\"id\":$NID,\"enabled\":false}" >/dev/null
curl -s -H "Cookie: douve_session=$F" "$BASE/api/channels" | python3 -c "import json,sys; c=[x for x in json.load(sys.stdin)['channels'] if x['id']==$NID][0]; assert not c['enabled']" 2>/dev/null \
    && ok "채널 끄기" || bad "채널 끄기"
post $F /api/channels/delete "{\"id\":$BID}" >/dev/null
[ "$(sqlite3 "$DIR/hub.db" "SELECT count(*) FROM notify_channels")" = 2 ] && ok "채널 삭제" || bad "채널 삭제"

# 감사 기록 해시 체인: 웹훅 내보내기 → 받은 쪽에서 체인 검증, CLI 확인, 변조 감지
out=$(post $F /api/channels/create "{\"kind\":\"webhook\",\"name\":\"audit\",\"config\":{\"url\":\"http://127.0.0.1:$WP/audit\",\"audit\":true}}")
case "$out" in *error*) ok "감사 기록 웹훅은 서명 비밀값 필요" ;; *) bad "비밀값 검사 ($out)";; esac
out=$(post $F /api/channels/create "{\"kind\":\"webhook\",\"name\":\"audit\",\"config\":{\"url\":\"http://127.0.0.1:$WP/audit\",\"secret\":\"aud1t\",\"audit\":true}}")
case "$out" in *'"audit":true'*) ok "감사 기록 웹훅 추가" ;; *) bad "감사 웹훅 ($out)";; esac
python3 - "$DIR/hook.log" "$DIR/hub.db" <<'PY' && ok "내보낸 감사 기록의 체인·서명을 밖에서 검증" || bad "감사 내보내기 ($(grep /audit "$DIR/hook.log" | head -c 600))"
import hashlib, hmac, json, sqlite3, sys, time
def h(prev, r):
    m = b"douve-audit-v1"
    for v in (prev, str(r["id"]).encode(), str(r["ts"]).encode(),
              (str(r["user_id"]) if r["user_id"] is not None else "").encode(),
              r["event"].encode(), r["ip"].encode(), r["detail"].encode()):
        m += str(len(v)).encode() + b":" + v
    return hashlib.sha256(m).digest()
db = sqlite3.connect(sys.argv[2])
want = db.execute("SELECT max(id) FROM audit_log").fetchone()[0]
for _ in range(50):
    batches = [json.loads(l) for l in open(sys.argv[1]) if '"/audit"' in l]
    recs = [r for b in batches for r in json.loads(b["body"])["records"]]
    if recs and recs[-1]["id"] >= want: break
    time.sleep(0.1)
prev = bytes(32)
for b in batches:
    want_sig = "sha256=" + hmac.new(b"aud1t", (b["ts"] + "." + b["body"]).encode(), hashlib.sha256).hexdigest()
    assert b["sig"] == want_sig
    body = json.loads(b["body"])
    assert body["type"] == "audit" and bytes.fromhex(body["prev_hash"]) == prev, "batch 연결"
    for r in body["records"]:
        prev = h(prev, r)
        assert prev.hex() == r["hash"], r
ids = [r["id"] for r in recs]
assert ids == list(range(1, len(ids) + 1)) and ids[-1] >= want, ids
PY
"$HUB" audit-verify --config "$DIR/hub.json" | grep -q "해시 체인 정상" && ok "audit-verify 정상" || bad "audit-verify"
sqlite3 "$DIR/hub.db" "UPDATE audit_log SET detail = 'tampered' WHERE id = 2"
out=$("$HUB" audit-verify --config "$DIR/hub.json"); code=$?
[ $code = 1 ] && grep -q "#2" <<<"$out" && ok "audit-verify가 변조 위치를 찾음" || bad "변조 감지 ($code $out)"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
