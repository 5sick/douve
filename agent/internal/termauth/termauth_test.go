package termauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	origin = "https://douve.example.com"
	rpID   = "example.com"
)

// authenticator는 시험용 패스키 (WebAuthn 인증기 흉내)
type authenticator struct {
	key  Key
	sign func(digest, msg []byte) []byte
}

func newES256(t *testing.T, id, user string, admin bool, nodes ...int64) *authenticator {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := pk.PublicKey.Bytes()
	return &authenticator{
		key: Key{ID: b64.EncodeToString([]byte(id)), Alg: AlgES256, X: b64.EncodeToString(raw[1:33]),
			Y: b64.EncodeToString(raw[33:]), User: user, Admin: admin, Nodes: nodes},
		sign: func(d, _ []byte) []byte { s, _ := ecdsa.SignASN1(rand.Reader, pk, d); return s },
	}
}

func newEd25519(t *testing.T, id, user string, admin bool, nodes ...int64) *authenticator {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &authenticator{
		key:  Key{ID: b64.EncodeToString([]byte(id)), Alg: AlgEdDSA, X: b64.EncodeToString(pub), User: user, Admin: admin, Nodes: nodes},
		sign: func(_, m []byte) []byte { return ed25519.Sign(priv, m) },
	}
}

func newRS256(t *testing.T, id, user string, admin bool) *authenticator {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &authenticator{
		key: Key{ID: b64.EncodeToString([]byte(id)), Alg: AlgRS256, N: b64.EncodeToString(pk.N.Bytes()),
			E: b64.EncodeToString([]byte{1, 0, 1}), User: user, Admin: admin},
		sign: func(d, _ []byte) []byte { s, _ := rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA256, d); return s },
	}
}

type assertOpt struct {
	origin, rpID, typ string
	flags             byte
}

func (a *authenticator) assert(challenge []byte, o assertOpt) Assertion {
	if o.origin == "" {
		o.origin = origin
	}
	if o.rpID == "" {
		o.rpID = rpID
	}
	if o.typ == "" {
		o.typ = "webauthn.get"
	}
	if o.flags == 0 {
		o.flags = 0x05 // UP | UV
	}
	cd, _ := json.Marshal(map[string]any{"type": o.typ, "challenge": b64.EncodeToString(challenge), "origin": o.origin})
	rp := sha256.Sum256([]byte(o.rpID))
	ad := append(rp[:], o.flags, 0, 0, 0, 7)
	cdh := sha256.Sum256(cd)
	msg := append(append([]byte{}, ad...), cdh[:]...)
	d := sha256.Sum256(msg)
	return Assertion{ID: a.key.ID, ClientData: b64.EncodeToString(cd), AuthData: b64.EncodeToString(ad),
		Signature: b64.EncodeToString(a.sign(d[:], msg))}
}

func snapshot(version int64, keys ...*authenticator) string {
	t := Trust{V: 1, Version: version, Origin: origin, RPID: rpID, Keys: []Key{}}
	for _, k := range keys {
		t.Keys = append(t.Keys, k.key)
	}
	b, _ := json.Marshal(t)
	return string(b)
}

func signedRecord(snap string, signer *authenticator) Record {
	a := signer.assert(TrustChallenge(snap), assertOpt{})
	return Record{Snapshot: snap, Sig: &a}
}

func openAuth(a *authenticator, node int64, user string, ts int64, nonce string, o assertOpt) *OpenAuth {
	sum := sha256.Sum256([]byte(OpenStatement(node, user, ts, nonce)))
	return &OpenAuth{TS: ts, Nonce: nonce, Assertion: a.assert(sum[:], o)}
}

func newStore(t *testing.T) (*Store, string) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

const nonce = "nonce-0123456789abcdef"

func TestOpenAllKeyTypes(t *testing.T) {
	es := newES256(t, "es", "a@x", true)
	ed := newEd25519(t, "ed", "b@x", true)
	rs := newRS256(t, "rs", "c@x", true)
	s, _ := newStore(t)
	if _, err := s.Apply([]Record{{Snapshot: snapshot(1, es, ed, rs)}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	for i, a := range []*authenticator{es, ed, rs} {
		n := nonce + string(rune('a'+i))
		who, err := s.CheckOpen(3, "ubuntu", openAuth(a, 3, "ubuntu", now, n, assertOpt{}))
		if err != nil || who != a.key.User {
			t.Fatalf("%s: %v %q", a.key.User, err, who)
		}
	}
}

func TestOpenRejects(t *testing.T) {
	admin := newES256(t, "admin", "admin@x", true)
	op := newEd25519(t, "op", "op@x", false, 5)
	stranger := newES256(t, "stranger", "evil@x", true)
	s, _ := newStore(t)
	if _, err := s.Apply([]Record{{Snapshot: snapshot(1, admin, op)}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	cases := []struct {
		name string
		node int64
		user string
		auth *OpenAuth
		want string
	}{
		{"서명 없음", 1, "ubuntu", nil, "서명이 없는"},
		{"모르는 패스키", 1, "ubuntu", openAuth(stranger, 1, "ubuntu", now, nonce, assertOpt{}), "모르는 패스키"},
		{"운영자: 허락 안 된 서버", 1, "ubuntu", openAuth(op, 1, "ubuntu", now, nonce, assertOpt{}), "권한이 없습니다"},
		{"다른 서버용 서명", 1, "ubuntu", openAuth(admin, 2, "ubuntu", now, nonce, assertOpt{}), "요청과 다릅니다"},
		{"다른 계정용 서명", 1, "root", openAuth(admin, 1, "ubuntu", now, nonce, assertOpt{}), "요청과 다릅니다"},
		{"오래된 서명", 1, "ubuntu", openAuth(admin, 1, "ubuntu", now-600, nonce, assertOpt{}), "시각"},
		{"미래 서명", 1, "ubuntu", openAuth(admin, 1, "ubuntu", now+600, nonce, assertOpt{}), "시각"},
		{"다른 사이트", 1, "ubuntu", openAuth(admin, 1, "ubuntu", now, nonce, assertOpt{origin: "https://evil.example"}), "다른 주소"},
		{"다른 rpId", 1, "ubuntu", openAuth(admin, 1, "ubuntu", now, nonce, assertOpt{rpID: "evil.example"}), "rpId"},
		{"UV 없음", 1, "ubuntu", openAuth(admin, 1, "ubuntu", now, nonce, assertOpt{flags: 0x01}), "UV"},
		{"등록 서명", 1, "ubuntu", openAuth(admin, 1, "ubuntu", now, nonce, assertOpt{typ: "webauthn.create"}), "종류"},
		{"짧은 nonce", 1, "ubuntu", openAuth(admin, 1, "ubuntu", now, "short", assertOpt{}), "1회용"},
	}
	for _, c := range cases {
		_, err := s.CheckOpen(c.node, c.user, c.auth)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (기대 %q)", c.name, err, c.want)
		}
	}
	// 서명 바꿔치기: 다른 키의 서명을 관리자 id로
	a := openAuth(stranger, 1, "ubuntu", now, nonce, assertOpt{})
	a.ID = admin.key.ID
	if _, err := s.CheckOpen(1, "ubuntu", a); err == nil || !strings.Contains(err.Error(), "맞지 않습니다") {
		t.Errorf("서명 바꿔치기: %v", err)
	}
	// 운영자는 허락된 서버에서 열 수 있다
	if _, err := s.CheckOpen(5, "ubuntu", openAuth(op, 5, "ubuntu", now, nonce, assertOpt{})); err != nil {
		t.Errorf("운영자 허락된 서버: %v", err)
	}
}

func TestReplay(t *testing.T) {
	admin := newES256(t, "admin", "admin@x", true)
	s, _ := newStore(t)
	_, _ = s.Apply([]Record{{Snapshot: snapshot(1, admin)}})
	a := openAuth(admin, 1, "ubuntu", time.Now().Unix(), nonce, assertOpt{})
	if _, err := s.CheckOpen(1, "ubuntu", a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CheckOpen(1, "ubuntu", a); err == nil || !strings.Contains(err.Error(), "이미 쓴") {
		t.Fatalf("재사용: %v", err)
	}
}

func TestNoTrustYet(t *testing.T) {
	admin := newES256(t, "admin", "admin@x", true)
	s, _ := newStore(t)
	_, err := s.CheckOpen(1, "ubuntu", openAuth(admin, 1, "ubuntu", time.Now().Unix(), nonce, assertOpt{}))
	if err == nil || !strings.Contains(err.Error(), "받지 못했습니다") {
		t.Fatal(err)
	}
}

func TestTrustChanges(t *testing.T) {
	admin := newES256(t, "admin", "admin@x", true)
	admin2 := newEd25519(t, "admin2", "admin2@x", true)
	op := newES256(t, "op", "op@x", false, 1)
	evil := newES256(t, "evil", "evil@x", true)
	s, dir := newStore(t)

	// 처음에는 서명 없이도 믿는다 (가장 새 판)
	if ch, err := s.Apply([]Record{{Snapshot: snapshot(1)}}); err != nil || !ch {
		t.Fatal(ch, err)
	}
	// 관리자 키가 아직 없으면 (설치 직후) 서명 없는 새 판도 받는다
	if ch, err := s.Apply([]Record{{Snapshot: snapshot(2, op)}}); err != nil || !ch {
		t.Fatal("관리자 없음", ch, err)
	}
	if ch, err := s.Apply([]Record{{Snapshot: snapshot(2, admin)}}); err != nil || ch {
		t.Fatal("같은 버전", ch, err)
	}
	if ch, err := s.Apply([]Record{{Snapshot: snapshot(1, op)}, {Snapshot: snapshot(3, admin)}}); err != nil || !ch {
		t.Fatal(ch, err)
	}
	if s.Current().Version != 3 {
		t.Fatal(s.Current().Version)
	}
	// 그다음 서명 없는 변경은 거부 (Hub가 장악돼 공격자 키를 넣으려는 경우)
	if ch, err := s.Apply([]Record{{Snapshot: snapshot(4, admin, evil)}}); ch || err != ErrUntrustedChange {
		t.Fatal(ch, err)
	}
	// 모르는 관리자 키로 서명
	if ch, err := s.Apply([]Record{signedRecord(snapshot(4, admin, evil), evil)}); ch || err == nil {
		t.Fatal("모르는 키 서명", ch, err)
	}
	// 운영자 키 서명은 신뢰 목록을 바꿀 수 없다
	s2, _ := newStore(t)
	_, _ = s2.Apply([]Record{{Snapshot: snapshot(1, admin, op)}})
	if ch, err := s2.Apply([]Record{signedRecord(snapshot(2, admin, op, evil), op)}); ch || err == nil {
		t.Fatal("운영자 서명", ch, err)
	}
	// 서명한 내용과 다른 목록 (서명은 진짜, 내용 바꿔치기)
	r := signedRecord(snapshot(4, admin, admin2), admin)
	r.Snapshot = snapshot(4, admin, evil)
	if ch, err := s.Apply([]Record{r}); ch || err == nil {
		t.Fatal("내용 바꿔치기", ch, err)
	}
	// 관리자 서명 + 연쇄: v4(admin이 admin2 추가) → v5(admin2가 admin 제거)
	v3 := signedRecord(snapshot(4, admin, admin2), admin)
	v4 := signedRecord(snapshot(5, admin2), admin2)
	if ch, err := s.Apply([]Record{v4, v3}); err != nil || !ch || s.Current().Version != 5 {
		t.Fatal(ch, err, s.Current().Version)
	}
	// 옛 판 재전송은 무시 (지운 키가 되살아나지 않게)
	if ch, err := s.Apply([]Record{v3}); ch || err != nil || s.Current().Version != 5 {
		t.Fatal("옛 판", ch, err)
	}
	now := time.Now().Unix()
	if _, err := s.CheckOpen(1, "u", openAuth(admin, 1, "u", now, nonce, assertOpt{})); err == nil {
		t.Fatal("지운 관리자 키로 열림")
	}
	// 파일에 저장되고 다시 읽힌다
	s3, err := Open(dir)
	if err != nil || s3.Current() == nil || s3.Current().Version != 5 {
		t.Fatal("다시 읽기", err)
	}
	if _, err := s3.CheckOpen(1, "u", openAuth(admin2, 1, "u", now, nonce+"x", assertOpt{})); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(filepath.Join(dir, FileName))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("파일 권한 %v", st.Mode())
	}
	// reset 후에는 다시 처음처럼
	if err := Reset(dir); err != nil {
		t.Fatal(err)
	}
	s4, _ := Open(dir)
	if s4.Current() != nil {
		t.Fatal("reset")
	}
}

func TestParseRejects(t *testing.T) {
	a := newES256(t, "a", "a@x", true)
	good := snapshot(1, a)
	bad := []string{
		"", "{}", `{"v":2,"version":1,"origin":"o","rp_id":"r","keys":[]}`,
		`{"v":1,"version":0,"origin":"o","rp_id":"r","keys":[]}`,
		strings.Replace(good, `"keys"`, `"extra":1,"keys"`, 1),                  // 모르는 필드
		strings.Replace(good, `"alg":-7`, `"alg":-35`, 1),                       // 지원 안 하는 알고리즘
		strings.Replace(good, a.key.X, b64.EncodeToString(make([]byte, 32)), 1), // 곡선 밖의 점
		snapshot(1, a, a), // 같은 키 두 번
	}
	for i, b := range bad {
		if _, err := Parse(b); err == nil {
			t.Errorf("%d: 받아들임 %s", i, b)
		}
	}
	if _, err := Parse(good); err != nil {
		t.Fatal(err)
	}
}

func TestLockedStore(t *testing.T) {
	// 파일을 읽을 수 없으면 처음처럼 믿지 않는다 (목록 변경·터미널 모두 거부)
	admin := newES256(t, "admin", "admin@x", true)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(dir)
	if err == nil {
		t.Fatal("깨진 파일을 읽음")
	}
	s := Locked(dir, err)
	if ch, err := s.Apply([]Record{{Snapshot: snapshot(1, admin)}}); ch || err == nil {
		t.Fatal("잠긴 상태에서 목록 받음", ch, err)
	}
	if _, err := s.CheckOpen(1, "u", openAuth(admin, 1, "u", time.Now().Unix(), nonce, assertOpt{})); err == nil {
		t.Fatal("잠긴 상태에서 터미널 열림")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, FileName)); string(b) != "{broken" {
		t.Fatal("파일을 덮어씀")
	}
}

func TestSignedBeforeRestart(t *testing.T) {
	// 재시작하면 1회용 값 기록이 사라지므로, 재시작 전에 만든 서명은 받지 않는다
	admin := newES256(t, "admin", "admin@x", true)
	s, dir := newStore(t)
	_, _ = s.Apply([]Record{{Snapshot: snapshot(1, admin)}})
	ts := time.Now().Unix() - 30
	a := openAuth(admin, 1, "u", ts, nonce, assertOpt{})
	s2, _ := Open(dir)
	if _, err := s2.CheckOpen(1, "u", a); err == nil || !strings.Contains(err.Error(), "다시 시작하기 전") {
		t.Fatal(err)
	}
	s2.started = time.Unix(ts-10, 0)
	if _, err := s2.CheckOpen(1, "u", a); err != nil {
		t.Fatal(err)
	}
}

func TestActionSignatures(t *testing.T) {
	admin := newES256(t, "admin", "admin@x", true)
	op := newEd25519(t, "op", "op@x", false, 5)
	s, _ := newStore(t)
	_, _ = s.Apply([]Record{{Snapshot: snapshot(1, admin, op)}})
	now := time.Now().Unix()
	act := func(a *authenticator, node int64, action, n string) *OpenAuth {
		sum := sha256.Sum256([]byte(ActionStatement(node, action, now, n)))
		return &OpenAuth{TS: now, Nonce: n, Assertion: a.assert(sum[:], assertOpt{})}
	}
	if who, err := s.CheckAction(1, "fix:ssh_password", act(admin, 1, "fix:ssh_password", nonce+"1")); err != nil || who != "admin@x" {
		t.Fatal(who, err)
	}
	// 다른 작업용 서명으로는 안 된다
	if _, err := s.CheckAction(1, "fix:auto_updates", act(admin, 1, "fix:ssh_password", nonce+"2")); err == nil {
		t.Fatal("다른 작업 서명")
	}
	// 터미널 열기 서명을 작업에 쓸 수 없고, 그 반대도 마찬가지 (문장 머리말이 다름)
	if _, err := s.CheckAction(1, "u", openAuth(admin, 1, "u", now, nonce+"3", assertOpt{})); err == nil {
		t.Fatal("터미널 서명을 작업에")
	}
	if _, err := s.CheckOpen(1, "fix:x", act(admin, 1, "fix:x", nonce+"4")); err == nil {
		t.Fatal("작업 서명으로 터미널")
	}
	// 운영자는 허락된 서버에서만
	if _, err := s.CheckAction(1, "fix:x", act(op, 1, "fix:x", nonce+"5")); err == nil {
		t.Fatal("운영자 다른 서버")
	}
	if _, err := s.CheckAction(5, "fix:x", act(op, 5, "fix:x", nonce+"6")); err != nil {
		t.Fatal(err)
	}
	// 재사용
	a := act(admin, 1, "fix:y", nonce+"7")
	_, _ = s.CheckAction(1, "fix:y", a)
	if _, err := s.CheckAction(1, "fix:y", a); err == nil {
		t.Fatal("재사용")
	}
}

func TestStatementsMatchHub(t *testing.T) {
	// Hub(cluster/term_trust.cc, hub/tests/term_trust_test.cc)와 같은 문장
	if got := OpenStatement(3, "ubuntu", 1700000000, "nonce-1"); got != "douve-terminal-open:v1\n3\nubuntu\n1700000000\nnonce-1" {
		t.Fatal(got)
	}
	if got := ActionStatement(3, "fix:ssh_password", 1700000000, "n1"); got != "douve-server-action:v1\n3\nfix:ssh_password\n1700000000\nn1" {
		t.Fatal(got)
	}
}
