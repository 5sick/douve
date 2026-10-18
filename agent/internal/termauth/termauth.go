// Package termauth는 터미널을 열기 전에 Agent가 직접 하는 확인이다. Hub를 믿지 않아도 되게 한다.
//
// 터미널을 열 때마다 사용자는 패스키로 "이 서버(node), 이 계정(user), 지금(ts), 1회용 값(nonce)"에
// 서명한다 (WebAuthn assertion, challenge = SHA-256(문장)). Agent는 자기가 믿는 패스키 목록(신뢰 목록)으로
// 서명을 검증한 뒤에만 셸을 띄운다. Hub가 장악돼도 사용자의 패스키 없이는 터미널을 열 수 없다.
//
// 신뢰 목록은 Agent가 처음 받을 때(그리고 관리자 패스키가 아직 하나도 없는 동안)만 그대로 믿는다
// (등록과 같은 시점의 신뢰, TOFU). 그다음부터는 지금 목록에 있는 관리자 패스키의 서명이 있어야
// 바꾼다. 버전은 늘기만 한다 (옛 목록 재전송 방지).
// 목록은 Agent 상태 디렉터리에 있어 Hub가 직접 고칠 수 없다. 처음부터 다시 받으려면 서버에서
// root로 `douve-agent terminal-trust reset`.
package termauth

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

// 서명하는 문장의 머리말. Hub(cluster/term_trust.cc)와 같아야 한다.
const (
	openPrefix   = "douve-terminal-open:v1\n"
	trustPrefix  = "douve-terminal-trust:v1\n"
	actionPrefix = "douve-server-action:v1\n" // 서버를 바꾸는 작업 (보안 점검표 고치기 등)
)

// 서명 시각 허용 범위 (Hub·Agent 시계 차이 + 패스키 터치 시간)
const MaxSkew = 2 * time.Minute

// COSE 알고리즘 (WebAuthn에서 쓰는 것만)
const (
	AlgES256 = -7
	AlgEdDSA = -8
	AlgRS256 = -257
)

// FileName은 상태 디렉터리 안의 신뢰 목록 파일이다.
const FileName = "terminal-trust.json"

var b64 = base64.RawURLEncoding

// Key는 터미널을 열 수 있는 패스키 하나.
type Key struct {
	ID    string  `json:"id"` // credential id (base64url)
	Alg   int     `json:"alg"`
	X     string  `json:"x,omitempty"` // ES256: x, y / EdDSA: x
	Y     string  `json:"y,omitempty"`
	N     string  `json:"n,omitempty"` // RS256
	E     string  `json:"e,omitempty"`
	User  string  `json:"user"`            // 표시용 (이메일)
	Admin bool    `json:"admin,omitempty"` // 모든 서버 + 신뢰 목록 변경 서명
	Nodes []int64 `json:"nodes,omitempty"` // 관리자가 아니면 이 서버들만
}

// Trust는 신뢰 목록 내용이다 (Hub가 만든 문자열을 그대로 서명·저장한다).
type Trust struct {
	V       int    `json:"v"`
	Version int64  `json:"version"`
	Origin  string `json:"origin"` // 패스키 서명이 나온 웹 주소 (https://douve.example.com)
	RPID    string `json:"rp_id"`
	Keys    []Key  `json:"keys"`
}

// Assertion은 WebAuthn 서명 결과 (모두 base64url).
type Assertion struct {
	ID         string `json:"id"`
	ClientData string `json:"client_data"`
	AuthData   string `json:"auth_data"`
	Signature  string `json:"sig"`
}

// Record는 Hub가 보내는 신뢰 목록 한 판. 첫 판은 서명이 없을 수 있다.
type Record struct {
	Snapshot string     `json:"snapshot"`
	Sig      *Assertion `json:"sig,omitempty"`
}

// OpenAuth는 터미널 열기 요청에 붙는 서명.
type OpenAuth struct {
	TS    int64  `json:"ts"`
	Nonce string `json:"nonce"`
	Assertion
}

type stored struct {
	Snapshot string     `json:"snapshot"`
	Sig      *Assertion `json:"sig,omitempty"`
	Received int64      `json:"received"`
}

// Store는 신뢰 목록과 최근 쓴 1회용 값을 가진다. 스레드 안전.
type Store struct {
	path    string
	now     func() time.Time
	started time.Time // 이보다 먼저 만든 서명은 받지 않는다 (1회용 값 기록은 메모리라 재시작 후 재사용 방지)

	mu     sync.Mutex
	locked error // 신뢰 목록을 읽을 수 없음: 터미널도, 목록 변경도 거부 (처음처럼 믿지 않는다)
	cur    *Trust
	seen   map[string]time.Time // nonce → 만료
	keyed  map[string]*Key
}

// Open은 상태 디렉터리의 신뢰 목록을 읽는다 (없으면 빈 상태: 처음 받는 목록을 믿는다).
func Open(stateDir string) (*Store, error) {
	s := &Store{path: filepath.Join(stateDir, FileName), now: time.Now, started: time.Now(), seen: map[string]time.Time{}}
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var st stored
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("%s: %w", s.path, err)
	}
	t, err := Parse(st.Snapshot)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.path, err)
	}
	s.set(t)
	return s, nil
}

// Locked는 신뢰 목록 파일을 읽을 수 없을 때 쓴다. 이때 빈 목록으로 시작하면 Hub가 보내는 목록을
// 처음처럼 믿게 되므로, 터미널 열기와 목록 변경을 모두 거부한다 (Agent의 다른 기능은 그대로).
func Locked(stateDir string, err error) *Store {
	return &Store{path: filepath.Join(stateDir, FileName), now: time.Now, seen: map[string]time.Time{},
		locked: fmt.Errorf("터미널 신뢰 목록을 읽을 수 없어 터미널을 열지 않습니다: %w", err)}
}

// Reset은 신뢰 목록을 지운다 (다음에 Hub가 보내는 목록을 처음처럼 믿는다). root만 쓰는 명령.
func Reset(stateDir string) error {
	err := os.Remove(filepath.Join(stateDir, FileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Current는 지금 신뢰 목록 (없으면 nil).
func (s *Store) Current() *Trust {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

func (s *Store) set(t *Trust) {
	s.cur = t
	s.keyed = map[string]*Key{}
	for i := range t.Keys {
		s.keyed[t.Keys[i].ID] = &t.Keys[i]
	}
}

// Parse는 신뢰 목록 문자열을 읽고 형식을 확인한다.
func Parse(snapshot string) (*Trust, error) {
	if len(snapshot) > 1<<20 {
		return nil, errors.New("신뢰 목록이 너무 큽니다")
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(snapshot)))
	dec.DisallowUnknownFields()
	var t Trust
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("신뢰 목록 형식: %w", err)
	}
	if t.V != 1 || t.Version <= 0 || t.Origin == "" || t.RPID == "" {
		return nil, errors.New("신뢰 목록 형식: v·version·origin·rp_id 필요")
	}
	ids := map[string]bool{}
	for i := range t.Keys {
		k := &t.Keys[i]
		if ids[k.ID] {
			return nil, fmt.Errorf("신뢰 목록: 같은 패스키가 두 번 (%s)", k.ID)
		}
		ids[k.ID] = true
		if _, err := k.publicKey(); err != nil {
			return nil, fmt.Errorf("신뢰 목록: %s: %w", k.User, err)
		}
	}
	return &t, nil
}

func decodeField(s string, want int) ([]byte, error) {
	b, err := b64.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if want > 0 && len(b) != want {
		return nil, fmt.Errorf("길이 %d (기대 %d)", len(b), want)
	}
	return b, nil
}

func (k *Key) publicKey() (crypto.PublicKey, error) {
	if _, err := b64.DecodeString(k.ID); err != nil || k.ID == "" {
		return nil, errors.New("잘못된 패스키 id")
	}
	switch k.Alg {
	case AlgES256:
		x, err1 := decodeField(k.X, 32)
		y, err2 := decodeField(k.Y, 32)
		if err1 != nil || err2 != nil {
			return nil, errors.New("잘못된 P-256 키")
		}
		// 곡선 위의 점인지까지 확인한다
		return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	case AlgEdDSA:
		x, err := decodeField(k.X, ed25519.PublicKeySize)
		if err != nil {
			return nil, errors.New("잘못된 Ed25519 키")
		}
		return ed25519.PublicKey(x), nil
	case AlgRS256:
		n, err1 := decodeField(k.N, 0)
		e, err2 := decodeField(k.E, 0)
		if err1 != nil || err2 != nil || len(n) < 256 || len(n) > 1024 || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("잘못된 RSA 키")
		}
		ev := 0
		for _, c := range e {
			ev = ev<<8 | int(c)
		}
		if ev < 3 || ev%2 == 0 {
			return nil, errors.New("잘못된 RSA 지수")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: ev}, nil
	}
	return nil, fmt.Errorf("지원하지 않는 알고리즘 %d", k.Alg)
}

func (t *Trust) hasAdmin() bool {
	for _, k := range t.Keys {
		if k.Admin {
			return true
		}
	}
	return false
}

func (k *Key) allows(nodeID int64) bool {
	if k.Admin {
		return true
	}
	for _, n := range k.Nodes {
		if n == nodeID {
			return true
		}
	}
	return false
}

// verify는 WebAuthn 서명(§7.2)을 확인한다: 형식(webauthn.get), challenge, origin, rpIdHash, 사용자 확인(UP·UV), 서명.
func verify(k *Key, t *Trust, a *Assertion, challenge []byte) error {
	pub, err := k.publicKey()
	if err != nil {
		return err
	}
	cd, err1 := b64.DecodeString(a.ClientData)
	ad, err2 := b64.DecodeString(a.AuthData)
	sig, err3 := b64.DecodeString(a.Signature)
	if err1 != nil || err2 != nil || err3 != nil || len(cd) > 8192 || len(ad) > 8192 || len(sig) > 1024 {
		return errors.New("서명 형식 오류")
	}
	var c struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	if json.Unmarshal(cd, &c) != nil {
		return errors.New("clientDataJSON 형식 오류")
	}
	got, err := b64.DecodeString(c.Challenge)
	switch {
	case c.Type != "webauthn.get":
		return errors.New("서명 종류가 다릅니다")
	case err != nil || !bytes.Equal(got, challenge):
		return errors.New("서명한 내용이 요청과 다릅니다")
	case c.Origin != t.Origin || c.CrossOrigin:
		return fmt.Errorf("다른 주소에서 만든 서명입니다 (%s)", c.Origin)
	}
	// authenticatorData: rpIdHash(32) flags(1) signCount(4) ...
	if len(ad) < 37 {
		return errors.New("authenticatorData가 짧습니다")
	}
	rp := sha256.Sum256([]byte(t.RPID))
	if !bytes.Equal(ad[:32], rp[:]) {
		return errors.New("rpId가 다릅니다")
	}
	if ad[32]&0x01 == 0 || ad[32]&0x04 == 0 {
		return errors.New("패스키 사용자 확인(UV)이 없습니다")
	}
	cdHash := sha256.Sum256(cd)
	msg := append(append([]byte{}, ad...), cdHash[:]...)
	digest := sha256.Sum256(msg)
	ok := false
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		ok = ecdsa.VerifyASN1(p, digest[:], sig)
	case ed25519.PublicKey:
		ok = ed25519.Verify(p, msg, sig)
	case *rsa.PublicKey:
		ok = rsa.VerifyPKCS1v15(p, crypto.SHA256, digest[:], sig) == nil
	}
	if !ok {
		return errors.New("서명이 맞지 않습니다")
	}
	return nil
}

// OpenStatement는 터미널 열기에 서명하는 문장이다.
func OpenStatement(nodeID int64, user string, ts int64, nonce string) string {
	return openPrefix + strconv.FormatInt(nodeID, 10) + "\n" + user + "\n" + strconv.FormatInt(ts, 10) + "\n" + nonce
}

// ActionStatement는 서버를 바꾸는 작업(action, 예: "fix:ssh_password")에 서명하는 문장이다.
func ActionStatement(nodeID int64, action string, ts int64, nonce string) string {
	return actionPrefix + strconv.FormatInt(nodeID, 10) + "\n" + action + "\n" + strconv.FormatInt(ts, 10) + "\n" + nonce
}

// TrustChallenge는 신뢰 목록 변경에 서명하는 challenge다.
func TrustChallenge(snapshot string) []byte {
	h := sha256.Sum256([]byte(trustPrefix + snapshot))
	return h[:]
}

// CheckOpen은 이 서버(nodeID)에서 user 계정 터미널을 열어도 되는지 사용자의 패스키 서명으로 확인한다.
// 성공하면 서명한 사람(신뢰 목록의 user)을 돌려준다.
func (s *Store) CheckOpen(nodeID int64, user string, a *OpenAuth) (string, error) {
	if a == nil {
		return "", errors.New("패스키 서명이 없는 요청입니다 (Hub를 업데이트하세요)")
	}
	return s.check(nodeID, OpenStatement(nodeID, user, a.TS, a.Nonce), a)
}

// CheckAction은 이 서버(nodeID)에서 action을 해도 되는지 사용자의 패스키 서명으로 확인한다 (터미널과 같은 권한).
func (s *Store) CheckAction(nodeID int64, action string, a *OpenAuth) (string, error) {
	if a == nil {
		return "", errors.New("패스키 서명이 없는 요청입니다 (Hub를 업데이트하세요)")
	}
	return s.check(nodeID, ActionStatement(nodeID, action, a.TS, a.Nonce), a)
}

func (s *Store) check(nodeID int64, statement string, a *OpenAuth) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked != nil {
		return "", s.locked
	}
	if s.cur == nil {
		return "", errors.New("이 서버가 아직 터미널 신뢰 목록을 받지 못했습니다")
	}
	now := s.now()
	for n, exp := range s.seen {
		if now.After(exp) {
			delete(s.seen, n)
		}
	}
	ts := time.Unix(a.TS, 0)
	if ts.Before(now.Add(-MaxSkew)) || ts.After(now.Add(MaxSkew)) {
		return "", errors.New("서명 시각이 맞지 않습니다 (서버 시계를 확인하세요)")
	}
	if a.TS < s.started.Unix()-1 {
		return "", errors.New("이 서버가 다시 시작하기 전에 만든 서명입니다. 다시 여세요")
	}
	if len(a.Nonce) < 16 || len(a.Nonce) > 64 {
		return "", errors.New("잘못된 1회용 값")
	}
	if _, used := s.seen[a.Nonce]; used {
		return "", errors.New("이미 쓴 서명입니다")
	}
	k := s.keyed[a.ID]
	if k == nil {
		return "", errors.New("이 서버가 모르는 패스키입니다 (관리자가 신뢰 목록 변경을 승인해야 합니다)")
	}
	if !k.allows(nodeID) {
		return "", errors.New("이 패스키는 이 서버의 터미널 권한이 없습니다")
	}
	sum := sha256.Sum256([]byte(statement))
	if err := verify(k, s.cur, &a.Assertion, sum[:]); err != nil {
		return "", err
	}
	s.seen[a.Nonce] = ts.Add(MaxSkew + time.Minute)
	return k.User, nil
}

// ErrUntrustedChange는 지금 목록의 관리자 서명이 없는 변경이다 (Hub가 아직 승인받지 않음).
var ErrUntrustedChange = errors.New("관리자 패스키 서명이 없는 신뢰 목록 변경")

// Apply는 Hub가 보낸 신뢰 목록들을 버전 순서로 적용한다. 바뀌었으면 changed=true.
func (s *Store) Apply(recs []Record) (changed bool, err error) {
	parsed := make([]struct {
		t *Trust
		r Record
	}, 0, len(recs))
	for _, r := range recs {
		t, e := Parse(r.Snapshot)
		if e != nil {
			return false, e
		}
		parsed = append(parsed, struct {
			t *Trust
			r Record
		}{t, r})
	}
	sort.Slice(parsed, func(i, j int) bool { return parsed[i].t.Version < parsed[j].t.Version })
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked != nil {
		return false, s.locked
	}
	if len(parsed) == 0 {
		return false, nil
	}
	// 처음이거나 아직 관리자 패스키가 하나도 없으면 (설치 직후 등, 아무도 터미널을 열 수 없는 상태)
	// 가장 새 판을 서명 없이 믿는다. 관리자 키가 생긴 뒤부터는 그 키의 서명이 있어야 바뀐다.
	if s.cur == nil || !s.cur.hasAdmin() {
		last := parsed[len(parsed)-1]
		if s.cur != nil && last.t.Version <= s.cur.Version {
			return false, nil
		}
		if e := s.save(last.r); e != nil {
			return false, e
		}
		s.set(last.t)
		return true, nil
	}
	for _, p := range parsed {
		if p.t.Version <= s.cur.Version {
			continue
		}
		if p.r.Sig == nil {
			err = ErrUntrustedChange
			continue
		}
		signer := s.keyed[p.r.Sig.ID]
		if signer == nil || !signer.Admin {
			err = fmt.Errorf("버전 %d: 이 서버가 믿는 관리자 패스키의 서명이 아닙니다", p.t.Version)
			continue
		}
		if e := verify(signer, s.cur, p.r.Sig, TrustChallenge(p.r.Snapshot)); e != nil {
			err = fmt.Errorf("버전 %d: %w", p.t.Version, e)
			continue
		}
		if e := s.save(p.r); e != nil {
			return changed, e
		}
		s.set(p.t)
		changed, err = true, nil
	}
	return changed, err
}

func (s *Store) save(r Record) error {
	b, _ := json.MarshalIndent(stored{Snapshot: r.Snapshot, Sig: r.Sig, Received: s.now().Unix()}, "", "  ")
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
