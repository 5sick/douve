// Package sign은 릴리스 서명(minisign 호환, Ed25519 + BLAKE2b-512 사전 해시)을 만들고 검증한다.
// 서명은 SHA256SUMS 파일에 붙고(SHA256SUMS.minisig), 신뢰 주석에 버전을 넣어 되돌리기 공격을 막는다.
// 공개키·서명 파일은 minisign과 같은 형식이라 누구나 `minisign -Vm SHA256SUMS -P <공개키>`로 확인할 수 있다.
package sign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/5sick/douve/agent/internal/i18n"
)

// PublicKey는 minisign 공개키 (키 ID 8바이트 + Ed25519 공개키).
type PublicKey struct {
	ID  [8]byte
	Key ed25519.PublicKey
}

// SecretKey는 Douve 서명 도구의 비밀키 (minisign의 암호화된 비밀키 형식은 쓰지 않는다).
type SecretKey struct {
	ID  [8]byte
	Key ed25519.PrivateKey
}

func (p PublicKey) IDHex() string {
	// minisign은 키 ID를 리틀 엔디언 정수의 16진수로 보여 준다
	return fmt.Sprintf("%016X", binary.LittleEndian.Uint64(p.ID[:]))
}

// Generate는 새 키 쌍을 만든다.
func Generate() (SecretKey, PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SecretKey{}, PublicKey{}, err
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return SecretKey{}, PublicKey{}, err
	}
	return SecretKey{ID: id, Key: priv}, PublicKey{ID: id, Key: pub}, nil
}

// String은 minisign 공개키 파일 내용 (두 줄).
func (p PublicKey) String() string {
	b := append([]byte("Ed"), p.ID[:]...)
	b = append(b, p.Key...)
	return "untrusted comment: minisign public key " + p.IDHex() + "\n" + base64.StdEncoding.EncodeToString(b) + "\n"
}

// Line은 공개키 한 줄(base64)만.
func (p PublicKey) Line() string {
	return strings.TrimSpace(strings.SplitN(p.String(), "\n", 3)[1])
}

// ParsePublicKey는 공개키 파일 내용 또는 base64 한 줄을 읽는다.
func ParsePublicKey(s string) (PublicKey, error) {
	var line string
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "untrusted comment:") {
			line = l
			break
		}
	}
	b, err := base64.StdEncoding.DecodeString(line)
	if err != nil || len(b) != 42 || string(b[:2]) != "Ed" {
		return PublicKey{}, errors.New("minisign 공개키 형식이 아닙니다")
	}
	var p PublicKey
	copy(p.ID[:], b[2:10])
	p.Key = ed25519.PublicKey(append([]byte(nil), b[10:]...))
	return p, nil
}

func (s SecretKey) String() string {
	b := append(append([]byte(nil), s.ID[:]...), s.Key...)
	return "untrusted comment: douve signing secret key — 비밀 (공개 저장소·서버에 두지 말 것)\n" +
		base64.StdEncoding.EncodeToString(b) + "\n"
}

func ParseSecretKey(s string) (SecretKey, error) {
	var line string
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "untrusted comment:") {
			line = l
		}
	}
	b, err := base64.StdEncoding.DecodeString(line)
	if err != nil || len(b) != 8+ed25519.PrivateKeySize {
		return SecretKey{}, errors.New("비밀키 형식이 아닙니다")
	}
	var k SecretKey
	copy(k.ID[:], b[:8])
	k.Key = ed25519.PrivateKey(append([]byte(nil), b[8:]...))
	return k, nil
}

func (s SecretKey) Public() PublicKey {
	return PublicKey{ID: s.ID, Key: s.Key.Public().(ed25519.PublicKey)}
}

// Sign은 data의 minisign 서명 파일(사전 해시 "ED")을 만든다. trusted는 신뢰 주석 (한 줄).
func Sign(k SecretKey, data []byte, trusted string) (string, error) {
	if strings.ContainsAny(trusted, "\r\n") {
		return "", errors.New("신뢰 주석은 한 줄이어야 합니다")
	}
	h := blake2b.Sum512(data)
	sig := ed25519.Sign(k.Key, h[:])
	head := append([]byte("ED"), k.ID[:]...)
	head = append(head, sig...)
	global := ed25519.Sign(k.Key, append(append([]byte(nil), sig...), []byte(trusted)...))
	return "untrusted comment: signature from douve secret key\n" +
		base64.StdEncoding.EncodeToString(head) + "\n" +
		"trusted comment: " + trusted + "\n" +
		base64.StdEncoding.EncodeToString(global) + "\n", nil
}

// Verify는 서명 파일이 keys 중 하나로 data에 대해 유효한지 확인하고 신뢰 주석을 돌려준다.
func Verify(keys []PublicKey, data []byte, sigFile string) (string, error) {
	lines := strings.Split(strings.ReplaceAll(sigFile, "\r\n", "\n"), "\n")
	if len(lines) < 4 || !strings.HasPrefix(lines[0], "untrusted comment:") ||
		!strings.HasPrefix(lines[2], "trusted comment: ") {
		return "", errors.New(i18n.T("서명 파일 형식이 아닙니다"))
	}
	head, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil || len(head) != 74 {
		return "", errors.New(i18n.T("서명 형식 오류"))
	}
	global, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[3]))
	if err != nil || len(global) != ed25519.SignatureSize {
		return "", errors.New(i18n.T("서명 형식 오류"))
	}
	alg, id, sig := string(head[:2]), head[2:10], head[10:]
	trusted := strings.TrimPrefix(lines[2], "trusted comment: ")
	var key *PublicKey
	for i := range keys {
		if bytes.Equal(keys[i].ID[:], id) {
			key = &keys[i]
			break
		}
	}
	if key == nil {
		return "", fmt.Errorf(i18n.T("신뢰하는 키로 만든 서명이 아닙니다 (키 ID %s)"),
			fmt.Sprintf("%016X", binary.LittleEndian.Uint64(id)))
	}
	var msg []byte
	switch alg {
	case "ED":
		h := blake2b.Sum512(data)
		msg = h[:]
	case "Ed":
		msg = data
	default:
		return "", errors.New(i18n.T("알 수 없는 서명 방식"))
	}
	if !ed25519.Verify(key.Key, msg, sig) {
		return "", errors.New(i18n.T("서명이 맞지 않습니다"))
	}
	if !ed25519.Verify(key.Key, append(append([]byte(nil), sig...), []byte(trusted)...), global) {
		return "", errors.New(i18n.T("신뢰 주석 서명이 맞지 않습니다"))
	}
	return trusted, nil
}

// TrustedComment는 릴리스 서명에 넣는 신뢰 주석.
func TrustedComment(version, file string, at time.Time) string {
	return fmt.Sprintf("timestamp:%d\tfile:%s\tversion:%s", at.Unix(), file, version)
}

// CommentField는 신뢰 주석에서 key:value를 찾는다.
func CommentField(trusted, key string) string {
	for _, f := range strings.Split(trusted, "\t") {
		if v, ok := strings.CutPrefix(f, key+":"); ok {
			return v
		}
	}
	return ""
}

// Older는 a가 b보다 이전 릴리스인지 (둘 다 vX.Y.Z[-N-g해시] 형식일 때만 판단, 아니면 false).
func Older(a, b string) bool {
	pa, oka := parseVersion(a)
	pb, okb := parseVersion(b)
	if !oka || !okb {
		return false
	}
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func parseVersion(v string) ([4]int, bool) {
	var out [4]int
	v = strings.TrimPrefix(v, "v")
	if i := strings.Index(v, "-dirty"); i >= 0 {
		v = v[:i]
	}
	main, rest, _ := strings.Cut(v, "-")
	parts := strings.Split(main, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	if rest != "" { // git describe: 태그 뒤 커밋 수
		n, err := strconv.Atoi(strings.SplitN(rest, "-", 2)[0])
		if err != nil {
			return out, false
		}
		out[3] = n
	}
	return out, true
}
