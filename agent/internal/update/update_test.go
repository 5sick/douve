package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/5sick/douve/agent/internal/sign"
)

// 서명된 릴리스 만들기: body가 douve-agent-linux-amd64
func signedRelease(t *testing.T, sk sign.SecretKey, body []byte, version string) Release {
	t.Helper()
	sum := sha256.Sum256(body)
	sums := hex.EncodeToString(sum[:]) + "  douve-agent-linux-amd64\n" + strings.Repeat("0", 64) + "  douve-agent-linux-arm64\n"
	sig, err := sign.Sign(sk, []byte(sums), sign.TrustedComment(version, "SHA256SUMS", time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	return Release{Version: version, Path: "/dl/douve-agent-linux-amd64", SHA256: hex.EncodeToString(sum[:]), Sums: sums, Sig: sig}
}

func TestApplyVerifiesSignatureAndReplaces(t *testing.T) {
	body := []byte("#!/bin/sh\necho new\n")
	served := body
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(served) }))
	defer srv.Close()
	sk, pk, _ := sign.Generate()
	keys := []sign.PublicKey{pk}

	dir := t.TempDir()
	exe := filepath.Join(dir, "douve-agent")
	os.WriteFile(exe, []byte("old"), 0o755)
	state := filepath.Join(dir, "state")
	unchanged := func() bool { b, _ := os.ReadFile(exe); return string(b) == "old" }

	rel := signedRelease(t, sk, body, "v0.3.0")

	// 서명이 없거나, 다른 키거나, 내용이 바뀌면 받지 않는다
	noSig := rel
	noSig.Sig = ""
	if err := Apply(context.Background(), srv.URL, noSig, keys, "amd64", "v0.2.0", exe, state); err == nil || !unchanged() {
		t.Fatal("서명 없는 릴리스를 받음")
	}
	other, _, _ := sign.Generate()
	if err := Apply(context.Background(), srv.URL, signedRelease(t, other, body, "v0.3.0"), keys, "amd64", "v0.2.0", exe, state); err == nil || !unchanged() {
		t.Fatal("믿지 않는 키의 서명을 받음")
	}
	forged := rel
	forged.Sums = strings.Replace(rel.Sums, rel.SHA256[:8], "deadbeef", 1)
	if err := Apply(context.Background(), srv.URL, forged, keys, "amd64", "v0.2.0", exe, state); err == nil || !unchanged() {
		t.Fatal("바꿔치기한 목록을 받음")
	}
	// Hub가 지시한 버전과 서명된 버전이 다르면 거부, 이전 버전으로 되돌리기도 거부
	wrongVer := rel
	wrongVer.Version = "v0.4.0"
	if err := Apply(context.Background(), srv.URL, wrongVer, keys, "amd64", "v0.2.0", exe, state); err == nil || !unchanged() {
		t.Fatal("버전 불일치를 받음")
	}
	if err := Apply(context.Background(), srv.URL, signedRelease(t, sk, body, "v0.1.0"), keys, "amd64", "v0.2.0", exe, state); err == nil || !strings.Contains(err.Error(), "이전 버전") {
		t.Fatalf("되돌리기: %v", err)
	}
	// Hub가 알려 준 체크섬이 서명된 목록과 다르면 거부
	hubLie := rel
	hubLie.SHA256 = strings.Repeat("1", 64)
	if err := Apply(context.Background(), srv.URL, hubLie, keys, "amd64", "v0.2.0", exe, state); err == nil || !unchanged() {
		t.Fatal("체크섬 불일치를 받음")
	}
	// 이상한 다운로드 경로
	badPath := rel
	badPath.Path = "/dl/../../etc/passwd"
	if err := Apply(context.Background(), srv.URL, badPath, keys, "amd64", "v0.2.0", exe, state); err == nil {
		t.Fatal("경로 검사")
	}
	// 서명은 맞는데 내려받은 파일이 다르면 거부 (Hub가 다른 파일을 줌)
	served = []byte("evil")
	if err := Apply(context.Background(), srv.URL, rel, keys, "amd64", "v0.2.0", exe, state); err == nil || !unchanged() {
		t.Fatal("다른 파일로 교체됨")
	}
	if _, err := os.Stat(filepath.Join(dir, ".douve-agent.new")); err == nil {
		t.Fatal("임시 파일이 남음")
	}
	served = body
	os.Remove(filepath.Join(state, "last-update.json"))

	if err := Apply(context.Background(), srv.URL, rel, keys, "amd64", "v0.2.0", exe, state); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != string(body) {
		t.Fatal("교체 안 됨")
	}
	st, _ := os.Stat(exe)
	if st.Mode().Perm() != 0o755 {
		t.Fatalf("권한 %v", st.Mode().Perm())
	}
	// 같은 업데이트를 곧바로 다시 지시받으면 건너뜀 (재시작 반복 방지)
	if err := Apply(context.Background(), srv.URL, rel, keys, "amd64", "v0.2.0", exe, state); !errors.Is(err, ErrRecentlyTried) {
		t.Fatalf("반복 방지 실패: %v", err)
	}
}

func TestTrustedKeys(t *testing.T) {
	if len(TrustedKeys("/nonexistent")) != len(ReleaseKeys) {
		t.Fatal("공식 키가 기본으로 들어가야 함")
	}
	_, pk, _ := sign.Generate()
	p := filepath.Join(t.TempDir(), TrustedKeysFile)
	os.WriteFile(p, []byte("# 내 빌드 키\n"+pk.String()+"\ngarbage\n"), 0o600)
	keys := TrustedKeys(p)
	if len(keys) != len(ReleaseKeys)+1 || keys[len(keys)-1].IDHex() != pk.IDHex() {
		t.Fatalf("%d", len(keys))
	}
}
