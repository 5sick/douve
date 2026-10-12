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
	"testing"
)

func TestApplyVerifiesAndReplaces(t *testing.T) {
	body := []byte("#!/bin/sh\necho new\n")
	sum := sha256.Sum256(body)
	want := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	defer srv.Close()

	dir := t.TempDir()
	exe := filepath.Join(dir, "douve-agent")
	os.WriteFile(exe, []byte("old"), 0o755)
	state := filepath.Join(dir, "state")

	// 체크섬이 다르면 교체하지 않음
	bad := want[:63] + "0"
	if bad == want {
		bad = want[:63] + "1"
	}
	if err := Apply(context.Background(), srv.URL, "/x", bad, exe, state); err == nil {
		t.Fatal("체크섬 불일치를 통과시킴")
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatal("불일치인데 교체됨")
	}
	if _, err := os.Stat(filepath.Join(dir, ".douve-agent.new")); err == nil {
		t.Fatal("임시 파일이 남음")
	}

	if err := Apply(context.Background(), srv.URL, "/x", want, exe, state); err != nil {
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
	if err := Apply(context.Background(), srv.URL, "/x", want, exe, state); !errors.Is(err, ErrRecentlyTried) {
		t.Fatalf("반복 방지 실패: %v", err)
	}
}
