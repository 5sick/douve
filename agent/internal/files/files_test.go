package files

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type recorder struct {
	mu   sync.Mutex
	msgs []map[string]any
}

func (r *recorder) send(v any) error {
	r.mu.Lock()
	r.msgs = append(r.msgs, v.(map[string]any))
	r.mu.Unlock()
	return nil
}

func (r *recorder) last(sid string) map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.msgs) - 1; i >= 0; i-- {
		if r.msgs[i]["sid"] == sid {
			return r.msgs[i]
		}
	}
	return nil
}

func (r *recorder) wait(t *testing.T, sid, typ string) map[string]any {
	t.Helper()
	for i := 0; i < 200; i++ {
		if m := r.last(sid); m != nil && (m["type"] == typ || m["type"] == "file_error") {
			return m
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s: %s 안 옴", sid, typ)
	return nil
}

func setup(t *testing.T) (*Manager, *recorder, string) {
	if os.Geteuid() == 0 {
		t.Skip("root가 아닌 계정에서 시험 (root면 systemd-run 경로)")
	}
	me, _ := user.Current()
	r := &recorder{}
	m := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)), func() Sender { return r.send },
		func(n string) bool { return n == me.Username })
	return m, r, me.Username
}

func shaHex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func upload(m *Manager, sid, me, path string, data []byte, sha string) {
	m.Put(sid, me, path, int64(len(data)), sha)
	for i := 0; i < len(data); i += 1000 {
		j := min(i+1000, len(data))
		m.Chunk(sid, base64.StdEncoding.EncodeToString(data[i:j]))
	}
	m.End(sid)
}

func TestPutGet(t *testing.T) {
	m, r, me := setup(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "a b:c.txt") // 공백·콜론
	data := []byte(strings.Repeat("douve 파일 ", 5000))
	upload(m, "sid-put-0001", me, path, data, shaHex(data))
	if got := r.wait(t, "sid-put-0001", "file_done"); got["type"] != "file_done" || got["sha256"] != shaHex(data) {
		t.Fatalf("올리기: %v", got)
	}
	if b, _ := os.ReadFile(path); string(b) != string(data) {
		t.Fatal("내용")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.douve-*")); len(left) != 0 {
		t.Fatalf("임시 파일 남음: %v", left)
	}
	// 내려받기
	m.Get("sid-get-0001", me, path)
	var got []byte
	r.mu.Lock()
	for _, msg := range r.msgs {
		if msg["sid"] == "sid-get-0001" && msg["type"] == "file_data" {
			b, _ := base64.StdEncoding.DecodeString(msg["data"].(string))
			got = append(got, b...)
		}
	}
	r.mu.Unlock()
	done := r.last("sid-get-0001")
	if string(got) != string(data) || done["type"] != "file_done" || done["sha256"] != shaHex(data) {
		t.Fatalf("내려받기: %d %v", len(got), done)
	}
}

func TestPutRejectsMismatch(t *testing.T) {
	m, r, me := setup(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "x.txt")
	if err := os.WriteFile(path, []byte("원래 내용"), 0o600); err != nil {
		t.Fatal(err)
	}
	data := []byte("바꿔치기한 내용")
	upload(m, "sid-bad-0001", me, path, data, shaHex([]byte("서명한 내용")))
	if got := r.wait(t, "sid-bad-0001", "file_done"); got["type"] != "file_error" {
		t.Fatalf("다른 내용이 통과: %v", got)
	}
	time.Sleep(100 * time.Millisecond)
	if b, _ := os.ReadFile(path); string(b) != "원래 내용" {
		t.Fatal("원래 파일이 바뀜")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.douve-*")); len(left) != 0 {
		t.Fatalf("임시 파일 남음: %v", left)
	}
	// 서명한 크기보다 많이 보내면 바로 중단
	m.Put("sid-big-0001", me, path, 3, shaHex([]byte("abc")))
	m.Chunk("sid-big-0001", base64.StdEncoding.EncodeToString([]byte("abcdef")))
	if got := r.last("sid-big-0001"); got["type"] != "file_error" {
		t.Fatalf("크기 초과: %v", got)
	}
}

func TestRejects(t *testing.T) {
	m, r, me := setup(t)
	dir := t.TempDir()
	m.Get("sid-dir-0001", me, dir+"/sub")
	if got := r.last("sid-dir-0001"); got["type"] != "file_error" {
		t.Fatalf("없는 파일: %v", got)
	}
	m.Get("sid-dir-0002", me, dir)
	if got := r.last("sid-dir-0002"); got["type"] != "file_error" {
		t.Fatalf("디렉터리: %v", got)
	}
	m.Get("sid-root-001", "root", "/etc/shadow")
	if got := r.last("sid-root-001"); got["type"] != "file_error" || !strings.Contains(got["error"].(string), "허용되지 않은") {
		t.Fatalf("다른 계정: %v", got)
	}
	m.Put("sid-big-0002", me, dir+"/f", MaxSize+1, shaHex(nil))
	if got := r.last("sid-big-0002"); got["type"] != "file_error" {
		t.Fatal("100MB 초과")
	}
	for _, p := range []string{"", "a\nb", "dir/", ".", "..", "a/..", "~/x", strings.Repeat("a", 5000)} {
		if ValidPath(p) == nil {
			t.Errorf("잘못된 경로 허용: %q", p)
		}
	}
	for _, p := range []string{"a.txt", "/tmp/x y", "../up.txt", "a~b"} {
		if err := ValidPath(p); err != nil {
			t.Errorf("%q: %v", p, err)
		}
	}
}

func TestActions(t *testing.T) {
	if got := PutAction("ubuntu", 3, "ab", "/tmp/a:b"); got != "file-put:ubuntu:3:ab:/tmp/a:b" {
		t.Fatal(got)
	}
	if got := GetAction("ubuntu", "x"); got != "file-get:ubuntu:x" {
		t.Fatal(got)
	}
}
