package term

import (
	"encoding/base64"
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
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, v.(map[string]any))
	return nil
}

func (r *recorder) wait(t *testing.T, pred func([]map[string]any) bool) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		cp := append([]map[string]any{}, r.msgs...)
		r.mu.Unlock()
		if pred(cp) {
			return cp
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("시간 초과: %v", r.msgs)
	return nil
}

func output(msgs []map[string]any) string {
	var b strings.Builder
	for _, m := range msgs {
		if m["type"] == "term_out" {
			d, _ := base64.StdEncoding.DecodeString(m["data"].(string))
			b.Write(d)
		}
	}
	return b.String()
}

func newMgr() (*Manager, *recorder) {
	m := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := &recorder{}
	m.SetSender(r.send)
	return m, r
}

func TestShellRoundTripAsSelf(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root에서는 systemd-run 경로라 단위 테스트에서 제외")
	}
	m, r := newMgr()
	me, _ := user.Current()
	m.Open("sess-0001", me.Username, 100, 30)
	r.wait(t, func(ms []map[string]any) bool { return len(ms) > 0 && ms[0]["type"] == "term_opened" })
	m.Input("sess-0001", base64.StdEncoding.EncodeToString([]byte("echo douve-$((40+2)); stty size\n")))
	r.wait(t, func(ms []map[string]any) bool {
		o := output(ms)
		return strings.Contains(o, "douve-42") && strings.Contains(o, "30 100")
	})
	m.Resize("sess-0001", 120, 40)
	m.Input("sess-0001", base64.StdEncoding.EncodeToString([]byte("stty size; exit 3\n")))
	ms := r.wait(t, func(ms []map[string]any) bool { return ms[len(ms)-1]["type"] == "term_exit" })
	if !strings.Contains(output(ms), "40 120") {
		t.Errorf("크기 조절 안 됨: %q", output(ms))
	}
	if code := ms[len(ms)-1]["code"]; code != 3 {
		t.Errorf("종료 코드 %v", code)
	}
	if m.Count() != 0 {
		t.Error("세션이 남음")
	}
}

func TestCloseKillsShell(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip()
	}
	m, r := newMgr()
	me, _ := user.Current()
	m.Open("sess-0002", me.Username, 80, 24)
	r.wait(t, func(ms []map[string]any) bool { return len(ms) > 0 })
	m.Close("sess-0002")
	r.wait(t, func(ms []map[string]any) bool { return ms[len(ms)-1]["type"] == "term_exit" })
}

func TestRejectsOtherUsersAndLimits(t *testing.T) {
	m, r := newMgr()
	m.Open("sess-0003", "root", 80, 24)
	ms := r.wait(t, func(ms []map[string]any) bool { return len(ms) > 0 })
	if ms[0]["type"] != "term_exit" || !strings.Contains(ms[0]["error"].(string), "허용되지 않은") {
		t.Fatalf("다른 계정 허용됨: %v", ms[0])
	}
	m.Open("bad id!", "x", 80, 24)
	ms = r.wait(t, func(ms []map[string]any) bool { return len(ms) > 1 })
	if !strings.Contains(ms[1]["error"].(string), "세션 ID") {
		t.Fatalf("%v", ms[1])
	}
}

func TestMaxSessions(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip()
	}
	m, r := newMgr()
	me, _ := user.Current()
	for i := 0; i < MaxSessions+1; i++ {
		m.Open("sess-max-"+string(rune('a'+i)), me.Username, 80, 24)
	}
	ms := r.wait(t, func(ms []map[string]any) bool { return len(ms) >= MaxSessions+1 })
	rejected := 0
	for _, x := range ms {
		if x["type"] == "term_exit" && strings.Contains(x["error"].(string), "동시") {
			rejected++
		}
	}
	if rejected != 1 {
		t.Fatalf("제한 초과 거부 %d개: %v", rejected, ms)
	}
	m.CloseAll()
	r.wait(t, func([]map[string]any) bool { return m.Count() == 0 })
}

func TestAllowedUsersRootMode(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "passwd"), []byte(`root:x:0:0:root:/root:/bin/bash
ubuntu:x:1000:1000::/home/ubuntu:/bin/bash
monitor:x:1001:1001::/home/monitor:/bin/bash
svc:x:998:998::/:/usr/sbin/nologin
rocky:x:1002:10::/home/rocky:/bin/bash
locked:x:1003:1003::/home/locked:/usr/sbin/nologin
`), 0o644)
	os.WriteFile(filepath.Join(dir, "group"), []byte(`wheel:x:10:
sudo:x:27:ubuntu,locked
monitor:x:1001:
`), 0o644)
	m := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.passwd, m.group, m.euid = filepath.Join(dir, "passwd"), filepath.Join(dir, "group"), 0
	m.sudoers = nil
	got := strings.Join(m.AllowedUsers(), ",")
	// ubuntu(sudo 구성원), rocky(주 그룹 wheel). monitor(관리 그룹 아님)·locked(nologin)·root 제외
	if got != "ubuntu,rocky" {
		t.Fatalf("%s", got)
	}
}

// Rocky 클라우드 이미지: wheel이 아니라 sudoers.d(cloud-init)로 권한. 특정 명령만 허용된 계정은 제외.
func TestAllowedUsersFromSudoers(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "passwd"), []byte(`rocky:x:1000:1000::/home/rocky:/bin/bash
monitor:x:1001:1001::/home/monitor:/bin/bash
ops:x:1002:1002::/home/ops:/bin/bash
`), 0o644)
	os.WriteFile(filepath.Join(dir, "group"), []byte("wheel:x:10:\nadm:x:4:rocky\ndevops:x:2000:ops\n"), 0o644)
	sd := filepath.Join(dir, "sudoers.d")
	os.Mkdir(sd, 0o755)
	os.WriteFile(filepath.Join(sd, "90-cloud-init-users"), []byte("# User rules for rocky\nrocky ALL=(ALL) NOPASSWD:ALL\n"), 0o440)
	os.WriteFile(filepath.Join(sd, "health-check"), []byte("monitor ALL=(root) NOPASSWD: /usr/local/bin/health-check\n"), 0o440)
	os.WriteFile(filepath.Join(sd, "devops"), []byte("%devops ALL=(ALL:ALL) ALL\n"), 0o440)
	os.WriteFile(filepath.Join(sd, "ignored.bak"), []byte("monitor ALL=(ALL) ALL\n"), 0o440) // '.' 포함 → sudo도 무시
	m := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.passwd, m.group, m.sudoers, m.euid = filepath.Join(dir, "passwd"), filepath.Join(dir, "group"), []string{sd}, 0
	if got := strings.Join(m.AllowedUsers(), ","); got != "rocky,ops" {
		t.Fatalf("%s", got)
	}
}

// root 경로(systemd-run) 시험. 운영 노드에서 직접: sudo DOUVE_ROOT_TEST_USER=<계정> ./term.test -test.run Root
func TestRootSystemdRun(t *testing.T) {
	name := os.Getenv("DOUVE_ROOT_TEST_USER")
	if os.Geteuid() != 0 || name == "" {
		t.Skip("root + DOUVE_ROOT_TEST_USER 필요")
	}
	m, r := newMgr()
	m.Open("root-test-01", name, 90, 33)
	r.wait(t, func(ms []map[string]any) bool { return len(ms) > 0 && ms[0]["type"] == "term_opened" })
	r.wait(t, func(ms []map[string]any) bool { return strings.Contains(output(ms), "$") }) // 프롬프트
	m.Input("root-test-01", base64.StdEncoding.EncodeToString([]byte("id -un; sudo -n true && echo SUDO-$((1+1)); stty size; exit 4\n")))
	ms := r.wait(t, func(ms []map[string]any) bool { return ms[len(ms)-1]["type"] == "term_exit" })
	out := output(ms)
	for _, want := range []string{name, "SUDO-2", "33 90"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q 없음: %q", want, out)
		}
	}
	if code := ms[len(ms)-1]["code"]; code != 4 {
		t.Errorf("종료 코드 %v (출력 %q)", code, out)
	}
}
