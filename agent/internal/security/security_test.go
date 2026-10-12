package security

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func jline(id, msg string, ts int64, cursor string) string {
	return fmt.Sprintf(`{"SYSLOG_IDENTIFIER":%q,"MESSAGE":%q,"__REALTIME_TIMESTAMP":"%d","__CURSOR":%q}`, id, msg, ts*1_000_000, cursor)
}

func TestJournalParsing(t *testing.T) {
	dir := t.TempDir()
	var gotCursor string
	out := strings.Join([]string{
		jline("sshd-session", "Accepted publickey for monitor from 172.20.0.3 port 33380 ssh2: ED25519 SHA256:abc", 100, "c1"),
		jline("sshd", "Failed password for root from 1.2.3.4 port 22 ssh2", 101, "c2"),
		jline("sshd", "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2", 102, "c3"),
		jline("sshd", "Invalid user test from 1.2.3.4 port 5555", 103, "c4"),
		jline("sshd", "Invalid user x from 1.2.3.4 port 5555", 104, "c5"),
		jline("sshd", "Invalid user y from 1.2.3.4 port 5555", 105, "c6"),
		jline("sshd", "Failed password for root from 9.9.9.9 port 22 ssh2", 106, "c7"), // 1회 → 보고 안 함
		jline("sudo", "monitor :  PWD=/home/monitor ; USER=root ; COMMAND=/usr/local/bin/health-check certs", 107, "c8"),
		jline("sudo", "   rocky : TTY=pts/3 ; PWD=/home/rocky ; USER=root ; COMMAND=/bin/systemctl restart nginx", 108, "c9"),
		jline("sudo", "pam_unix(sudo:session): session opened for user root(uid=0) by rocky(uid=1000)", 109, "c10"),
		jline("su", "(to root) ubuntu on pts/7", 110, "c11"),
		jline("useradd", "new user: name=evil, UID=1005, GID=1005, home=/home/evil, shell=/bin/bash", 111, "c12"),
		"-- cursor: c12",
	}, "\n")
	c := &Collector{StateDir: dir, files: func() []string { return nil },
		journal: func(_ context.Context, cursor string) ([]byte, error) { gotCursor = cursor; return []byte(out), nil },
		Resolve: func(tty string) string {
			if tty == "pts/3" {
				return "sid-douve"
			}
			return ""
		}}
	c.load()
	ev := c.Collect(context.Background(), nil)
	kinds := map[string]int{}
	for _, e := range ev {
		kinds[e.Kind]++
	}
	if kinds["ssh_login"] != 1 || kinds["ssh_fail"] != 1 || kinds["sudo"] != 2 || kinds["su"] != 1 || kinds["account"] != 1 {
		t.Fatalf("%v\n%+v", kinds, ev)
	}
	for _, e := range ev {
		switch e.Kind {
		case "ssh_login":
			if e.Fields["user"] != "monitor" || e.Fields["ip"] != "172.20.0.3" || e.TS != 100 {
				t.Errorf("%+v", e)
			}
		case "ssh_fail":
			if e.Fields["ip"] != "1.2.3.4" || e.Fields["count"] != "5" {
				t.Errorf("%+v", e)
			}
		case "sudo":
			if e.Fields["user"] == "rocky" && (e.ViaSID != "sid-douve" || e.Fields["tty"] != "pts/3") {
				t.Errorf("Douve 터미널 sudo 표시: %+v", e)
			}
			if e.Fields["user"] == "monitor" && (e.ViaSID != "" || !strings.Contains(e.Fields["command"], "health-check")) {
				t.Errorf("%+v", e)
			}
		}
	}
	if gotCursor != "" {
		t.Errorf("처음에는 커서 없이: %q", gotCursor)
	}
	// 커서 저장 → 다음 호출에서 사용
	c2 := &Collector{StateDir: dir, files: func() []string { return nil },
		journal: func(_ context.Context, cursor string) ([]byte, error) { gotCursor = cursor; return nil, nil }}
	c2.load()
	c2.Collect(context.Background(), nil)
	if gotCursor != "c12" {
		t.Errorf("저장된 커서 %q", gotCursor)
	}
}

func TestFileChanges(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "authorized_keys")
	os.WriteFile(a, []byte("key1\n"), 0o600)
	files := []string{a}
	c := &Collector{StateDir: dir, files: func() []string { return files },
		journal: func(context.Context, string) ([]byte, error) { return nil, nil }}
	c.load()
	if ev := c.Collect(context.Background(), nil); len(ev) != 0 {
		t.Fatalf("첫 실행은 기준선만: %+v", ev)
	}
	os.WriteFile(a, []byte("key1\nkey2\n"), 0o600)
	ev := c.Collect(context.Background(), nil)
	if len(ev) != 1 || ev[0].Kind != "file_changed" || ev[0].Fields["change"] != "변경" {
		t.Fatalf("%+v", ev)
	}
	if ev := c.Collect(context.Background(), nil); len(ev) != 0 {
		t.Fatalf("같은 내용이면 조용: %+v", ev)
	}
	b := filepath.Join(dir, "sudoers.d-evil")
	os.WriteFile(b, []byte("evil ALL=(ALL) NOPASSWD: ALL\n"), 0o440)
	files = append(files, b)
	ev = c.Collect(context.Background(), nil)
	if len(ev) != 1 || ev[0].Fields["change"] != "생성" {
		t.Fatalf("%+v", ev)
	}
	os.Remove(a)
	files = files[1:]
	ev = c.Collect(context.Background(), nil)
	if len(ev) != 1 || ev[0].Fields["change"] != "삭제" {
		t.Fatalf("%+v", ev)
	}
}

func TestNewPorts(t *testing.T) {
	dir := t.TempDir()
	c := &Collector{StateDir: dir, files: func() []string { return nil },
		journal: func(context.Context, string) ([]byte, error) { return nil, nil }}
	c.load()
	if ev := c.Collect(context.Background(), []string{"22 sshd", "443 douve-agent"}); len(ev) != 0 {
		t.Fatalf("첫 실행 기준선: %+v", ev)
	}
	ev := c.Collect(context.Background(), []string{"22 sshd", "443 douve-agent", "4444 nc"})
	if len(ev) != 1 || ev[0].Fields["listen"] != "4444 nc" {
		t.Fatalf("%+v", ev)
	}
	// 재시작 후에도 기준선 유지
	c2 := &Collector{StateDir: dir, files: func() []string { return nil },
		journal: func(context.Context, string) ([]byte, error) { return nil, nil }}
	c2.load()
	if ev := c2.Collect(context.Background(), []string{"22 sshd", "443 douve-agent", "4444 nc"}); len(ev) != 0 {
		t.Fatalf("%+v", ev)
	}
}
