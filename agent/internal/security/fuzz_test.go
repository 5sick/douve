package security

import (
	"context"
	"testing"
)

// journald 출력 해석: 로그 내용은 외부(로그인 시도자)가 정할 수 있다. 멈추거나 요약이 끝없이 길어지면 안 된다.
func FuzzJournal(f *testing.F) {
	f.Add(jline("sshd", "Failed password for root from 1.2.3.4 port 22 ssh2", 1, "c1"))
	f.Add(jline("sudo", "   rocky : TTY=pts/3 ; PWD=/x ; USER=root ; COMMAND=/bin/ls", 2, "c2") + "\n-- cursor: c2")
	f.Add(jline("useradd", "new user: name=evil, UID=1005", 3, "c3"))
	f.Fuzz(func(t *testing.T, out string) {
		c := &Collector{StateDir: t.TempDir(), files: func() []string { return nil },
			journal: func(context.Context, string) ([]byte, error) { return []byte(out), nil },
			Resolve: func(string) string { return "" }}
		for _, e := range c.Collect(context.Background(), nil) {
			if len(e.Summary) > 600 {
				t.Fatalf("요약이 너무 김: %d", len(e.Summary))
			}
		}
	})
}
