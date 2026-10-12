// Package security는 노드의 보안 관련 사건을 모아 Hub로 보낸다.
//
//   - journald: SSH 로그인 성공·실패, sudo, su, 계정 변경(useradd 등) — 커서를 저장해 놓치지 않음
//   - 중요 파일 변경: passwd·shadow·sudoers·sshd 설정·authorized_keys·cron·systemd 유닛 (SHA-256 비교)
//   - 새로 열린 공개 포트
//
// 판단(심각도·알림·"문제 없음" 처리)은 Hub가 한다. Agent는 사실만 보고한다.
package security

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Event는 Hub로 보내는 사건 하나다.
type Event struct {
	Kind    string            `json:"kind"` // ssh_login, ssh_fail, sudo, su, account, file_changed, port_opened
	TS      int64             `json:"ts"`   // 유닉스 초
	Summary string            `json:"summary"`
	Fields  map[string]string `json:"fields"`
	ViaSID  string            `json:"via_sid,omitempty"` // Douve 웹 터미널 세션에서 일어난 일
}

// TTYResolver는 pts 이름(예: pts/3)이 Douve 터미널 세션이면 그 세션 ID를 돌려준다.
type TTYResolver func(tty string) string

type Collector struct {
	StateDir string
	Resolve  TTYResolver
	// Enabled가 있으면 켜진 종류만 보고한다 (Hub의 보안 감시 항목 설정)
	Enabled func(kind string) bool

	// 테스트에서 바꿈
	journal func(ctx context.Context, cursor string) ([]byte, error)
	files   func() []string

	cursor   string
	hashes   map[string]string
	ports    map[string]bool
	failures map[string]int // ip → 이번 주기 실패 수
}

func New(stateDir string, resolve TTYResolver) *Collector {
	c := &Collector{StateDir: stateDir, Resolve: resolve, journal: readJournal, files: watchedFiles}
	// 시험용 훅 (E2E): journald 대신 파일(읽고 비움), 감시 파일 목록 지정
	if p := os.Getenv("DOUVE_TEST_JOURNAL_FILE"); p != "" {
		c.journal = func(context.Context, string) ([]byte, error) {
			b, err := os.ReadFile(p)
			if err == nil {
				_ = os.Truncate(p, 0)
			}
			return b, err
		}
	}
	if v := os.Getenv("DOUVE_TEST_WATCH_FILES"); v != "" {
		list := strings.Split(v, ":")
		c.files = func() []string { return list }
	}
	c.load()
	return c
}

// TestHooksEnabled는 시험용 훅이 켜져 있는지 (root가 아니어도 보안 수집을 돌림).
func TestHooksEnabled() bool { return os.Getenv("DOUVE_TEST_JOURNAL_FILE") != "" }

type persisted struct {
	Cursor string            `json:"cursor"`
	Hashes map[string]string `json:"hashes"`
	Ports  []string          `json:"ports"`
}

func (c *Collector) statePath() string { return filepath.Join(c.StateDir, "security.json") }

func (c *Collector) load() {
	c.hashes = map[string]string{}
	c.ports = map[string]bool{}
	b, err := os.ReadFile(c.statePath())
	if err != nil {
		return
	}
	var p persisted
	if json.Unmarshal(b, &p) == nil {
		c.cursor = p.Cursor
		if p.Hashes != nil {
			c.hashes = p.Hashes
		}
		for _, x := range p.Ports {
			c.ports[x] = true
		}
	}
}

func (c *Collector) save() {
	p := persisted{Cursor: c.cursor, Hashes: c.hashes}
	for x := range c.ports {
		p.Ports = append(p.Ports, x)
	}
	sort.Strings(p.Ports)
	b, _ := json.Marshal(p)
	_ = os.MkdirAll(c.StateDir, 0o700)
	tmp := c.statePath() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, c.statePath())
	}
}

var journalIDs = []string{"sshd", "sshd-session", "sudo", "su", "useradd", "userdel", "usermod",
	"groupadd", "groupdel", "gpasswd", "passwd", "chpasswd", "chage"}

func readJournal(ctx context.Context, cursor string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	args := []string{"--no-pager", "-o", "json", "--show-cursor"}
	if cursor == "" {
		args = append(args, "-n", "0") // 처음에는 지금부터 (과거 로그로 알림 폭탄 방지)
	} else {
		args = append(args, "--after-cursor="+cursor, "-n", "2000")
	}
	for _, id := range journalIDs {
		args = append(args, "SYSLOG_IDENTIFIER="+id)
	}
	return exec.CommandContext(ctx, "journalctl", args...).Output()
}

var (
	reAccepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port \d+`)
	reFailed   = regexp.MustCompile(`^Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port`)
	reInvalid  = regexp.MustCompile(`^Invalid user (\S*) from (\S+)`)
	reSudo     = regexp.MustCompile(`^\s*(\S+) :\s*(?:TTY=(\S+) ; )?PWD=.*? ; USER=(\S+) ; COMMAND=(.*)$`)
	reSu       = regexp.MustCompile(`\(to (\S+)\) (\S+) on (\S+)`)
)

// Collect는 지난번 이후의 사건을 모은다 (주기적으로 호출).
func (c *Collector) Collect(ctx context.Context, listening []string) []Event {
	var all []Event
	all = append(all, c.fromJournal(ctx)...)
	all = append(all, c.fileChanges()...) // 꺼져 있어도 기준선은 계속 갱신 (다시 켤 때 오래된 변경이 쏟아지지 않게)
	if listening != nil {
		all = append(all, c.newPorts(listening)...)
	}
	c.save()
	if c.Enabled == nil {
		return all
	}
	var events []Event
	for _, e := range all {
		if c.Enabled(e.Kind) {
			events = append(events, e)
		}
	}
	return events
}

func (c *Collector) fromJournal(ctx context.Context) []Event {
	out, err := c.journal(ctx, c.cursor)
	if err != nil {
		return nil
	}
	var events []Event
	c.failures = map[string]int{}
	firstFail := map[string]int64{}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "-- cursor: ") {
			c.cursor = strings.TrimPrefix(line, "-- cursor: ")
			continue
		}
		var e map[string]any
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		msg, _ := e["MESSAGE"].(string)
		id, _ := e["SYSLOG_IDENTIFIER"].(string)
		if cur, ok := e["__CURSOR"].(string); ok {
			c.cursor = cur
		}
		ts := int64(0)
		if us, ok := e["__REALTIME_TIMESTAMP"].(string); ok {
			n, _ := strconv.ParseInt(us, 10, 64)
			ts = n / 1_000_000
		}
		switch {
		case id == "sshd" || id == "sshd-session":
			if m := reAccepted.FindStringSubmatch(msg); m != nil {
				events = append(events, Event{Kind: "ssh_login", TS: ts,
					Summary: "SSH 로그인: " + m[2] + " (" + m[3] + ", " + m[1] + ")",
					Fields:  map[string]string{"user": m[2], "ip": m[3], "method": m[1]}})
			} else if m := reFailed.FindStringSubmatch(msg); m != nil {
				c.failures[m[3]]++
				if firstFail[m[3]] == 0 {
					firstFail[m[3]] = ts
				}
			} else if m := reInvalid.FindStringSubmatch(msg); m != nil {
				c.failures[m[2]]++
				if firstFail[m[2]] == 0 {
					firstFail[m[2]] = ts
				}
			}
		case id == "sudo":
			if m := reSudo.FindStringSubmatch(msg); m != nil {
				ev := Event{Kind: "sudo", TS: ts, Summary: "sudo: " + m[1] + " → " + m[3] + ": " + truncate(m[4], 160),
					Fields: map[string]string{"user": m[1], "tty": m[2], "as": m[3], "command": truncate(m[4], 500)}}
				if m[2] != "" && c.Resolve != nil {
					ev.ViaSID = c.Resolve(strings.TrimPrefix(m[2], "/dev/"))
				}
				events = append(events, ev)
			}
		case id == "su":
			if m := reSu.FindStringSubmatch(msg); m != nil {
				ev := Event{Kind: "su", TS: ts, Summary: "su: " + m[2] + " → " + m[1],
					Fields: map[string]string{"user": m[2], "as": m[1], "tty": m[3]}}
				if c.Resolve != nil {
					ev.ViaSID = c.Resolve(strings.TrimPrefix(m[3], "/dev/"))
				}
				events = append(events, ev)
			}
		default: // 계정 변경 도구
			if strings.Contains(msg, "pam_unix") {
				continue
			}
			events = append(events, Event{Kind: "account", TS: ts, Summary: id + ": " + truncate(msg, 200),
				Fields: map[string]string{"tool": id, "message": truncate(msg, 500)}})
		}
	}
	// 실패는 IP별로 묶어서 보고 (5회 이상만)
	for ip, n := range c.failures {
		if n >= 5 {
			events = append(events, Event{Kind: "ssh_fail", TS: firstFail[ip],
				Summary: "SSH 로그인 실패 " + strconv.Itoa(n) + "회 (" + ip + ")",
				Fields:  map[string]string{"ip": ip, "count": strconv.Itoa(n)}})
		}
	}
	return events
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// watchedFiles는 변경을 감시할 파일 목록이다.
func watchedFiles() []string {
	files := []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers", "/etc/ssh/sshd_config",
		"/etc/crontab", "/root/.ssh/authorized_keys"}
	for _, pat := range []string{"/etc/sudoers.d/*", "/etc/ssh/sshd_config.d/*", "/etc/cron.d/*",
		"/var/spool/cron/*", "/var/spool/cron/crontabs/*", "/home/*/.ssh/authorized_keys",
		"/etc/systemd/system/*.service", "/etc/systemd/system/*.timer"} {
		m, _ := filepath.Glob(pat)
		files = append(files, m...)
	}
	return files
}

func hashFile(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 16<<20)); err != nil {
		return "", false
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

func (c *Collector) fileChanges() []Event {
	now := time.Now().Unix()
	first := len(c.hashes) == 0
	seen := map[string]bool{}
	var events []Event
	for _, p := range c.files() {
		seen[p] = true
		h, ok := hashFile(p)
		if !ok {
			continue
		}
		old, had := c.hashes[p]
		c.hashes[p] = h
		if first || old == h {
			continue
		}
		change := "변경"
		if !had {
			change = "생성"
		}
		events = append(events, Event{Kind: "file_changed", TS: now, Summary: "중요 파일 " + change + ": " + p,
			Fields: map[string]string{"path": p, "change": change, "sha256": h[:16]}})
	}
	for p := range c.hashes {
		if !seen[p] {
			delete(c.hashes, p)
			if !first {
				events = append(events, Event{Kind: "file_changed", TS: now, Summary: "중요 파일 삭제: " + p,
					Fields: map[string]string{"path": p, "change": "삭제", "sha256": "deleted"}})
			}
		}
	}
	return events
}

// newPorts: listening = "주소:포트 프로세스" 목록 (공개 주소만). 처음 본 것만 알린다.
func (c *Collector) newPorts(listening []string) []Event {
	first := len(c.ports) == 0
	now := time.Now().Unix()
	var events []Event
	for _, l := range listening {
		if c.ports[l] {
			continue
		}
		c.ports[l] = true
		if first {
			continue
		}
		events = append(events, Event{Kind: "port_opened", TS: now, Summary: "새 공개 포트: " + l,
			Fields: map[string]string{"listen": l}})
	}
	return events
}
