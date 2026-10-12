// Package term은 Hub를 거쳐 브라우저에 여는 터미널 세션(PTY)이다.
//
// root로 실행 중이면 Agent가 PTY를 만들고 `systemd-run --wait --uid=<계정> -p TTYPath=<pts>`로 로그인 셸을 띄운다.
// 셸은 PID1이 만든 새 유닛에서 돌기 때문에 Agent 서비스의 샌드박스(NoNewPrivileges 등)와 무관하게
// sudo 등이 정상 동작한다. root가 아니면(개발·시험) 자기 계정 셸만 직접 실행한다.
package term

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
)

const (
	MaxSessions = 4
	IdleTimeout = 30 * time.Minute
	readChunk   = 32 * 1024
)

// Sender는 Hub로 메시지를 보낸다 (현재 WebSocket 연결).
type Sender func(v any) error

type Manager struct {
	log *slog.Logger

	// 테스트에서 바꿈
	passwd, group string
	sudoers       []string // 파일 또는 디렉터리
	euid          int

	mu       sync.Mutex
	sessions map[string]*session
	send     Sender
	recent   map[string]closedTTY // 최근 끝난 세션의 pts (보안 사건 출처 표시용)
}

type closedTTY struct {
	sid string
	at  time.Time
}

type session struct {
	id        string
	unit      string // systemd-run 유닛 이름 (root 모드)
	ptmx      *os.File
	tty       *os.File // root 모드: systemd에 넘긴 PTY 슬레이브 (끝날 때 닫음)
	cmd       *exec.Cmd
	done      chan int // 종료 코드
	errOut    *strings.Builder
	lastInput time.Time
	closed    bool
}

func NewManager(log *slog.Logger) *Manager {
	return &Manager{log: log, passwd: "/etc/passwd", group: "/etc/group",
		sudoers: []string{"/etc/sudoers", "/etc/sudoers.d"}, euid: os.Geteuid(),
		sessions: map[string]*session{}, recent: map[string]closedTTY{}}
}

// SetSender는 Hub 연결이 바뀔 때 호출한다.
func (m *Manager) SetSender(s Sender) {
	m.mu.Lock()
	m.send = s
	m.mu.Unlock()
}

func (m *Manager) emit(v any) {
	m.mu.Lock()
	send := m.send
	m.mu.Unlock()
	if send != nil {
		_ = send(v)
	}
}

// 모든 명령 허용 규칙만 인정: "user ALL=(ALL) NOPASSWD: ALL", "%group ALL=(ALL:ALL) ALL".
// "monitor ALL=(root) NOPASSWD: /usr/local/bin/health-check"처럼 특정 명령만 허용된 계정은 제외.
var sudoAllRe = regexp.MustCompile(`^(%?[A-Za-z0-9_.-]+)\s+ALL\s*=\s*(\([^)]*\))?\s*(NOPASSWD:\s*)?ALL\s*$`)

// sudoAll은 sudoers에서 모든 명령 권한을 가진 계정과 그룹을 찾는다.
func (m *Manager) sudoAll() (users, groups map[string]bool) {
	users, groups = map[string]bool{}, map[string]bool{}
	var files []string
	for _, p := range m.sudoers {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		if !st.IsDir() {
			files = append(files, p)
			continue
		}
		entries, _ := os.ReadDir(p)
		for _, e := range entries {
			// sudo도 '.'이나 '~'가 들어간 파일은 읽지 않는다
			if !e.IsDir() && !strings.ContainsAny(e.Name(), ".~") {
				files = append(files, filepath.Join(p, e.Name()))
			}
		}
	}
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if mm := sudoAllRe.FindStringSubmatch(line); mm != nil {
				if strings.HasPrefix(mm[1], "%") {
					groups[mm[1][1:]] = true
				} else {
					users[mm[1]] = true
				}
			}
		}
		fh.Close()
	}
	return users, groups
}

// AllowedUsers는 터미널을 열 수 있는 계정이다.
// root 모드: sudo 전체 권한이 있는 계정(sudoers 직접·그룹, 또는 sudo/wheel/admin 그룹) 중
// uid 1000~59999, 로그인 가능한 셸.
// 아니면: 자기 계정만.
func (m *Manager) AllowedUsers() []string {
	if m.euid != 0 {
		if u, err := user.Current(); err == nil {
			return []string{u.Username}
		}
		return nil
	}
	admins, sudoGroups := m.sudoAll()
	for _, g := range []string{"sudo", "wheel", "admin"} {
		sudoGroups[g] = true
	}
	adminGIDs := map[string]bool{}
	if f, err := os.Open(m.group); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			p := strings.Split(sc.Text(), ":")
			if len(p) < 4 || !sudoGroups[p[0]] {
				continue
			}
			adminGIDs[p[2]] = true
			for _, u := range strings.Split(p[3], ",") {
				if u != "" {
					admins[u] = true
				}
			}
		}
		f.Close()
	}
	var out []string
	f, err := os.Open(m.passwd)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) < 7 {
			continue
		}
		uid := 0
		fmt.Sscan(p[2], &uid)
		shell := p[6]
		if uid < 1000 || uid >= 60000 || strings.HasSuffix(shell, "nologin") || strings.HasSuffix(shell, "false") || shell == "" {
			continue
		}
		if admins[p[0]] || adminGIDs[p[3]] {
			out = append(out, p[0])
		}
	}
	return out
}

func (m *Manager) userAllowed(name string) bool {
	for _, u := range m.AllowedUsers() {
		if u == name {
			return true
		}
	}
	return false
}

func validSID(sid string) bool {
	if len(sid) < 8 || len(sid) > 64 {
		return false
	}
	for _, c := range sid {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func clampSize(cols, rows int) (uint16, uint16) {
	if cols < 10 || cols > 1000 {
		cols = 80
	}
	if rows < 3 || rows > 500 {
		rows = 24
	}
	return uint16(cols), uint16(rows)
}

// start는 셸을 띄우고 PTY 마스터를 돌려준다.
//   - 비root(개발·시험): 자기 계정 셸을 PTY에서 직접 실행
//   - root: Agent가 PTY를 만들고 `systemd-run --wait`에 TTYPath로 넘긴다. 셸은 PID1이 만든 새 유닛에서
//     돌아 Agent 샌드박스와 무관하게 sudo가 동작한다. (systemd-run --pty는 쓰지 않는다: SELinux에서
//     Agent 문맥이 만든 pts(devpts_t)를 PID1이 열 수 없어 208/STDIN으로 실패 — 아래 relabel 참고)
func (m *Manager) start(sid, name string, cols, rows uint16) (*session, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, err
	}
	shell := loginShell(m.passwd, name)
	size := &pty.Winsize{Cols: cols, Rows: rows}
	if m.euid != 0 {
		cmd := exec.Command(shell, "-l")
		cmd.Dir = u.HomeDir
		cmd.Env = append(os.Environ(), "TERM=xterm-256color", "DOUVE_TERMINAL=1")
		ptmx, err := pty.StartWithSize(cmd, size)
		if err != nil {
			return nil, err
		}
		return &session{id: sid, ptmx: ptmx, cmd: cmd, lastInput: time.Now(), done: make(chan int, 1)}, nil
	}
	ptmx, tty, err := pty.Open()
	if err != nil {
		return nil, err
	}
	_ = pty.Setsize(ptmx, size)
	relabelForInit(tty.Name())
	unit := "douve-term-" + sid
	cmd := exec.Command("systemd-run", "--wait", "--quiet", "--collect",
		"--unit="+unit, "--uid="+name,
		"-p", "WorkingDirectory=~",
		// 기다리지 않고 바로 이 PTY를 제어 터미널로 (tty 모드는 inotify watch가 필요하고 SELinux가 막음)
		"-p", "StandardInput=tty-force", "-p", "StandardOutput=tty", "-p", "StandardError=tty",
		"-p", "TTYPath="+tty.Name(), // 새 PTY라 TTYReset/TTYVHangup 불필요 (먼저 들어온 입력을 지움)
		"--setenv=TERM=xterm-256color", "--setenv=DOUVE_TERMINAL=1",
		"--", shell, "-l")
	var errBuf strings.Builder
	cmd.Stdout = &errBuf
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		ptmx.Close()
		tty.Close()
		return nil, err
	}
	return &session{id: sid, unit: unit, ptmx: ptmx, tty: tty, cmd: cmd, lastInput: time.Now(),
		done: make(chan int, 1), errOut: &errBuf}, nil
}

// relabelForInit은 SELinux가 켜진 시스템에서 PTY 레이블을 user_devpts_t로 바꿔 PID1(init_t)이 열 수 있게 한다.
// Agent(unconfined_service_t)가 만든 pts는 devpts_t라 init_t의 open이 거부된다. SELinux가 없으면 아무 일도 하지 않는다.
func relabelForInit(path string) {
	if _, err := os.Stat("/sys/fs/selinux/enforce"); err != nil {
		return
	}
	_ = syscall.Setxattr(path, "security.selinux", []byte("system_u:object_r:user_devpts_t:s0"), 0)
}

func loginShell(passwd, name string) string {
	if f, err := os.Open(passwd); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			p := strings.Split(sc.Text(), ":")
			if len(p) >= 7 && p[0] == name && p[6] != "" {
				return p[6]
			}
		}
	}
	return "/bin/sh"
}

// Open은 새 세션을 연다. 결과는 term_opened 또는 term_exit(error)로 Hub에 알린다.
func (m *Manager) Open(sid, name string, cols, rows int) {
	fail := func(err error) {
		m.log.Warn("터미널 열기 실패", "user", name, "err", err)
		m.emit(map[string]any{"type": "term_exit", "sid": sid, "code": -1, "error": err.Error()})
	}
	if !validSID(sid) {
		fail(errors.New("잘못된 세션 ID"))
		return
	}
	if !m.userAllowed(name) {
		fail(fmt.Errorf("허용되지 않은 계정: %s", name))
		return
	}
	m.mu.Lock()
	if _, dup := m.sessions[sid]; dup || len(m.sessions) >= MaxSessions {
		m.mu.Unlock()
		fail(fmt.Errorf("동시 터미널은 %d개까지입니다", MaxSessions))
		return
	}
	m.sessions[sid] = &session{id: sid, lastInput: time.Now()} // 자리 예약
	m.mu.Unlock()

	c, r := clampSize(cols, rows)
	sess, err := m.start(sid, name, c, r)
	if err != nil {
		m.mu.Lock()
		delete(m.sessions, sid)
		m.mu.Unlock()
		fail(err)
		return
	}
	m.mu.Lock()
	m.sessions[sid] = sess
	m.mu.Unlock()
	m.log.Info("터미널 열림", "sid", sid, "user", name)
	m.emit(map[string]any{"type": "term_opened", "sid": sid})
	go m.wait(sess)
	go m.pump(sess)
}

// wait는 셸(또는 systemd-run --wait)이 끝나기를 기다렸다가 PTY를 닫아 pump를 끝낸다.
func (m *Manager) wait(s *session) {
	code := 0
	if err := s.cmd.Wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	if s.errOut != nil && code != 0 && s.errOut.Len() > 0 {
		m.log.Warn("systemd-run", "sid", s.id, "out", strings.TrimSpace(s.errOut.String()))
	}
	time.Sleep(200 * time.Millisecond) // 남은 출력 전달
	if s.tty != nil {
		m.mu.Lock()
		m.recent[s.tty.Name()] = closedTTY{sid: s.id, at: time.Now()}
		m.mu.Unlock()
		s.tty.Close()
	}
	s.ptmx.Close()
	s.done <- code
}

func (m *Manager) pump(s *session) {
	buf := make([]byte, readChunk)
	for {
		n, err := s.ptmx.Read(buf)
		if n > 0 {
			m.emit(map[string]any{"type": "term_out", "sid": s.id, "data": base64.StdEncoding.EncodeToString(buf[:n])})
		}
		if err != nil {
			break
		}
	}
	code := <-s.done
	m.mu.Lock()
	delete(m.sessions, s.id)
	m.mu.Unlock()
	m.log.Info("터미널 종료", "sid", s.id, "code", code)
	m.emit(map[string]any{"type": "term_exit", "sid": s.id, "code": code})
}

func (m *Manager) get(sid string) *session {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[sid]
	if s == nil || s.ptmx == nil {
		return nil
	}
	return s
}

func (m *Manager) Input(sid, b64 string) {
	s := m.get(sid)
	if s == nil {
		return
	}
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(data) > 64*1024 {
		return
	}
	m.mu.Lock()
	s.lastInput = time.Now()
	m.mu.Unlock()
	_, _ = s.ptmx.Write(data)
}

func (m *Manager) Resize(sid string, cols, rows int) {
	if s := m.get(sid); s != nil {
		c, r := clampSize(cols, rows)
		_ = pty.Setsize(s.ptmx, &pty.Winsize{Cols: c, Rows: r})
	}
}

// Close는 세션을 끝낸다 (셸과 그 자식 프로세스까지).
func (m *Manager) Close(sid string) {
	s := m.get(sid)
	if s == nil {
		return
	}
	m.mu.Lock()
	if s.closed {
		m.mu.Unlock()
		return
	}
	s.closed = true
	m.mu.Unlock()
	if s.unit != "" {
		// 유닛째 멈춰야 셸에서 띄운 프로세스까지 정리된다
		_ = exec.Command("systemctl", "stop", s.unit+".service").Run()
	}
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Signal(syscall.SIGHUP)
		go func(p *os.Process) {
			time.Sleep(3 * time.Second)
			_ = p.Kill()
		}(s.cmd.Process)
	}
}

// CloseAll은 Hub 연결이 끊기거나 Agent가 끝날 때 모든 세션을 닫는다.
func (m *Manager) CloseAll() {
	m.mu.Lock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	for _, id := range ids {
		m.Close(id)
	}
}

// ReapIdle은 입력이 오래 없는 세션을 닫는다 (주기적으로 호출).
func (m *Manager) ReapIdle() {
	now := time.Now()
	m.mu.Lock()
	var idle []string
	for id, s := range m.sessions {
		if s.ptmx != nil && now.Sub(s.lastInput) > IdleTimeout {
			idle = append(idle, id)
		}
	}
	m.mu.Unlock()
	for _, id := range idle {
		m.log.Info("입력 없는 터미널 종료", "sid", id)
		m.Close(id)
	}
}

// TTYOwner는 pts(예: "pts/3")가 Douve 터미널 세션(진행 중이거나 2분 안에 끝난)이면 세션 ID를 돌려준다.
func (m *Manager) TTYOwner(tty string) string {
	path := "/dev/" + strings.TrimPrefix(tty, "/dev/")
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if s.tty != nil && s.tty.Name() == path {
			return id
		}
	}
	for p, c := range m.recent {
		if time.Since(c.at) > 2*time.Minute {
			delete(m.recent, p)
		} else if p == path {
			return c.sid
		}
	}
	return ""
}

func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}
