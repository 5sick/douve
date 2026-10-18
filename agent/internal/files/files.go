// Package files는 브라우저 ↔ 서버 파일 올리기·내려받기다 (Hub를 거쳐 Agent WebSocket으로).
//
// 터미널처럼 그 계정의 권한으로만 읽고 쓴다: root면 `systemd-run --uid=<계정> --pipe`로 PID1이 만든 새
// 유닛에서 cat을 띄운다 (Agent 샌드박스와 무관, 권한 검사는 커널이). root가 아니면(개발·시험) 자기 계정만.
// 올리기는 "<경로>.douve-<sid>"에 받은 뒤 크기·SHA-256이 서명한 값과 같을 때만 mv로 바꿔 놓는다.
// 패스키 서명 확인(어떤 계정·경로·내용인지)은 호출자(Agent main, termauth)가 먼저 한다.
package files

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"os/user"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/5sick/douve/agent/internal/sockexec"
)

const (
	MaxSize   = 100 << 20 // 한 번에 100MB
	chunk     = 192 << 10 // 내려받기 조각 (base64 후 256KB, WebSocket 1MB 제한 안)
	ackEvery  = 1 << 20   // 올리기: 1MB마다 받았다고 알림 (브라우저가 그만큼씩 보낸다)
	idleLimit = 2 * time.Minute
)

// Sender는 Hub로 메시지를 보낸다.
type Sender func(v any) error

// ValidPath는 경로 형식을 본다: 1~4096바이트, 제어 문자 없음, 디렉터리(/로 끝남) 아님, ~로 시작하지 않음
// (셸이 펼치지 않으므로 화면이 "~/a"를 "a"로 바꿔 보낸다). 상대 경로는 홈 기준.
func ValidPath(p string) error {
	if p == "" || len(p) > 4096 || strings.HasPrefix(p, "~") || strings.HasSuffix(p, "/") || strings.HasSuffix(p, "/.") || strings.HasSuffix(p, "/..") || p == "." || p == ".." {
		return errors.New("잘못된 경로")
	}
	for _, r := range p {
		if unicode.IsControl(r) {
			return errors.New("경로에 제어 문자가 있습니다")
		}
	}
	return nil
}

// PutAction·GetAction은 패스키로 서명하는 작업 문자열이다 (경로가 마지막이라 ':'가 있어도 모호하지 않다).
func PutAction(user string, size int64, sha string, path string) string {
	return fmt.Sprintf("file-put:%s:%d:%s:%s", user, size, sha, path)
}
func GetAction(user, path string) string { return "file-get:" + user + ":" + path }

type transfer struct {
	sid      string
	user     string
	path     string
	tmp      string
	size     int64
	sha      string
	cmd      *sockexec.Cmd
	stdin    io.WriteCloser
	hash     hash.Hash
	got      int64
	acked    int64
	lastSeen time.Time
	done     chan struct{}
}

// Manager는 진행 중인 전송을 가진다.
type Manager struct {
	log     *slog.Logger
	send    func() Sender
	allowed func(name string) bool
	euid    int

	mu     sync.Mutex
	active map[string]*transfer
}

func NewManager(log *slog.Logger, send func() Sender, allowed func(string) bool) *Manager {
	return &Manager{log: log, send: send, allowed: allowed, euid: os.Geteuid(), active: map[string]*transfer{}}
}

func (m *Manager) emit(v any) {
	if s := m.send(); s != nil {
		_ = s(v)
	}
}

func (m *Manager) fail(sid string, err error) {
	m.log.Warn("파일 전송 실패", "sid", sid, "err", err)
	m.emit(map[string]any{"type": "file_error", "sid": sid, "error": err.Error()})
}

// command는 그 계정으로 sh 스크립트를 실행한다. 입출력은 소켓 쌍이다 (파이프는 SELinux에서 systemd-run
// --pipe로 PID1에 넘길 수 없다, sockexec 참고). separateStderr면 표준 오류를 따로 받는다.
func (m *Manager) command(ctx context.Context, separateStderr bool, account, script string, args ...string) (*sockexec.Cmd, error) {
	if m.euid != 0 {
		cur, err := user.Current()
		if err != nil || cur.Username != account {
			return nil, fmt.Errorf("root가 아니면 자기 계정만: %s", account)
		}
		cmd, err := sockexec.Command(ctx, separateStderr, "/bin/sh", append([]string{"-c", script, "sh"}, args...)...)
		if err != nil {
			return nil, err
		}
		cmd.Dir = cur.HomeDir
		return cmd, nil
	}
	full := append([]string{"--wait", "--pipe", "--quiet", "--collect", "--uid=" + account,
		"-p", "WorkingDirectory=~", "--", "/bin/sh", "-c", script, "sh"}, args...)
	return sockexec.Command(ctx, separateStderr, "systemd-run", full...)
}

// run은 짧은 명령(mv·rm)을 실행하고 출력을 돌려준다.
func (m *Manager) run(account, script string, args ...string) (string, error) {
	cmd, err := m.command(context.Background(), false, account, script, args...)
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	cmd.StdinWriter().Close()
	out, _ := io.ReadAll(cmd.StdoutReader())
	return strings.TrimSpace(string(out)), cmd.Wait()
}

func (m *Manager) check(sid, account, path string) error {
	if len(sid) < 8 || len(sid) > 64 {
		return errors.New("잘못된 전송 ID")
	}
	if !m.allowed(account) {
		return fmt.Errorf("허용되지 않은 계정: %s", account)
	}
	return ValidPath(path)
}

// Put은 올리기를 시작한다. 이어서 Chunk·End가 온다.
func (m *Manager) Put(sid, account, path string, size int64, sha string) {
	if err := m.check(sid, account, path); err != nil {
		m.fail(sid, err)
		return
	}
	if size < 0 || size > MaxSize {
		m.fail(sid, fmt.Errorf("파일은 %dMB까지입니다", MaxSize>>20))
		return
	}
	if b, err := hex.DecodeString(sha); err != nil || len(b) != 32 {
		m.fail(sid, errors.New("잘못된 SHA-256"))
		return
	}
	tmp := path + ".douve-" + sid
	cmd, err := m.command(context.Background(), false, account, `umask 077; exec cat > "$1"`, tmp)
	if err != nil {
		m.fail(sid, err)
		return
	}
	if err := cmd.Start(); err != nil {
		m.fail(sid, err)
		return
	}
	stdin := cmd.StdinWriter()
	var errOut strings.Builder
	outDone := make(chan struct{})
	go func() { _, _ = io.Copy(&errOut, cmd.StdoutReader()); close(outDone) }()
	t := &transfer{sid: sid, user: account, path: path, tmp: tmp, size: size, sha: sha, cmd: cmd, stdin: stdin,
		hash: sha256.New(), lastSeen: time.Now(), done: make(chan struct{})}
	m.mu.Lock()
	if _, dup := m.active[sid]; dup || len(m.active) >= 8 {
		m.mu.Unlock()
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		m.fail(sid, errors.New("동시 전송이 너무 많습니다"))
		return
	}
	m.active[sid] = t
	m.mu.Unlock()
	go func() {
		<-outDone
		err := cmd.Wait()
		if err != nil && errOut.Len() > 0 {
			m.log.Debug("파일 쓰기", "sid", sid, "out", strings.TrimSpace(errOut.String()))
		}
		close(t.done)
	}()
	m.log.Info("파일 올리기 시작", "sid", sid, "user", account, "path", path, "size", size)
	m.emit(map[string]any{"type": "file_ready", "sid": sid})
}

func (m *Manager) get(sid string) *transfer {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active[sid]
}

func (m *Manager) drop(sid string) {
	m.mu.Lock()
	delete(m.active, sid)
	m.mu.Unlock()
}

// Chunk는 올리는 내용 한 조각 (base64).
func (m *Manager) Chunk(sid, b64 string) {
	t := m.get(sid)
	if t == nil {
		return
	}
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || t.got+int64(len(data)) > t.size {
		m.abort(t, errors.New("받은 내용이 서명한 크기와 다릅니다"))
		return
	}
	if _, err := t.stdin.Write(data); err != nil {
		m.abort(t, fmt.Errorf("쓰기 실패 (권한·디스크를 확인하세요)"))
		return
	}
	_, _ = t.hash.Write(data)
	t.got += int64(len(data))
	t.lastSeen = time.Now()
	if t.got-t.acked >= ackEvery || t.got == t.size {
		t.acked = t.got
		m.emit(map[string]any{"type": "file_ack", "sid": sid, "bytes": t.got})
	}
}

// End는 올리기를 끝낸다: 크기·SHA-256이 맞으면 제자리로, 아니면 지운다.
func (m *Manager) End(sid string) {
	t := m.get(sid)
	if t == nil {
		return
	}
	_ = t.stdin.Close()
	select {
	case <-t.done:
	case <-time.After(30 * time.Second):
		m.abort(t, errors.New("쓰기가 끝나지 않습니다"))
		return
	}
	sum := hex.EncodeToString(t.hash.Sum(nil))
	if t.cmd.ProcessState == nil || !t.cmd.ProcessState.Success() {
		m.abort(t, errors.New("파일을 쓸 수 없습니다 (경로·권한을 확인하세요)"))
		return
	}
	if t.got != t.size || sum != t.sha {
		m.abort(t, errors.New("받은 내용이 서명한 내용과 다릅니다"))
		return
	}
	if out, err := m.run(t.user, `exec mv -f -- "$1" "$2"`, t.tmp, t.path); err != nil {
		if out == "" {
			out = err.Error()
		}
		err = fmt.Errorf("옮기기 실패: %s", out)
		m.abort(t, err)
		return
	}
	m.drop(sid)
	m.log.Info("파일 올리기 완료", "sid", sid, "user", t.user, "path", t.path, "size", t.size)
	m.emit(map[string]any{"type": "file_done", "sid": sid, "size": t.size, "sha256": sum})
}

// abort는 올리기를 멈추고 임시 파일을 지운다.
func (m *Manager) abort(t *transfer, why error) {
	m.drop(t.sid)
	_ = t.stdin.Close()
	if t.cmd.Process != nil {
		_ = t.cmd.Process.Kill()
	}
	go func() {
		<-t.done
		_, _ = m.run(t.user, `exec rm -f -- "$1"`, t.tmp)
	}()
	m.fail(t.sid, why)
}

// Cancel은 브라우저가 끊었을 때.
func (m *Manager) Cancel(sid string) {
	if t := m.get(sid); t != nil {
		m.abort(t, errors.New("취소됨"))
	}
}

// ReapIdle은 오래 멈춘 올리기를 정리한다 (주기적으로 호출).
func (m *Manager) ReapIdle() {
	m.mu.Lock()
	var idle []*transfer
	for _, t := range m.active {
		if time.Since(t.lastSeen) > idleLimit {
			idle = append(idle, t)
		}
	}
	m.mu.Unlock()
	for _, t := range idle {
		m.abort(t, errors.New("시간 초과"))
	}
}

// Get은 내려받기: 그 계정 권한으로 읽어 조각으로 보낸다. 끝에 크기·SHA-256.
func (m *Manager) Get(sid, account, path string) {
	if err := m.check(sid, account, path); err != nil {
		m.fail(sid, err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	cmd, err := m.command(ctx, true, account, `[ -f "$1" ] || { echo "파일이 아닙니다" >&2; exit 2; }; exec cat -- "$1"`, path)
	if err != nil {
		m.fail(sid, err)
		return
	}
	if err := cmd.Start(); err != nil {
		m.fail(sid, err)
		return
	}
	cmd.StdinWriter().Close()
	stdout := cmd.StdoutReader()
	var errOut strings.Builder
	errDone := make(chan struct{})
	go func() { _, _ = io.Copy(&errOut, cmd.StderrReader()); close(errDone) }()
	m.log.Info("파일 내려받기", "sid", sid, "user", account, "path", path)
	h := sha256.New()
	buf := make([]byte, chunk)
	var total int64
	for {
		n, rerr := io.ReadFull(stdout, buf)
		if n > 0 {
			total += int64(n)
			if total > MaxSize {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				m.fail(sid, fmt.Errorf("파일은 %dMB까지입니다", MaxSize>>20))
				return
			}
			h.Write(buf[:n])
			m.emit(map[string]any{"type": "file_data", "sid": sid, "data": base64.StdEncoding.EncodeToString(buf[:n])})
		}
		if rerr != nil {
			break
		}
	}
	<-errDone
	if err := cmd.Wait(); err != nil {
		msg := strings.TrimSpace(errOut.String())
		if msg == "" {
			msg = "읽을 수 없습니다 (경로·권한을 확인하세요)"
		} else if i := strings.LastIndexByte(msg, '\n'); i >= 0 {
			msg = msg[i+1:]
		}
		m.fail(sid, errors.New(msg))
		return
	}
	m.emit(map[string]any{"type": "file_done", "sid": sid, "size": total, "sha256": hex.EncodeToString(h.Sum(nil))})
}
