// Package sockexec은 표준 입출력을 파이프 대신 유닉스 소켓 쌍으로 연결해 명령을 실행한다.
//
// `systemd-run --pipe`는 호출자의 표준 입출력 fd를 PID1에 넘긴다. SELinux가 켜진 서버(Rocky 등)에서는
// Agent(unconfined_service_t)가 만든 파이프를 init이 쓰지 못해 "Connection reset by peer"로 실패하지만,
// 소켓 쌍은 허용된다 (node3에서 확인). 그래서 systemd-run으로 샌드박스 밖 작업을 할 때는 이것을 쓴다.
package sockexec

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

// Cmd는 소켓 쌍으로 입출력을 연결한 명령이다.
type Cmd struct {
	*exec.Cmd
	stdin, stdout, stderr *net.UnixConn // 부모 쪽
	child                 []*os.File
}

func pair() (parent *net.UnixConn, child *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	pf := os.NewFile(uintptr(fds[0]), "sockexec-parent")
	defer pf.Close() // FileConn이 복제한다
	c, err := net.FileConn(pf)
	if err != nil {
		syscall.Close(fds[1])
		return nil, nil, err
	}
	return c.(*net.UnixConn), os.NewFile(uintptr(fds[1]), "sockexec-child"), nil
}

// Command는 명령을 만든다. separateStderr가 false면 표준 오류도 표준 출력 소켓으로 온다.
func Command(ctx context.Context, separateStderr bool, name string, args ...string) (*Cmd, error) {
	c := &Cmd{Cmd: exec.CommandContext(ctx, name, args...)}
	var err error
	var in, out *os.File
	if c.stdin, in, err = pair(); err != nil {
		return nil, err
	}
	if c.stdout, out, err = pair(); err != nil {
		c.closeAll()
		in.Close()
		return nil, err
	}
	c.child = []*os.File{in, out}
	c.Stdin, c.Stdout, c.Stderr = in, out, out
	if separateStderr {
		var errf *os.File
		if c.stderr, errf, err = pair(); err != nil {
			c.closeAll()
			return nil, err
		}
		c.child = append(c.child, errf)
		c.Stderr = errf
	}
	return c, nil
}

func (c *Cmd) closeAll() {
	for _, f := range c.child {
		f.Close()
	}
	c.child = nil
	for _, s := range []*net.UnixConn{c.stdin, c.stdout, c.stderr} {
		if s != nil {
			s.Close()
		}
	}
}

// Start는 실행하고 자식 쪽 소켓을 닫는다 (그래야 자식이 끝나면 부모가 EOF를 본다).
func (c *Cmd) Start() error {
	err := c.Cmd.Start()
	for _, f := range c.child {
		f.Close()
	}
	c.child = nil
	if err != nil {
		c.closeAll()
	}
	return err
}

type halfCloser struct{ *net.UnixConn }

func (h halfCloser) Close() error { return h.CloseWrite() }

// StdinWriter는 표준 입력이다. Close하면 자식이 EOF를 본다.
func (c *Cmd) StdinWriter() io.WriteCloser { return halfCloser{c.stdin} }

// StdoutReader는 표준 출력 (separateStderr가 false면 표준 오류 포함).
func (c *Cmd) StdoutReader() io.Reader { return c.stdout }

// StderrReader는 표준 오류 (separateStderr일 때만).
func (c *Cmd) StderrReader() io.Reader { return c.stderr }

// Wait는 끝나기를 기다리고 부모 쪽 소켓을 닫는다.
func (c *Cmd) Wait() error {
	err := c.Cmd.Wait()
	c.closeAll()
	return err
}

// Output은 표준 입력 없이 실행하고 표준 출력·오류를 합쳐 돌려준다 (exec.Cmd.CombinedOutput처럼).
func Output(ctx context.Context, env []string, name string, args ...string) (string, error) {
	c, err := Command(ctx, false, name, args...)
	if err != nil {
		return "", err
	}
	if env != nil {
		c.Env = env
	}
	if err := c.Start(); err != nil {
		return "", err
	}
	_ = c.stdin.CloseWrite()
	var b strings.Builder
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&b, c.stdout)
	}()
	wg.Wait()
	err = c.Wait()
	return b.String(), err
}
