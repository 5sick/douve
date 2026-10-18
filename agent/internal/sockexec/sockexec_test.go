package sockexec

import (
	"context"
	"io"
	"os/exec"
	"strings"
	"testing"
)

func TestOutput(t *testing.T) {
	out, err := Output(context.Background(), nil, "/bin/sh", "-c", "echo out; echo err >&2; cat")
	if err != nil || out != "out\nerr\n" {
		t.Fatalf("%q %v", out, err)
	}
	_, err = Output(context.Background(), nil, "/bin/sh", "-c", "exit 3")
	var ee *exec.ExitError
	if !strings.Contains(err.Error(), "3") || !asExit(err, &ee) || ee.ExitCode() != 3 {
		t.Fatalf("종료 코드: %v", err)
	}
}

func asExit(err error, ee **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	*ee = e
	return ok
}

func TestStreams(t *testing.T) {
	c, err := Command(context.Background(), true, "/bin/sh", "-c", "tr a-z A-Z; echo done >&2")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	w := c.StdinWriter()
	big := strings.Repeat("abc", 200000) // 소켓 버퍼보다 크게 (쓰기와 읽기를 함께)
	go func() { _, _ = io.WriteString(w, big); w.Close() }()
	got, _ := io.ReadAll(c.StdoutReader())
	errOut, _ := io.ReadAll(c.StderrReader())
	if err := c.Wait(); err != nil {
		t.Fatal(err)
	}
	if string(got) != strings.ToUpper(big) || string(errOut) != "done\n" {
		t.Fatalf("출력 %d바이트, 오류 %q", len(got), errOut)
	}
}
