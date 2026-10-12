package tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// echo는 받은 바이트를 그대로 돌려주는 TCP 서버다.
func echo(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func waitConnected(t *testing.T, s *Server, id int64, want bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if s.Connected(id) == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("터널 상태가 %v가 아님", want)
}

func TestTunnelRoundTripAndAllowList(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := NewServer(func(id int64) (ed25519.PublicKey, bool) { return pub, id == 7 }, quiet())
	hs := httptest.NewServer(srv)
	defer hs.Close()
	allowed := echo(t)
	other := echo(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cl := NewClient(7, priv, quiet())
	cl.Configure(strings.Replace(hs.URL, "http", "ws", 1)+Path, []string{allowed})
	go cl.Run(ctx)
	waitConnected(t, srv, 7, true)

	conn, err := srv.Dial(ctx, 7, allowed)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("douve-tunnel "), 100000) // 1.2MB
	go conn.Write(payload)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("왕복 데이터 불일치: %v", err)
	}
	conn.Close()

	if _, err := srv.Dial(ctx, 7, other); err == nil || !strings.Contains(err.Error(), "허용되지 않은") {
		t.Fatalf("허용 목록 밖 주소에 연결됨: %v", err)
	}
	if _, err := srv.Dial(ctx, 8, allowed); err == nil {
		t.Fatal("연결 안 된 노드로 dial 성공")
	}
	// 허용 목록 갱신 (주소 그대로면 재연결 없이)
	cl.Configure(strings.Replace(hs.URL, "http", "ws", 1)+Path, []string{other})
	if c2, err := srv.Dial(ctx, 7, other); err != nil {
		t.Fatalf("갱신된 허용 목록: %v", err)
	} else {
		c2.Close()
	}
	// 주소를 비우면 연결을 끊는다
	cl.Configure("", nil)
	waitConnected(t, srv, 7, false)
}

func TestTunnelRejectsWrongKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	srv := NewServer(func(id int64) (ed25519.PublicKey, bool) { return pub, true }, quiet())
	hs := httptest.NewServer(srv)
	defer hs.Close()
	cl := NewClient(7, otherPriv, quiet())
	err := cl.session(context.Background(), strings.Replace(hs.URL, "http", "ws", 1)+Path)
	if err == nil || !strings.Contains(err.Error(), "인증") {
		t.Fatalf("다른 키로 인증 통과: %v", err)
	}
	if srv.Connected(7) {
		t.Fatal("거부된 터널이 등록됨")
	}
}
