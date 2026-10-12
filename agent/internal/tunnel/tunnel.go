// Package tunnel은 입구(edge)가 다른 서버의 서비스에 닿는 통로다. 그 서버로 직접 갈 길(WireGuard·Tailscale·
// 같은 사설망)이 없어도 동작한다: 서비스가 있는 서버의 Agent가 입구로 "나가는" WebSocket을 열어 두고,
// 입구는 그 위에 yamux 스트림을 열어 요청을 실어 보낸다. 집 서버처럼 공인 IP·포트포워딩이 없어도 된다.
//
// 인증: 입구가 nonce를 보내면 Agent가 Ed25519("douve-tunnel:v1:<nonce>:<node_id>") 서명으로 답한다
// (Hub가 입구에 노드 공개키를 알려 준다).
// 스트림: 입구가 "주소\n"을 보내면 Agent는 Hub가 허락한 주소(자기 서비스 업스트림)일 때만 연결해
// "OK\n" 뒤에 바이트를 그대로 잇는다. 아니면 "ERR 이유\n".
package tunnel

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

// Path는 입구가 터널 연결을 받는 경로다 (모든 도메인에서).
const Path = "/_douve/tunnel"

func AuthMessage(nonce string, nodeID int64) string {
	return "douve-tunnel:v1:" + nonce + ":" + strconv.FormatInt(nodeID, 10)
}

func yamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.LogOutput = io.Discard
	c.KeepAliveInterval = 20 * time.Second
	c.ConnectionWriteTimeout = 15 * time.Second
	return c
}

type hello struct {
	Nonce  string `json:"nonce,omitempty"`
	NodeID int64  `json:"node_id,omitempty"`
	Sig    string `json:"sig,omitempty"`
	OK     bool   `json:"ok,omitempty"`
	Error  string `json:"error,omitempty"`
}

// ---------- 입구 쪽 ----------

// KeyLookup은 노드 ID의 공개키를 돌려준다 (Hub가 보낸 라우팅 표에서).
type KeyLookup func(nodeID int64) (ed25519.PublicKey, bool)

type Server struct {
	Keys KeyLookup
	Log  *slog.Logger

	mu       sync.Mutex
	sessions map[int64]*yamux.Session
}

func NewServer(keys KeyLookup, log *slog.Logger) *Server {
	return &Server{Keys: keys, Log: log, sessions: map[int64]*yamux.Session{}}
}

// Connected는 그 노드의 터널이 살아 있는지 본다.
func (s *Server) Connected(nodeID int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[nodeID]
	return sess != nil && !sess.IsClosed()
}

// Dial은 노드의 터널로 addr에 연결한다.
func (s *Server) Dial(ctx context.Context, nodeID int64, addr string) (net.Conn, error) {
	s.mu.Lock()
	sess := s.sessions[nodeID]
	s.mu.Unlock()
	if sess == nil || sess.IsClosed() {
		return nil, fmt.Errorf("노드 %d의 터널이 연결되어 있지 않습니다", nodeID)
	}
	st, err := sess.OpenStream()
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = st.SetDeadline(dl)
	}
	if _, err := io.WriteString(st, addr+"\n"); err != nil {
		st.Close()
		return nil, err
	}
	br := bufio.NewReader(st)
	line, err := br.ReadString('\n')
	if err != nil {
		st.Close()
		return nil, err
	}
	if line != "OK\n" {
		st.Close()
		return nil, fmt.Errorf("터널: %s", strings.TrimSpace(strings.TrimPrefix(line, "ERR ")))
	}
	_ = st.SetDeadline(time.Time{})
	return &bufConn{Conn: st, r: br}, nil
}

// bufConn은 응답 줄을 읽느라 버퍼에 남은 바이트를 먼저 돌려준다.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func randomNonce() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true}) // 브라우저가 아님 (Origin 없음)
	if err != nil {
		return
	}
	defer c.CloseNow()
	c.SetReadLimit(4 << 20)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	nonce := randomNonce()
	b, _ := json.Marshal(hello{Nonce: nonce})
	if c.Write(ctx, websocket.MessageText, b) != nil {
		cancel()
		return
	}
	_, data, err := c.Read(ctx)
	cancel()
	var h hello
	if err != nil || json.Unmarshal(data, &h) != nil {
		return
	}
	sig, _ := base64.RawURLEncoding.DecodeString(h.Sig)
	pub, ok := s.Keys(h.NodeID)
	if !ok || !ed25519.Verify(pub, []byte(AuthMessage(nonce, h.NodeID)), sig) {
		s.Log.Warn("터널 인증 실패", "node", h.NodeID, "from", r.RemoteAddr)
		b, _ := json.Marshal(hello{Error: "인증 실패"})
		_ = c.Write(r.Context(), websocket.MessageText, b)
		c.Close(websocket.StatusPolicyViolation, "인증 실패")
		return
	}
	b, _ = json.Marshal(hello{OK: true})
	if c.Write(r.Context(), websocket.MessageText, b) != nil {
		return
	}
	nc := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	sess, err := yamux.Client(nc, yamuxConfig())
	if err != nil {
		return
	}
	s.mu.Lock()
	if old := s.sessions[h.NodeID]; old != nil {
		old.Close()
	}
	s.sessions[h.NodeID] = sess
	s.mu.Unlock()
	s.Log.Info("터널 연결", "node", h.NodeID, "from", r.RemoteAddr)
	<-sess.CloseChan()
	s.mu.Lock()
	if s.sessions[h.NodeID] == sess {
		delete(s.sessions, h.NodeID)
	}
	s.mu.Unlock()
	s.Log.Info("터널 끊김", "node", h.NodeID)
}

// ---------- 서비스가 있는 서버(Agent) 쪽 ----------

type Client struct {
	NodeID int64
	Key    ed25519.PrivateKey
	Log    *slog.Logger
	// DialFunc가 있으면 업스트림 연결에 쓴다 (시험용)
	DialFunc func(addr string) (net.Conn, error)

	mu      sync.Mutex
	url     string
	allowed map[string]bool
	restart chan struct{}
}

func NewClient(nodeID int64, key ed25519.PrivateKey, log *slog.Logger) *Client {
	return &Client{NodeID: nodeID, Key: key, Log: log, allowed: map[string]bool{}, restart: make(chan struct{}, 1)}
}

// Configure는 Hub가 보낸 터널 주소와 허용 목록을 적용한다. url이 비면 연결하지 않는다.
func (c *Client) Configure(url string, allowed []string) {
	m := map[string]bool{}
	for _, a := range allowed {
		m[a] = true
	}
	c.mu.Lock()
	changed := c.url != url
	c.url = url
	c.allowed = m
	c.mu.Unlock()
	if changed {
		c.Log.Info("터널 설정 변경", "url", url, "allow", len(allowed))
		select {
		case c.restart <- struct{}{}:
		default:
		}
	}
}

func (c *Client) isAllowed(addr string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.allowed[addr]
}

func (c *Client) currentURL() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.url
}

// Run은 ctx가 끝날 때까지 터널을 유지한다 (끊기면 재접속, 주소가 바뀌면 다시 연결).
func (c *Client) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		url := c.currentURL()
		if url == "" {
			select {
			case <-ctx.Done():
				return
			case <-c.restart:
				continue
			}
		}
		sctx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		start := time.Now()
		go func() { done <- c.session(sctx, url) }()
		var err error
		select {
		case err = <-done:
		case <-c.restart:
			cancel()
			<-done
			cancel()
			backoff = time.Second
			continue
		}
		cancel()
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(backoff/2)+1))
		wait := backoff + time.Duration(j.Int64())
		c.Log.Warn("터널 끊김, 재접속 대기", "err", err, "wait", wait.Round(time.Second))
		select {
		case <-ctx.Done():
			return
		case <-c.restart:
			backoff = time.Second
		case <-time.After(wait):
			backoff = min(backoff*2, time.Minute)
		}
	}
}

func (c *Client) session(ctx context.Context, url string) error {
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	ws, _, err := websocket.Dial(dctx, url, nil)
	cancel()
	if err != nil {
		return err
	}
	defer ws.CloseNow()
	ws.SetReadLimit(4 << 20)
	hctx, hcancel := context.WithTimeout(ctx, 10*time.Second)
	defer hcancel()
	_, data, err := ws.Read(hctx)
	if err != nil {
		return err
	}
	var h hello
	if json.Unmarshal(data, &h) != nil || h.Nonce == "" {
		return errors.New("터널 인사 형식 오류")
	}
	sig := ed25519.Sign(c.Key, []byte(AuthMessage(h.Nonce, c.NodeID)))
	b, _ := json.Marshal(hello{NodeID: c.NodeID, Sig: base64.RawURLEncoding.EncodeToString(sig)})
	if err := ws.Write(hctx, websocket.MessageText, b); err != nil {
		return err
	}
	_, data, err = ws.Read(hctx)
	if err != nil {
		return err
	}
	if json.Unmarshal(data, &h) != nil || !h.OK {
		return fmt.Errorf("터널 인증 거부: %s", h.Error)
	}
	nc := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	sess, err := yamux.Server(nc, yamuxConfig())
	if err != nil {
		return err
	}
	defer sess.Close()
	go func() { <-ctx.Done(); sess.Close(); ws.CloseNow() }() // 설정이 바뀌거나 끝나면 즉시 닫음
	c.Log.Info("터널 연결됨", "url", url)
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return err
		}
		go c.handle(st)
	}
}

func (c *Client) handle(st net.Conn) {
	defer st.Close()
	_ = st.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(st)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	addr := strings.TrimSpace(line)
	if !c.isAllowed(addr) {
		c.Log.Warn("터널: 허용되지 않은 주소 요청", "addr", addr)
		_, _ = io.WriteString(st, "ERR 허용되지 않은 주소\n")
		return
	}
	var up net.Conn
	if c.DialFunc != nil {
		up, err = c.DialFunc(addr)
	} else {
		up, err = net.DialTimeout("tcp", addr, 5*time.Second)
	}
	if err != nil {
		_, _ = io.WriteString(st, "ERR "+err.Error()+"\n")
		return
	}
	defer up.Close()
	if _, err := io.WriteString(st, "OK\n"); err != nil {
		return
	}
	_ = st.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, br); closeWrite(up); done <- struct{}{} }()
	go func() { _, _ = io.Copy(st, up); done <- struct{}{} }()
	<-done
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}
