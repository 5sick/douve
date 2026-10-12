package edge

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/5sick/douve/agent/internal/tunnel"
)

const goodToken = "good-session-token-0123456789abcdef"

// fakeHub는 /auth/verify만 흉내 낸다.
func fakeHub(t *testing.T, calls *atomic.Int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		c, err := r.Cookie(sessionCookie)
		if err == nil && c.Value == goodToken {
			w.Header().Set("X-Douve-User", "me@example.com")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
}

// upstream은 받은 요청 정보를 JSON으로 돌려주고, /ws는 에코 WebSocket이다.
func upstream(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			c, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer c.CloseNow()
			typ, data, err := c.Read(r.Context())
			if err == nil {
				c.Write(r.Context(), typ, append([]byte("echo:"), data...))
			}
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"host":   r.Host,
			"path":   r.URL.RequestURI(),
			"cookie": r.Header.Get("Cookie"),
			"user":   r.Header.Get("X-Douve-User"),
			"xff":    r.Header.Get("X-Forwarded-For"),
			"proto":  r.Header.Get("X-Forwarded-Proto"),
			"realip": r.Header.Get("X-Real-IP"),
		})
	}))
}

func setup(t *testing.T) (*Handler, *httptest.Server, *atomic.Int32, *httptest.Server) {
	var calls atomic.Int32
	hub := fakeHub(t, &calls)
	up := upstream(t)
	t.Cleanup(hub.Close)
	t.Cleanup(up.Close)
	h := NewHandler(slog.New(slog.NewTextHandler(io.Discard, nil)))
	tbl := &Table{
		VerifyURL: hub.URL + "/auth/verify",
		LoginURL:  "https://douve.example.com/login",
		Routes: []Route{
			{Host: "app.example.com", Upstream: strings.TrimPrefix(up.URL, "http://"), Auth: "douve",
				PublicPaths: []string{"/api/push/", "/status"}},
			{Host: "open.example.com", Upstream: strings.TrimPrefix(up.URL, "http://"), Auth: "public"},
			{Host: "douve.example.com", Upstream: strings.TrimPrefix(up.URL, "http://"), Auth: "hub"},
		},
	}
	if err := tbl.Validate(); err != nil {
		t.Fatal(err)
	}
	h.SetTable(tbl)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return h, srv, &calls, up
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func get(t *testing.T, srv *httptest.Server, host, path string, hdr map[string]string) (*http.Response, map[string]string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	req.Host = host
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]string
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &body)
	return resp, body
}

func TestProtectedRedirectsToLoginWithEncodedReturnURL(t *testing.T) {
	_, srv, _, _ := setup(t)
	resp, _ := get(t, srv, "app.example.com", "/page?a=1&b=2", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Host != "douve.example.com" || loc.Path != "/login" {
		t.Fatalf("location %s", loc)
	}
	// nginx 방식은 & 뒤가 잘렸다. 여기서는 전체 주소가 보존되어야 한다.
	if rd := loc.Query().Get("rd"); rd != "http://app.example.com/page?a=1&b=2" {
		t.Fatalf("rd %q", rd)
	}
	// GET이 아닌 요청은 401
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/x", nil)
	req.Host = "app.example.com"
	r2, _ := noRedirect.Do(req)
	if r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST status %d", r2.StatusCode)
	}
}

func TestProtectedPassesWithSessionAndStripsCookie(t *testing.T) {
	_, srv, calls, _ := setup(t)
	hdr := map[string]string{
		"Cookie":       sessionCookie + "=" + goodToken + "; app_pref=dark",
		"X-Douve-User": "attacker@evil.com", // 위조 헤더
	}
	resp, body := get(t, srv, "app.example.com", "/page", hdr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if body["user"] != "me@example.com" {
		t.Fatalf("X-Douve-User %q (위조 헤더가 통과?)", body["user"])
	}
	if strings.Contains(body["cookie"], sessionCookie) || !strings.Contains(body["cookie"], "app_pref=dark") {
		t.Fatalf("업스트림 쿠키 %q", body["cookie"])
	}
	if body["host"] != "app.example.com" || body["realip"] != "127.0.0.1" || body["proto"] != "http" {
		t.Fatalf("전달 헤더 %+v", body)
	}
	// 두 번째 요청은 캐시 (Hub 호출 1회)
	get(t, srv, "app.example.com", "/page2", hdr)
	if calls.Load() != 1 {
		t.Fatalf("Hub 호출 %d회 (캐시 안 됨)", calls.Load())
	}
}

func TestBadSessionRedirects(t *testing.T) {
	_, srv, _, _ := setup(t)
	resp, _ := get(t, srv, "app.example.com", "/", map[string]string{"Cookie": sessionCookie + "=wrong"})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestPublicPathsAndPublicRoute(t *testing.T) {
	_, srv, _, _ := setup(t)
	for _, p := range []string{"/api/push/abc", "/status", "/status/x"} {
		resp, body := get(t, srv, "app.example.com", p, map[string]string{"Cookie": sessionCookie + "=" + goodToken})
		if resp.StatusCode != http.StatusOK || body["user"] != "" || strings.Contains(body["cookie"], sessionCookie) {
			t.Fatalf("%s: %d %+v", p, resp.StatusCode, body)
		}
	}
	for _, p := range []string{"/statusx", "/api/push", "/API/push/x"} {
		resp, _ := get(t, srv, "app.example.com", p, nil)
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("%s는 보호되어야 함: %d", p, resp.StatusCode)
		}
	}
	resp, body := get(t, srv, "open.example.com", "/", map[string]string{"Cookie": sessionCookie + "=" + goodToken, "X-Douve-User": "x"})
	if resp.StatusCode != http.StatusOK || body["user"] != "" || body["cookie"] != "" {
		t.Fatalf("공개 라우트 %d %+v", resp.StatusCode, body)
	}
}

func TestHubRouteKeepsCookie(t *testing.T) {
	_, srv, _, _ := setup(t)
	_, body := get(t, srv, "douve.example.com", "/login", map[string]string{"Cookie": sessionCookie + "=abc"})
	if !strings.Contains(body["cookie"], sessionCookie+"=abc") {
		t.Fatalf("Hub로 쿠키가 전달되어야 함: %+v", body)
	}
}

// 입구를 거친 요청에는 Tailscale 신원 헤더가 남지 않아야 한다 (Hub 사칭 방지)
func TestStripsTailscaleIdentityHeaders(t *testing.T) {
	seen := make(chan http.Header, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r.Header.Clone() }))
	defer up.Close()
	h := NewHandler(slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.SetTable(&Table{VerifyURL: "http://x/v", LoginURL: "https://x/l",
		Routes: []Route{{Host: "douve.example.com", Upstream: strings.TrimPrefix(up.URL, "http://"), Auth: "hub"}}})
	srv := httptest.NewServer(h)
	defer srv.Close()
	get(t, srv, "douve.example.com", "/", map[string]string{"Tailscale-User-Login": "admin@example.com", "Tailscale-User-Name": "x"})
	hdr := <-seen
	if hdr.Get("Tailscale-User-Login") != "" || hdr.Get("Tailscale-User-Name") != "" {
		t.Fatalf("Tailscale 헤더가 Hub로 넘어감: %v", hdr)
	}
}

func TestUnknownHostAndHubDown(t *testing.T) {
	h, srv, _, _ := setup(t)
	resp, _ := get(t, srv, "evil.example.com", "/", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown host %d", resp.StatusCode)
	}
	t2 := *h.Table()
	t2.VerifyURL = "http://127.0.0.1:1/auth/verify"
	h.SetTable(&t2)
	resp, _ = get(t, srv, "app.example.com", "/", map[string]string{"Cookie": sessionCookie + "=" + goodToken + "x"})
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("Hub 장애 시 fail-closed 502여야 함: %d", resp.StatusCode)
	}
	// 공개 라우트는 Hub 장애와 무관
	resp, _ = get(t, srv, "open.example.com", "/", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("공개 라우트 %d", resp.StatusCode)
	}
}

func TestUpstreamDown502(t *testing.T) {
	h, srv, _, _ := setup(t)
	t2 := *h.Table()
	t2.Routes = append([]Route{}, t2.Routes...)
	t2.Routes[1].Upstream = "127.0.0.1:1"
	h.SetTable(&t2)
	resp, _ := get(t, srv, "open.example.com", "/", nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestWebSocketThroughProxy(t *testing.T) {
	_, srv, _, _ := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hdr := http.Header{}
	hdr.Set("Cookie", sessionCookie+"="+goodToken)
	c, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws", &websocket.DialOptions{
		HTTPHeader: hdr, Host: "app.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	c.Write(ctx, websocket.MessageText, []byte("hi"))
	_, data, err := c.Read(ctx)
	if err != nil || string(data) != "echo:hi" {
		t.Fatalf("%q %v", data, err)
	}
	// 로그인 없으면 WebSocket도 거부
	_, resp, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws", &websocket.DialOptions{Host: "app.example.com", HTTPClient: noRedirect})
	if err == nil || resp == nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("로그인 없는 WebSocket이 통과함")
	}
}

func TestValidateRejectsBadTables(t *testing.T) {
	ok := Table{VerifyURL: "http://h/auth/verify", LoginURL: "https://h/login"}
	bad := []Route{
		{Host: "a.com", Upstream: "x:1", Auth: "nope"},
		{Host: "a.com/x", Upstream: "x:1", Auth: "douve"},
		{Host: "a.com", Upstream: "http://x:1", Auth: "douve"},
		{Host: "a.com", Upstream: "x:1", Auth: "douve", PublicPaths: []string{"/"}},
		{Host: "a.com", Upstream: "x:1", Auth: "douve", PublicPaths: []string{"api"}},
	}
	for _, r := range bad {
		tb := ok
		tb.Routes = []Route{r}
		if tb.Validate() == nil {
			t.Errorf("통과하면 안 됨: %+v", r)
		}
	}
	dup := ok
	dup.Routes = []Route{{Host: "a.com", Upstream: "x:1", Auth: "douve"}, {Host: "A.com.", Upstream: "y:1", Auth: "public"}}
	if dup.Validate() == nil {
		t.Error("중복 호스트")
	}
	nourl := Table{LoginURL: "https://h/login"}
	if nourl.Validate() == nil {
		t.Error("verify_url 없음")
	}
}

func TestTablePersistence(t *testing.T) {
	p := filepath.Join(t.TempDir(), "routes.json")
	tb := &Table{VerifyURL: "http://h/v", LoginURL: "https://h/l", Routes: []Route{{Host: "a.com", Upstream: "x:1", Auth: "public"}}}
	if err := SaveTable(p, tb); err != nil {
		t.Fatal(err)
	}
	got, err := LoadTable(p)
	if err != nil || len(got.Routes) != 1 || got.Routes[0].Host != "a.com" {
		t.Fatalf("%+v %v", got, err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("권한 %v", st.Mode().Perm())
	}
}

// 자체 서명 인증서를 대체 인증서로 쓰고 SNI로 고르는지
func TestFallbackCertSelection(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSigned(t, dir, []string{"a.example.com", "*.wild.example.com"})
	c := &certSource{log: slog.New(slog.NewTextHandler(io.Discard, nil)), files: []CertFiles{{certPath, keyPath}}}
	c.loadFallback()
	for _, name := range []string{"a.example.com", "x.wild.example.com"} {
		if cert, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: name}); err != nil || cert == nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "b.example.com"}); err == nil {
		t.Error("덮지 않는 도메인에 인증서를 줌")
	}
}

func writeSelfSigned(t *testing.T, dir string, names []string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	cp, kp := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)
	return cp, kp
}

func TestHSTSOnTLSOnlyWithoutDuplicates(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/own" {
			w.Header().Set("Strict-Transport-Security", "max-age=1")
		}
	}))
	defer up.Close()
	h := NewHandler(slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.SetTable(&Table{VerifyURL: "http://x/v", LoginURL: "https://x/l",
		Routes: []Route{{Host: "open.example.com", Upstream: strings.TrimPrefix(up.URL, "http://"), Auth: "public"}}})
	tlsSrv := httptest.NewTLSServer(h)
	defer tlsSrv.Close()
	plain := httptest.NewServer(h)
	defer plain.Close()
	do := func(c *http.Client, base, path string) []string {
		req, _ := http.NewRequest(http.MethodGet, base+path, nil)
		req.Host = "open.example.com"
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.Header.Values("Strict-Transport-Security")
	}
	if v := do(tlsSrv.Client(), tlsSrv.URL, "/"); len(v) != 1 || v[0] != "max-age=15552000" {
		t.Fatalf("TLS: %v", v)
	}
	if v := do(tlsSrv.Client(), tlsSrv.URL, "/own"); len(v) != 1 || v[0] != "max-age=1" {
		t.Fatalf("업스트림 값 유지·중복 없음: %v", v)
	}
	if v := do(http.DefaultClient, plain.URL, "/"); len(v) != 0 {
		t.Fatalf("평문에는 HSTS 없음: %v", v)
	}
}

func TestRouteOptions(t *testing.T) {
	echo := func(tag string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/slow") {
				time.Sleep(2 * time.Second)
			}
			json.NewEncoder(w).Encode(map[string]string{"tag": tag, "path": r.URL.RequestURI(), "host": r.Host,
				"prefix": r.Header.Get("X-Forwarded-Prefix")})
		}))
	}
	web, api := echo("web"), echo("api")
	defer web.Close()
	defer api.Close()
	tlsUp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"tag": "tls", "host": r.Host})
	}))
	defer tlsUp.Close()
	host := func(u string) string { return strings.TrimPrefix(strings.TrimPrefix(u, "http://"), "https://") }
	h := NewHandler(slog.New(slog.NewTextHandler(io.Discard, nil)))
	tbl := &Table{VerifyURL: "http://x/v", LoginURL: "https://x/l", Routes: []Route{
		{Host: "app.example.com", Upstream: host(web.URL), Auth: "public"},
		{Host: "app.example.com", PathPrefix: "/api", StripPrefix: true, Upstream: host(api.URL), Auth: "public"},
		{Host: "app.example.com", PathPrefix: "/api/v2", Upstream: host(web.URL), Auth: "public", Timeout: 1},
		{Host: "example.com", Kind: "redirect", RedirectTo: "https://douve.example.com/"},
		{Host: "pve.example.com", Upstream: host(tlsUp.URL), UpstreamTLS: 2, HostHeader: "pve.internal", Auth: "public"},
		{Host: "strict.example.com", Upstream: host(tlsUp.URL), UpstreamTLS: 1, Auth: "public"},
	}}
	if err := tbl.Validate(); err != nil {
		t.Fatal(err)
	}
	h.SetTable(tbl)
	srv := httptest.NewServer(h)
	defer srv.Close()

	_, b := get(t, srv, "app.example.com", "/page", nil)
	if b["tag"] != "web" {
		t.Errorf("기본 경로 %+v", b)
	}
	_, b = get(t, srv, "app.example.com", "/api/users?x=1", nil)
	if b["tag"] != "api" || b["path"] != "/users?x=1" || b["prefix"] != "/api" {
		t.Errorf("접두사 제거 %+v", b)
	}
	_, b = get(t, srv, "app.example.com", "/apix", nil)
	if b["tag"] != "web" {
		t.Errorf("/apix는 /api가 아님 %+v", b)
	}
	_, b = get(t, srv, "app.example.com", "/api/v2/z", nil)
	if b["tag"] != "web" || b["path"] != "/api/v2/z" {
		t.Errorf("가장 긴 접두사 %+v", b)
	}
	resp, _ := get(t, srv, "app.example.com", "/api/v2/slow", nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("타임아웃 → 502: %d", resp.StatusCode)
	}
	resp, _ = get(t, srv, "example.com", "/a/b?c=1", nil)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://douve.example.com/a/b?c=1" {
		t.Errorf("리다이렉트 %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, b = get(t, srv, "pve.example.com", "/", nil)
	if resp.StatusCode != 200 || b["tag"] != "tls" || b["host"] != "pve.internal" {
		t.Errorf("https 업스트림(검증 안 함)·Host 헤더 %d %+v", resp.StatusCode, b)
	}
	resp, _ = get(t, srv, "strict.example.com", "/", nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("자체 서명 인증서는 검증 모드에서 거부되어야 함: %d", resp.StatusCode)
	}
	dup := &Table{VerifyURL: "http://x/v", LoginURL: "https://x/l", Routes: []Route{
		{Host: "a.com", PathPrefix: "/api", Upstream: "x:1", Auth: "public"},
		{Host: "a.com", PathPrefix: "/api", Upstream: "y:1", Auth: "public"}}}
	if dup.Validate() == nil {
		t.Error("같은 도메인·경로 중복 허용됨")
	}
}

// auto 모드: 입구에서 직통이 안 되면 그 노드의 터널로 (집 서버). 실패 결과는 캐시해 다음 요청은 바로 터널.
func TestAutoModeFallsBackToTunnel(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"path": r.URL.Path})
	}))
	defer app.Close()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	const unreachable = "192.0.2.1:8080" // TEST-NET: 입구에서는 닿지 않음
	h := NewHandler(slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.SetTable(&Table{VerifyURL: "http://x/v", LoginURL: "https://x/l", SelfNode: 1,
		Nodes:  []NodeInfo{{ID: 2, PubKey: base64.RawURLEncoding.EncodeToString(pub), Mode: "auto"}},
		Routes: []Route{{Host: "home.example.com", Upstream: unreachable, Auth: "public", NodeID: 2}}})
	srv := httptest.NewServer(h.Tunnels())
	defer srv.Close()
	cl := tunnel.NewClient(2, priv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	cl.DialFunc = func(addr string) (net.Conn, error) {
		if addr != unreachable {
			return nil, fmt.Errorf("unexpected %s", addr)
		}
		return net.Dial("tcp", strings.TrimPrefix(app.URL, "http://")) // 그 서버 안에서는 닿음
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cl.Configure(strings.Replace(srv.URL, "http", "ws", 1)+tunnel.Path, []string{unreachable})
	go cl.Run(ctx)
	for i := 0; i < 100 && !h.Tunnels().Connected(2); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	front := httptest.NewServer(h)
	defer front.Close()
	start := time.Now()
	resp, body := get(t, front, "home.example.com", "/x", nil)
	if resp.StatusCode != 200 || body["path"] != "/x" {
		t.Fatalf("터널 폴백 실패 %d %+v", resp.StatusCode, body)
	}
	first := time.Since(start)
	start = time.Now()
	resp, _ = get(t, front, "home.example.com", "/y", nil)
	if resp.StatusCode != 200 || time.Since(start) > first/2 {
		t.Fatalf("직통 실패가 캐시되지 않음 (첫 %v, 두 번째 %v)", first, time.Since(start))
	}
}

func TestIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8080": true, "127.1.2.3:1": true, "localhost:80": true, "[::1]:80": true,
		"10.200.0.2:8080": false, "example.com:80": false,
	} {
		if got := isLoopback(addr); got != want {
			t.Fatalf("%s: %v", addr, got)
		}
	}
}

func TestLegacyMoatPolicy(t *testing.T) {
	tb := &Table{VerifyURL: "http://h/auth/verify", LoginURL: "https://h/login",
		Routes: []Route{{Host: "a.example.com", Upstream: "127.0.0.1:1", Auth: "moat"}}}
	if err := tb.Validate(); err != nil {
		t.Fatal(err)
	}
	if tb.Routes[0].Auth != "douve" {
		t.Fatalf("이전 이름의 정책은 로그인 필요로: %q", tb.Routes[0].Auth)
	}
}
