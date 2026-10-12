package edge

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/5sick/douve/agent/internal/i18n"
	"html"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/5sick/douve/agent/internal/tunnel"
)

const sessionCookie = "douve_session"

type tlsKey struct{}

// verifier는 Hub /auth/verify 결과를 짧게 캐시한다 (요청마다 Hub를 부르지 않도록).
type verifier struct {
	client *http.Client
	ttlOK  time.Duration
	ttlBad time.Duration

	mu    sync.Mutex
	cache map[[32]byte]verdict
}

type verdict struct {
	ok      bool
	user    string
	expires time.Time
}

func newVerifier() *verifier {
	return &verifier{
		client: &http.Client{Timeout: 5 * time.Second},
		ttlOK:  30 * time.Second,
		ttlBad: 5 * time.Second,
		cache:  map[[32]byte]verdict{},
	}
}

var errHubDown = &hubError{}

type hubError struct{}

func (*hubError) Error() string { return "로그인 서버에 연결할 수 없습니다" }

// check는 세션 쿠키 값이 유효한지 확인한다. Hub에 닿지 못하면 errHubDown.
func (v *verifier) check(ctx context.Context, verifyURL, token string) (bool, string, error) {
	key := sha256.Sum256([]byte(verifyURL + "\x00" + token))
	now := time.Now()
	v.mu.Lock()
	if d, ok := v.cache[key]; ok && now.Before(d.expires) {
		v.mu.Unlock()
		return d.ok, d.user, nil
	}
	if len(v.cache) > 10000 { // 오래된 항목 정리
		for k, d := range v.cache {
			if now.After(d.expires) {
				delete(v.cache, k)
			}
		}
	}
	v.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, nil)
	if err != nil {
		return false, "", err
	}
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	resp, err := v.client.Do(req)
	if err != nil {
		return false, "", errHubDown
	}
	resp.Body.Close()
	var d verdict
	switch resp.StatusCode {
	case http.StatusOK:
		d = verdict{ok: true, user: resp.Header.Get("X-Douve-User"), expires: now.Add(v.ttlOK)}
	case http.StatusUnauthorized:
		d = verdict{ok: false, expires: now.Add(v.ttlBad)}
	default:
		return false, "", errHubDown
	}
	v.mu.Lock()
	v.cache[key] = d
	v.mu.Unlock()
	return d.ok, d.user, nil
}

// Handler는 라우팅 표에 따라 요청을 처리한다. 표는 원자적으로 교체된다.
type Handler struct {
	table    atomic.Pointer[Table]
	verifier *verifier
	log      *slog.Logger
	tunnels  *tunnel.Server

	directMu sync.Mutex
	direct   map[string]directResult // auto 모드: 업스트림별 직통 가능 여부 캐시

	mu      sync.Mutex
	proxies map[string]*httputil.ReverseProxy // 업스트림·옵션별
}

func (r *Route) proxyKey(mode string) string {
	return fmt.Sprintf("%s|%d|%s|%d|%t|%s|%d|%s", r.Upstream, r.UpstreamTLS, r.HostHeader, r.Timeout, r.StripPrefix, r.prefix(), r.NodeID, mode)
}

type directResult struct {
	ok      bool
	expires time.Time
}

func NewHandler(log *slog.Logger) *Handler {
	h := &Handler{verifier: newVerifier(), log: log, proxies: map[string]*httputil.ReverseProxy{},
		direct: map[string]directResult{}}
	h.tunnels = tunnel.NewServer(h.nodeKey, log)
	return h
}

// Tunnels는 입구의 터널 서버다 (서비스가 있는 노드의 Agent가 접속).
func (h *Handler) Tunnels() *tunnel.Server { return h.tunnels }

func (h *Handler) nodeKey(id int64) (ed25519.PublicKey, bool) {
	t := h.table.Load()
	if t == nil {
		return nil, false
	}
	n := t.node(id)
	if n == nil {
		return nil, false
	}
	k, err := base64.RawURLEncoding.DecodeString(n.PubKey)
	if err != nil || len(k) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(k), true
}

// dial은 라우트의 노드로 가는 길을 고른다:
//   - 외부(노드 없음)·자기 노드: 직접
//   - direct: 직접 (WireGuard·Tailscale·같은 사설망)
//   - tunnel: 그 노드 Agent가 연 터널
//   - auto(기본): 직접 2초 시도 → 안 되면 터널. 결과는 직통 성공 5분, 실패 1분 캐시
func (h *Handler) dial(nodeID int64, mode string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		t := h.table.Load()
		if nodeID == 0 || t == nil || nodeID == t.SelfNode {
			return d.DialContext(ctx, network, addr)
		}
		// 127.0.0.1 같은 루프백 업스트림은 그 노드 안에서만 닿는다 — 직접 걸면 입구 자신에 붙는다
		if mode == "tunnel" || isLoopback(addr) {
			return h.tunnels.Dial(ctx, nodeID, addr)
		}
		if mode == "direct" {
			return d.DialContext(ctx, network, addr)
		}
		h.directMu.Lock()
		cached, ok := h.direct[addr]
		h.directMu.Unlock()
		if !ok || time.Now().After(cached.expires) || cached.ok {
			qctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			c, err := d.DialContext(qctx, network, addr)
			cancel()
			if err == nil {
				h.setDirect(addr, true, 5*time.Minute)
				return c, nil
			}
			h.setDirect(addr, false, time.Minute)
			if !h.tunnels.Connected(nodeID) {
				return nil, err
			}
		}
		return h.tunnels.Dial(ctx, nodeID, addr)
	}
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (h *Handler) setDirect(addr string, ok bool, ttl time.Duration) {
	h.directMu.Lock()
	h.direct[addr] = directResult{ok: ok, expires: time.Now().Add(ttl)}
	h.directMu.Unlock()
}

func (h *Handler) SetTable(t *Table) { h.table.Store(t) }
func (h *Handler) Table() *Table     { return h.table.Load() }

func hostOnly(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(strings.TrimSuffix(hostport, "."))
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (h *Handler) proxy(route *Route) *httputil.ReverseProxy {
	mode := "auto"
	if t := h.table.Load(); t != nil {
		if n := t.node(route.NodeID); n != nil && n.Mode != "" {
			mode = n.Mode
		}
	}
	key := route.proxyKey(mode)
	h.mu.Lock()
	defer h.mu.Unlock()
	if p, ok := h.proxies[key]; ok {
		return p
	}
	r := *route // 표가 바뀌어도 이 프록시는 만든 시점의 설정을 쓴다
	scheme := "http"
	if r.UpstreamTLS > 0 {
		scheme = "https"
	}
	target := &url.URL{Scheme: scheme, Host: r.Upstream}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = h.dial(r.NodeID, mode)
	if r.UpstreamTLS == 2 {
		// 사용자가 명시적으로 고른 경우에만 (Proxmox 등 자체 서명 인증서 장비)
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	if r.Timeout > 0 {
		transport.ResponseHeaderTimeout = time.Duration(r.Timeout) * time.Second
	}
	p := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			if r.StripPrefix && r.prefix() != "/" {
				rest := strings.TrimPrefix(pr.In.URL.Path, r.prefix())
				if !strings.HasPrefix(rest, "/") {
					rest = "/" + rest
				}
				pr.Out.URL.Path = rest
				pr.Out.URL.RawPath = ""
				pr.Out.Header.Set("X-Forwarded-Prefix", r.prefix())
			}
			pr.Out.Host = pr.In.Host // 원래 도메인 유지 (nginx의 Host $host)
			if r.HostHeader != "" {
				pr.Out.Host = r.HostHeader
			}
			pr.SetXForwarded()
			pr.Out.Header.Set("X-Real-IP", clientIP(pr.In))
		},
		FlushInterval: -1, // 스트리밍(SSE·LLM 응답) 즉시 전달
		ModifyResponse: func(res *http.Response) error {
			// HTTPS로 받은 요청이면 HSTS (업스트림이 이미 보냈으면 그 값 유지)
			if res.Request.Context().Value(tlsKey{}) != nil && res.Header.Get("Strict-Transport-Security") == "" {
				res.Header.Set("Strict-Transport-Security", "max-age=15552000")
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			h.log.Warn("업스트림 오류", "host", req.Host, "upstream", r.Upstream, "err", err)
			errorPage(w, req, http.StatusBadGateway, "서비스에 연결할 수 없습니다",
				"서비스가 내려가 있거나 응답하지 않습니다. 잠시 후 다시 시도하세요.")
		},
	}
	h.proxies[key] = p
	return p
}

// stripSession은 업스트림 서비스로 Douve 세션 쿠키가 넘어가지 않게 한다
// (서비스가 쿠키를 훔쳐 다른 서비스에 로그인하는 것 방지).
func stripSession(r *http.Request) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name != sessionCookie {
			r.AddCookie(c)
		}
	}
}

func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t := h.table.Load()
	host := hostOnly(r.Host)
	var route *Route
	if t != nil && !t.Disabled {
		route = t.lookup(host, r.URL.Path)
	}
	if route == nil {
		errorPage(w, r, http.StatusNotFound, "알 수 없는 주소", "이 도메인은 Douve에 등록되어 있지 않습니다.")
		return
	}
	// 클라이언트가 보낸 사용자 헤더는 절대 믿지 않는다. Tailscale 신원 헤더도 지운다
	// (Hub가 Tailscale 모드면 127.0.0.1에서 온 이 헤더를 로그인으로 인정하는데, 입구도 127.0.0.1에서 Hub로 간다)
	r.Header.Del("X-Douve-User")
	for _, h := range []string{"Tailscale-User-Login", "Tailscale-User-Name", "Tailscale-User-Profile-Pic", "Tailscale-Headers-Info"} {
		r.Header.Del(h)
	}

	if route.Kind == "redirect" {
		// 경로·쿼리는 그대로 붙인다 (접두사는 떼고)
		rest := r.URL.RequestURI()
		if p := route.prefix(); p != "/" {
			rest = strings.TrimPrefix(rest, p)
		}
		target := strings.TrimRight(route.RedirectTo, "/")
		if rest == "" || rest[0] != '/' {
			rest = "/" + rest
		}
		http.Redirect(w, r, target+rest, http.StatusFound)
		return
	}

	switch {
	case route.Auth == "hub":
		// Hub 자신: 쿠키 그대로, Hub가 로그인을 직접 처리
	case route.Auth == "public" || route.isPublicPath(r.URL.Path):
		stripSession(r)
	default: // douve
		token := ""
		if c, err := r.Cookie(sessionCookie); err == nil {
			token = c.Value
		}
		ok, user := false, ""
		if token != "" {
			var err error
			ok, user, err = h.verifier.check(r.Context(), t.VerifyURL, token)
			if err != nil {
				errorPage(w, r, http.StatusBadGateway, "로그인 서버에 연결할 수 없습니다",
					"Douve Hub가 응답하지 않습니다. 잠시 후 다시 시도하세요.")
				return
			}
		}
		if !ok {
			h.toLogin(w, r, t)
			return
		}
		stripSession(r)
		r.Header.Set("X-Douve-User", user)
	}
	if r.TLS != nil {
		r = r.WithContext(context.WithValue(r.Context(), tlsKey{}, true))
	}
	h.proxy(route).ServeHTTP(w, r)
}

func (h *Handler) toLogin(w http.ResponseWriter, r *http.Request, t *Table) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "로그인이 필요합니다", http.StatusUnauthorized)
		return
	}
	back := scheme(r) + "://" + r.Host + r.URL.RequestURI()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, t.LoginURL+"?rd="+url.QueryEscape(back), http.StatusFound)
}

func errorPage(w http.ResponseWriter, r *http.Request, code int, title, msg string) {
	lang := i18n.ForRequest(r)
	title, msg = i18n.In(lang, title), i18n.In(lang, msg)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`<!doctype html><html lang="` + lang + `"><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1"><title>` + html.EscapeString(title) +
		`</title><body style="font-family:sans-serif;max-width:520px;margin:15vh auto;padding:0 16px">` +
		`<h1 style="font-size:22px">` + html.EscapeString(title) + `</h1><p style="color:#666">` +
		html.EscapeString(msg) + `</p><p style="color:#999;font-size:13px">Douve</p></body></html>`))
}
