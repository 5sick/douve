package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/5sick/douve/agent/internal/tunnel"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// certSource는 SNI별 인증서를 고른다.
//   - ACME로 이미 받은 인증서가 있으면 그것
//   - 없고 기존 인증서 파일이 그 도메인을 덮으면 그것을 쓰면서 뒤에서 ACME 발급 시도
//   - 둘 다 없으면 ACME 발급(첫 요청이 몇 초 걸림)
type certSource struct {
	acme *autocert.Manager // nil이면 ACME 끔
	log  *slog.Logger

	mu       sync.RWMutex
	fallback []*tls.Certificate
	files    []CertFiles

	pending sync.Map // host → time.Time (마지막 백그라운드 발급 시도)
}

func (c *certSource) loadFallback() {
	var certs []*tls.Certificate
	for _, f := range c.files {
		cert, err := tls.LoadX509KeyPair(f.Cert, f.Key)
		if err != nil {
			c.log.Warn("대체 인증서를 읽을 수 없음", "cert", f.Cert, "err", err)
			continue
		}
		certs = append(certs, &cert) // Go 1.23+: Leaf가 채워진다
	}
	c.mu.Lock()
	c.fallback = certs
	c.mu.Unlock()
}

func (c *certSource) fallbackFor(name string) *tls.Certificate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := time.Now()
	for _, cert := range c.fallback {
		if cert.Leaf != nil && cert.Leaf.VerifyHostname(name) == nil && now.Before(cert.Leaf.NotAfter) {
			return cert
		}
	}
	return nil
}

func (c *certSource) acmeCached(name string) bool {
	_, err := c.acme.Cache.Get(context.Background(), name)
	return err == nil
}

func (c *certSource) obtainInBackground(name string) {
	if last, ok := c.pending.Load(name); ok && time.Since(last.(time.Time)) < time.Hour {
		return
	}
	c.pending.Store(name, time.Now())
	go func() {
		hello := &tls.ClientHelloInfo{
			ServerName:       name,
			SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
			SupportedCurves:  []tls.CurveID{tls.CurveP256},
			CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		}
		if _, err := c.acme.GetCertificate(hello); err != nil {
			c.log.Warn("인증서 발급 실패 (기존 인증서로 계속)", "host", name, "err", err)
			return
		}
		c.log.Info("인증서 발급 완료", "host", name)
	}()
}

func (c *certSource) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	if c.acme != nil && slices.Contains(hello.SupportedProtos, acme.ALPNProto) {
		return c.acme.GetCertificate(hello) // TLS-ALPN-01 검증 요청
	}
	fb := c.fallbackFor(name)
	if c.acme != nil {
		if c.acmeCached(name) || fb == nil {
			cert, err := c.acme.GetCertificate(hello)
			if err == nil || fb == nil {
				return cert, err
			}
		} else {
			c.obtainInBackground(name)
		}
	}
	if fb != nil {
		return fb, nil
	}
	return nil, fmt.Errorf("%s: 인증서 없음", name)
}

// Manager는 라우팅 표 적용과 HTTP/HTTPS 서버 수명을 관리한다.
type Manager struct {
	cfg       *Config
	tablePath string
	handler   *Handler
	certs     *certSource
	log       *slog.Logger

	mu       sync.Mutex
	servers  []*http.Server
	starting bool
	stop     chan struct{}
}

func NewManager(cfg *Config, stateDir string, log *slog.Logger) *Manager {
	m := &Manager{
		cfg:       cfg,
		tablePath: filepath.Join(stateDir, "routes.json"),
		handler:   NewHandler(log),
		log:       log,
	}
	m.certs = &certSource{log: log, files: cfg.FallbackCerts}
	if cfg.acmeEnabled() && !cfg.ServePlain {
		m.certs.acme = &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(filepath.Join(stateDir, "acme")),
			HostPolicy: func(_ context.Context, host string) error {
				if t := m.handler.Table(); t != nil && !t.Disabled && t.hasHost(host) {
					return nil
				}
				return fmt.Errorf("등록되지 않은 도메인: %s", host)
			},
		}
		if cfg.ACMEDirectory != "" {
			m.certs.acme.Client = &acme.Client{DirectoryURL: cfg.ACMEDirectory}
		}
	}
	m.certs.loadFallback()
	return m
}

// Start는 저장된 라우팅 표가 있으면 바로 서비스를 시작한다 (Hub 접속 전에도).
func (m *Manager) Start() {
	t, err := LoadTable(m.tablePath)
	if err != nil {
		return
	}
	m.log.Info("저장된 라우팅 표로 입구 시작", "hosts", len(t.Routes))
	m.activate(t)
}

// Apply는 Hub가 보낸 라우팅 표를 검증·저장·적용한다.
func (m *Manager) Apply(t *Table) error {
	if err := t.Validate(); err != nil {
		return err
	}
	if err := SaveTable(m.tablePath, t); err != nil {
		m.log.Warn("라우팅 표 저장 실패", "err", err)
	}
	m.activate(t)
	m.log.Info("라우팅 표 적용", "hosts", strings.Join(t.Hosts(), ","), "disabled", t.Disabled)
	return nil
}

func (m *Manager) activate(t *Table) {
	if m.certs.acme != nil && t.ACMEEmail != "" {
		m.certs.acme.Email = t.ACMEEmail // 첫 계정 등록 전에만 의미가 있다
	}
	m.handler.SetTable(t)
	if t.Disabled {
		m.shutdown()
		return
	}
	m.ensureServers()
}

func (m *Manager) redirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := m.handler.Table()
		host := hostOnly(r.Host)
		if t == nil || t.Disabled || !t.hasHost(host) {
			http.NotFound(w, r)
			return
		}
		target := "https://" + host
		if _, port, err := net.SplitHostPort(m.cfg.HTTPSAddr); err == nil && port != "443" {
			target += ":" + port
		}
		http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
}

// ensureServers는 서버를 띄운다. 포트가 사용 중이면(예: 전환 전 nginx) 30초마다 다시 시도한다.
func (m *Manager) ensureServers() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.servers) > 0 || m.starting {
		return
	}
	m.starting = true
	m.stop = make(chan struct{})
	stop := m.stop
	go func() {
		for {
			servers, err := m.listen()
			if err == nil {
				m.mu.Lock()
				m.servers = servers
				m.starting = false
				m.mu.Unlock()
				go m.reloadLoop(stop)
				return
			}
			m.log.Warn("입구 포트를 열 수 없음, 30초 후 재시도", "err", err)
			select {
			case <-stop:
				return
			case <-time.After(30 * time.Second):
			}
		}
	}()
}

// withTunnel은 터널 경로(/_douve/tunnel)를 라우팅보다 먼저 받는다 (모든 도메인에서).
func (m *Manager) withTunnel(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == tunnel.Path {
			m.handler.Tunnels().ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *Manager) listen() ([]*http.Server, error) {
	var lns []net.Listener
	var servers []*http.Server
	closeAll := func() {
		for _, l := range lns {
			l.Close()
		}
	}
	base := func(h http.Handler) *http.Server {
		return &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	}
	if m.cfg.HTTPAddr != "" {
		ln, err := net.Listen("tcp", m.cfg.HTTPAddr)
		if err != nil {
			return nil, err
		}
		lns = append(lns, ln)
		var h http.Handler = m.redirectHandler()
		if m.cfg.ServePlain {
			h = m.withTunnel(m.handler)
		} else if m.certs.acme != nil {
			h = m.certs.acme.HTTPHandler(h) // HTTP-01 검증
		}
		servers = append(servers, base(h))
	}
	if m.cfg.HTTPSAddr != "" {
		ln, err := net.Listen("tcp", m.cfg.HTTPSAddr)
		if err != nil {
			closeAll()
			return nil, err
		}
		tlsCfg := &tls.Config{
			GetCertificate: m.certs.GetCertificate,
			NextProtos:     []string{"h2", "http/1.1", acme.ALPNProto},
			MinVersion:     tls.VersionTLS12,
		}
		lns = append(lns, tls.NewListener(ln, tlsCfg))
		s := base(m.withTunnel(m.handler))
		s.TLSConfig = tlsCfg
		servers = append(servers, s)
	}
	for i, s := range servers {
		ln := lns[i]
		m.log.Info("입구 수신 시작", "addr", ln.Addr().String())
		go func() {
			if err := s.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				m.log.Error("입구 서버 종료", "err", err)
			}
		}()
	}
	return servers, nil
}

// reloadLoop는 certbot 등이 갱신한 대체 인증서 파일을 12시간마다 다시 읽는다.
func (m *Manager) reloadLoop(stop chan struct{}) {
	t := time.NewTicker(12 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			m.certs.loadFallback()
		}
	}
}

func (m *Manager) shutdown() {
	m.mu.Lock()
	servers := m.servers
	m.servers = nil
	if m.stop != nil {
		close(m.stop)
		m.stop = nil
	}
	m.starting = false
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(ctx)
	}
	if len(servers) > 0 {
		m.log.Info("입구 중지")
	}
}

// Close는 프로세스 종료 시 호출한다.
func (m *Manager) Close() { m.shutdown() }
