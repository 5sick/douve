// Package devnet은 입구가 여는 기기용 WireGuard 망(내부 길)이다.
//
// 사용자의 폰·PC는 Douve 화면에서 받은 WireGuard 설정(QR)으로 입구에 연결한다. 커널 인터페이스·
// 방화벽·IP 포워딩은 건드리지 않는다: WireGuard(userspace)와 TCP/IP(gVisor netstack)가 모두 Agent
// 안에서 돌고, 입구의 내부 주소(예: 10.201.0.1)에서
//   - DNS(53): 내부 길에 있는 서비스 도메인은 이 주소로, 나머지는 서버의 DNS로 넘긴다
//   - HTTP(80): HTTPS로 보낸다
//   - HTTPS(443): 입구와 같은 인증서로 받아, 기기 주소로 사용자를 찾고 권한을 확인한 뒤 같은 프록시로 넘긴다
//
// 기기 주소 = 신원이다: WireGuard는 각 기기 키에 허락된 주소(/32)에서 온 패킷만 받는다.
package devnet

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/5sick/douve/agent/internal/edge"
)

// KeyFile은 상태 디렉터리 안의 입구 WireGuard 개인키다 (Hub는 공개키만 안다).
const KeyFile = "devnet.key"

// Proxy는 내부 길 요청을 서비스로 넘긴다 (edge.Handler).
type Proxy interface {
	ServeInternal(w http.ResponseWriter, r *http.Request, route *edge.Route, user string)
}

// Gateway는 입구의 기기용 WireGuard 망이다.
type Gateway struct {
	log      *slog.Logger
	proxy    Proxy
	getCert  func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	priv     [32]byte
	pub      string
	Upstream func() string // DNS를 넘길 곳 (기본: /etc/resolv.conf의 첫 nameserver)
	OnChange func()        // 설정을 적용한 뒤 (Hub에 상태·공개키를 바로 알리게)

	cfg atomic.Pointer[edge.Devnet]

	mu      sync.Mutex
	dev     *device.Device
	tnet    *netstack.Net
	port    int
	address string
	peers   map[string]string // 지금 설정된 기기 (공개키 hex → 주소)
	closers []func()
}

// New는 상태 디렉터리의 개인키를 읽거나 새로 만든다.
func New(stateDir string, proxy Proxy, getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error), log *slog.Logger) (*Gateway, error) {
	g := &Gateway{log: log, proxy: proxy, getCert: getCert, Upstream: systemResolver}
	path := filepath.Join(stateDir, KeyFile)
	b, err := os.ReadFile(path)
	switch {
	case err == nil && len(b) == 32:
		copy(g.priv[:], b)
	case err == nil || errors.Is(err, os.ErrNotExist):
		if _, err := rand.Read(g.priv[:]); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, g.priv[:], 0o600); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	// X25519 개인키 다듬기 (WireGuard와 같은 방식)
	g.priv[0] &= 248
	g.priv[31] = (g.priv[31] & 127) | 64
	pub, err := curve25519.X25519(g.priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	g.pub = base64.StdEncoding.EncodeToString(pub)
	return g, nil
}

// PublicKey는 입구의 WireGuard 공개키 (base64). 기기 설정의 [Peer]에 들어간다.
func (g *Gateway) PublicKey() string { return g.pub }

func hexKey(b64 string) (string, error) {
	k, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(k) != 32 {
		return "", fmt.Errorf("잘못된 키 %q", b64)
	}
	return hex.EncodeToString(k), nil
}

// peersConfig는 지금 기기 목록(old: 공개키 → 주소)에서 새 목록으로 가는 UAPI 설정이다.
// 바뀌지 않은 기기는 건드리지 않는다 (통째로 바꾸면 연결된 기기의 세션 키가 사라져 한동안 끊긴다).
func peersConfig(old map[string]string, peers []edge.Peer) (string, map[string]string, error) {
	var b strings.Builder
	next := map[string]string{}
	for _, p := range peers {
		k, err := hexKey(p.PubKey)
		if err != nil {
			return "", nil, err
		}
		next[k] = p.IP
		if ip, ok := old[k]; ok && ip == p.IP {
			continue
		}
		fmt.Fprintf(&b, "public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\n", k, p.IP)
	}
	for k := range old {
		if _, ok := next[k]; !ok {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", k)
		}
	}
	return b.String(), next, nil
}

// Apply는 Hub가 보낸 내부 길 설정을 적용한다. nil이면 끈다.
func (g *Gateway) Apply(c *edge.Devnet) {
	if err := g.apply(c); err != nil {
		g.log.Warn("내부 길(기기 WireGuard) 설정 실패", "err", err)
	}
	if g.OnChange != nil {
		g.OnChange()
	}
}

func (g *Gateway) apply(c *edge.Devnet) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if c == nil {
		g.cfg.Store(nil)
		if g.dev != nil {
			g.log.Info("내부 길 끔")
		}
		g.stopLocked()
		return nil
	}
	if g.dev != nil && g.port == c.ListenPort && g.address == c.Address {
		diff, next, err := peersConfig(g.peers, c.Peers)
		if err != nil {
			return err
		}
		g.cfg.Store(c)
		if diff == "" {
			return nil
		}
		if err := g.dev.IpcSet(diff); err != nil {
			return err
		}
		g.peers = next
		return nil
	}
	peers, next, err := peersConfig(nil, c.Peers)
	if err != nil {
		return err
	}
	g.cfg.Store(c)
	g.stopLocked()
	addr, err := netip.ParseAddr(c.Address)
	if err != nil {
		return err
	}
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, 1420)
	if err != nil {
		return err
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hex.EncodeToString(g.priv[:]), c.ListenPort) + peers); err != nil {
		dev.Close()
		return fmt.Errorf("UDP %d: %w", c.ListenPort, err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return err
	}
	g.dev, g.tnet, g.port, g.address, g.peers = dev, tnet, c.ListenPort, c.Address, next
	g.closers = append(g.closers, dev.Close)
	if err := g.serveLocked(addr); err != nil {
		g.stopLocked()
		return err
	}
	g.log.Info("내부 길 시작", "udp", c.ListenPort, "address", c.Address, "devices", len(c.Peers))
	return nil
}

func (g *Gateway) stopLocked() {
	for i := len(g.closers) - 1; i >= 0; i-- {
		g.closers[i]()
	}
	g.closers, g.dev, g.tnet, g.port, g.address, g.peers = nil, nil, nil, 0, "", nil
}

// Close는 내부 길을 닫는다.
func (g *Gateway) Close() { g.Apply(nil) }

func (g *Gateway) serveLocked(addr netip.Addr) error {
	l80, err := g.tnet.ListenTCPAddrPort(netip.AddrPortFrom(addr, 80))
	if err != nil {
		return err
	}
	l443, err := g.tnet.ListenTCPAddrPort(netip.AddrPortFrom(addr, 443))
	if err != nil {
		l80.Close()
		return err
	}
	udp, err := g.tnet.ListenUDPAddrPort(netip.AddrPortFrom(addr, 53))
	if err != nil {
		l80.Close()
		l443.Close()
		return err
	}
	plain := &http.Server{Handler: http.HandlerFunc(g.toHTTPS), ReadHeaderTimeout: 10 * time.Second}
	secure := &http.Server{Handler: http.HandlerFunc(g.serve), ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{GetCertificate: g.getCert, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}}
	go func() { _ = plain.Serve(l80) }()
	go func() { _ = secure.ServeTLS(l443, "", "") }()
	stop := make(chan struct{})
	go g.serveDNS(udp, stop)
	g.closers = append(g.closers, func() {
		close(stop)
		udp.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = plain.Shutdown(ctx)
		_ = secure.Shutdown(ctx)
	})
	return nil
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(strings.TrimSuffix(hostport, "."))
}

func remoteIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (g *Gateway) toHTTPS(w http.ResponseWriter, r *http.Request) {
	c := g.cfg.Load()
	host := hostOnly(r.Host)
	if c == nil || host == "" || host == c.Address {
		g.serve(w, r) // 주소로 바로 열면 연결 상태 화면
		return
	}
	http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
}

func (g *Gateway) serve(w http.ResponseWriter, r *http.Request) {
	c := g.cfg.Load()
	if c == nil {
		http.Error(w, "내부 길이 꺼져 있습니다", http.StatusServiceUnavailable)
		return
	}
	peer := c.PeerByIP(remoteIP(r))
	if peer == nil {
		edge.ErrorPage(w, r, http.StatusForbidden, "등록되지 않은 기기", "Douve에서 이 기기를 등록하세요.")
		return
	}
	host := hostOnly(r.Host)
	if host == "" || host == c.Address {
		g.status(w, c, peer)
		return
	}
	route := c.Lookup(host, r.URL.Path)
	if route == nil {
		edge.ErrorPage(w, r, http.StatusNotFound, "알 수 없는 주소", "이 도메인은 Douve 내부 길에 없습니다.")
		return
	}
	if !peer.Allows(route) {
		edge.ErrorPage(w, r, http.StatusForbidden, "이 앱을 쓸 권한이 없습니다", "Douve 관리자에게 이 앱 권한을 요청하세요.")
		return
	}
	g.proxy.ServeInternal(w, r, route, peer.User)
}

// status는 입구 주소로 바로 열었을 때의 화면: 연결된 사용자와 들어갈 수 있는 앱.
func (g *Gateway) status(w http.ResponseWriter, c *edge.Devnet, p *edge.Peer) {
	seen := map[string]bool{}
	var hosts []string
	for i := range c.Routes {
		r := &c.Routes[i]
		if !seen[r.Host] && p.Allows(r) {
			seen[r.Host] = true
			hosts = append(hosts, r.Host)
		}
	}
	sort.Strings(hosts)
	var b strings.Builder
	b.WriteString(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>Douve</title><body style="font-family:sans-serif;max-width:520px;margin:10vh auto;padding:0 16px">` +
		`<h1 style="font-size:22px">Douve 내부 길에 연결됨</h1><p style="color:#666">` + html.EscapeString(p.User) + `</p><ul>`)
	for _, h := range hosts {
		b.WriteString(`<li><a href="https://` + html.EscapeString(h) + `/">` + html.EscapeString(h) + `</a></li>`)
	}
	b.WriteString(`</ul></body>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(b.String()))
}

// PeerStatus는 기기 연결 상태 (Hub 화면용).
type PeerStatus struct {
	PubKey        string `json:"pubkey"`
	LastHandshake int64  `json:"last_handshake"` // unix 초, 0 = 아직 없음
	RxBytes       int64  `json:"rx"`
	TxBytes       int64  `json:"tx"`
	Endpoint      string `json:"endpoint,omitempty"`
}

// Status는 기기별 마지막 연결과 주고받은 양이다.
func (g *Gateway) Status() []PeerStatus {
	g.mu.Lock()
	dev := g.dev
	g.mu.Unlock()
	if dev == nil {
		return nil
	}
	raw, err := dev.IpcGet()
	if err != nil {
		return nil
	}
	var out []PeerStatus
	var cur *PeerStatus
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			b, err := hex.DecodeString(v)
			if err != nil {
				cur = nil
				continue
			}
			out = append(out, PeerStatus{PubKey: base64.StdEncoding.EncodeToString(b)})
			cur = &out[len(out)-1]
		case "last_handshake_time_sec":
			if cur != nil {
				cur.LastHandshake, _ = strconv.ParseInt(v, 10, 64)
			}
		case "rx_bytes":
			if cur != nil {
				cur.RxBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.TxBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		case "endpoint":
			if cur != nil {
				cur.Endpoint = v
			}
		}
	}
	return out
}

// Running은 내부 길이 떠 있는지.
func (g *Gateway) Running() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.dev != nil
}

func systemResolver() string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "nameserver" {
				if ip, err := netip.ParseAddr(f[1]); err == nil {
					return netip.AddrPortFrom(ip, 53).String()
				}
			}
		}
	}
	return "1.1.1.1:53"
}
