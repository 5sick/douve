// Package edge는 입구(edge) 역할을 맡은 노드의 공개 HTTPS 리버스 프록시다.
//
// Hub가 보내는 라우팅 표(도메인 → 업스트림 + 접근 정책)대로 요청을 넘기고,
// "douve" 정책이면 Hub의 /auth/verify로 로그인 여부를 확인한다. 인증서는 Let's Encrypt(autocert)로
// 자동 발급하며, 발급 전·실패 시에는 설정한 기존 인증서 파일을 쓴다. 라우팅 표는 디스크에 저장해
// Hub가 내려가 있어도 계속 서비스한다.
package edge

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Route는 도메인 하나의 라우팅 규칙이다.
type Route struct {
	ID          int64    `json:"id"` // Hub 서비스 id (앱별 권한 확인용, Hub 자신은 0)
	Host        string   `json:"host"`
	Upstream    string   `json:"upstream"`
	Auth        string   `json:"auth"` // douve | public | hub
	PublicPaths []string `json:"public_paths"`
	// 경로 접두사 라우팅: 같은 도메인에서 가장 긴 접두사가 이긴다 ("" 또는 "/" = 전체)
	PathPrefix  string `json:"path_prefix"`
	StripPrefix bool   `json:"strip_prefix"`
	Kind        string `json:"kind"` // proxy(기본) | redirect
	RedirectTo  string `json:"redirect_to"`
	UpstreamTLS int    `json:"upstream_tls"` // 0 http, 1 https, 2 https(검증 안 함)
	HostHeader  string `json:"host_header"`
	Timeout     int    `json:"timeout"` // 첫 응답까지 초
	NodeID      int64  `json:"node_id"` // 서비스가 도는 노드 (0 = 외부·알 수 없음 → 직접 연결)
}

// NodeInfo는 터널 인증과 연결 방식 선택에 쓰는 노드 정보다.
type NodeInfo struct {
	ID     int64  `json:"id"`
	PubKey string `json:"pubkey"` // Ed25519, base64url
	Mode   string `json:"mode"`   // auto | direct | tunnel
}

// verifyURL은 이 앱에 대한 권한을 묻는 주소다 (서비스 id가 없으면 Hub가 관리자만 허용).
func (r *Route) verifyURL(base string) string {
	if r.ID <= 0 {
		return base
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + "service=" + strconv.FormatInt(r.ID, 10)
}

func (r *Route) prefix() string {
	if r.PathPrefix == "" {
		return "/"
	}
	return r.PathPrefix
}

// matches는 경로가 이 라우트의 접두사 아래인지 본다 ("/api"는 "/api", "/api/x"와 맞고 "/apix"와는 안 맞음).
func (r *Route) matches(path string) bool {
	p := r.prefix()
	return p == "/" || path == p || strings.HasPrefix(path, p+"/")
}

// Table은 Hub의 routes 메시지다.
type Table struct {
	Disabled  bool       `json:"disabled"`
	SelfNode  int64      `json:"self_node"` // 이 입구의 노드 ID (자기 노드 서비스는 항상 직접)
	Nodes     []NodeInfo `json:"nodes"`
	VerifyURL string     `json:"verify_url"`
	LoginURL  string     `json:"login_url"`
	ACMEEmail string     `json:"acme_email"`
	Routes    []Route    `json:"routes"`
	// 내부 길: Douve가 관리하는 WireGuard로 연결된 사용자 기기만 들어오는 길 (없으면 끔)
	Devnet *Devnet `json:"devnet,omitempty"`
}

// Devnet은 입구가 여는 기기용 WireGuard 망이다 (package devnet이 띄운다).
// 연결된 기기의 DNS가 Routes의 도메인을 Address로 풀어 주고, 요청은 기기 신원(WireGuard 키 = 사용자)으로
// 권한을 확인한 뒤 같은 프록시로 넘긴다. 로그인 화면 없음.
type Devnet struct {
	ListenPort int     `json:"listen_port"` // UDP
	Address    string  `json:"address"`     // 입구의 내부 주소 (예: 10.201.0.1)
	Peers      []Peer  `json:"peers"`
	Routes     []Route `json:"routes"` // 내부 길로 여는 서비스 (Hub 자신 포함 가능)
}

// Peer는 등록된 기기 하나.
type Peer struct {
	PubKey   string  `json:"pubkey"` // WireGuard 공개키 (base64)
	IP       string  `json:"ip"`     // 기기 주소 (예: 10.201.0.2)
	User     string  `json:"user"`   // 사용자 이메일 (X-Douve-User)
	All      bool    `json:"all,omitempty"`
	Services []int64 `json:"services,omitempty"` // All이 아니면 들어갈 수 있는 서비스
}

// Allows는 이 기기가 서비스에 들어가도 되는지 본다 (누구나 공개 앱은 등록된 기기면 허용).
func (p *Peer) Allows(r *Route) bool {
	if p.All || r.Auth == "public" || r.Auth == "hub" {
		return true
	}
	for _, id := range p.Services {
		if id == r.ID && id > 0 {
			return true
		}
	}
	return false
}

// PeerByIP는 기기 주소로 기기를 찾는다 (WireGuard가 주소 위조를 막으므로 주소 = 신원).
func (d *Devnet) PeerByIP(ip string) *Peer {
	for i := range d.Peers {
		if d.Peers[i].IP == ip {
			return &d.Peers[i]
		}
	}
	return nil
}

// Lookup은 내부 길의 라우트를 찾는다.
func (d *Devnet) Lookup(host, path string) *Route {
	return lookupIn(d.Routes, host, path)
}

// HasHost는 내부 길에 이 도메인이 있는지 (DNS 응답, 인증서 발급).
func (d *Devnet) HasHost(host string) bool {
	for i := range d.Routes {
		if d.Routes[i].Host == host {
			return true
		}
	}
	return false
}

func (d *Devnet) validate() error {
	if d.ListenPort < 1 || d.ListenPort > 65535 {
		return fmt.Errorf("devnet: 잘못된 포트 %d", d.ListenPort)
	}
	addr, err := netip.ParseAddr(d.Address)
	if err != nil || !addr.Is4() || !addr.IsPrivate() {
		return fmt.Errorf("devnet: 잘못된 주소 %q", d.Address)
	}
	prefix := netip.PrefixFrom(addr, 24).Masked()
	keys, ips := map[string]bool{}, map[string]bool{}
	for _, p := range d.Peers {
		k, err := base64.StdEncoding.DecodeString(p.PubKey)
		if err != nil || len(k) != 32 || keys[p.PubKey] {
			return fmt.Errorf("devnet: 잘못된 기기 키 %q", p.PubKey)
		}
		ip, err := netip.ParseAddr(p.IP)
		if err != nil || !prefix.Contains(ip) || ip == addr || ips[p.IP] {
			return fmt.Errorf("devnet: 잘못된 기기 주소 %q", p.IP)
		}
		keys[p.PubKey], ips[p.IP] = true, true
	}
	return validateRoutes(d.Routes)
}

// Validate는 Hub에서 받은 표를 검사한다 (잘못된 표로 기존 표를 덮어쓰지 않도록).
func (t *Table) Validate() error {
	if t.Disabled {
		return nil
	}
	if !strings.HasPrefix(t.VerifyURL, "http://") && !strings.HasPrefix(t.VerifyURL, "https://") {
		return fmt.Errorf("verify_url 형식 오류")
	}
	if !strings.HasPrefix(t.LoginURL, "https://") && !strings.HasPrefix(t.LoginURL, "http://") {
		return fmt.Errorf("login_url 형식 오류")
	}
	if err := validateRoutes(t.Routes); err != nil {
		return err
	}
	if t.Devnet != nil {
		return t.Devnet.validate()
	}
	return nil
}

func validateRoutes(routes []Route) error {
	seen := map[string]bool{}
	for i := range routes {
		r := &routes[i]
		r.Host = strings.ToLower(strings.TrimSuffix(r.Host, "."))
		if r.Host == "" || strings.ContainsAny(r.Host, "/: ") {
			return fmt.Errorf("잘못된 호스트: %q", r.Host)
		}
		if p := r.prefix(); !strings.HasPrefix(p, "/") || strings.Contains(p, "..") || strings.ContainsAny(p, " ?#") {
			return fmt.Errorf("%s: 잘못된 경로 접두사 %q", r.Host, p)
		}
		key := r.Host + r.prefix()
		if seen[key] {
			return fmt.Errorf("중복 라우트: %s", key)
		}
		seen[key] = true
		if r.Kind == "redirect" {
			if !strings.HasPrefix(r.RedirectTo, "https://") && !strings.HasPrefix(r.RedirectTo, "http://") {
				return fmt.Errorf("%s: 잘못된 리다이렉트 주소", r.Host)
			}
			continue
		}
		if r.Kind != "" && r.Kind != "proxy" {
			return fmt.Errorf("%s: 알 수 없는 유형 %q", r.Host, r.Kind)
		}
		if r.Upstream == "" || strings.Contains(r.Upstream, "/") {
			return fmt.Errorf("%s: 잘못된 업스트림 %q", r.Host, r.Upstream)
		}
		if r.UpstreamTLS < 0 || r.UpstreamTLS > 2 || r.Timeout < 0 {
			return fmt.Errorf("%s: 잘못된 업스트림 설정", r.Host)
		}
		switch r.Auth {
		case "moat": // 이름을 바꾸기 전(Moat) Hub·저장된 표의 값 = 로그인 필요
			routes[i].Auth = "douve"
		case "douve", "public", "hub":
		default:
			return fmt.Errorf("%s: 알 수 없는 정책 %q", r.Host, r.Auth)
		}
		for _, p := range r.PublicPaths {
			if !strings.HasPrefix(p, "/") || p == "/" {
				return fmt.Errorf("%s: 잘못된 예외 경로 %q", r.Host, p)
			}
		}
	}
	return nil
}

func (t *Table) node(id int64) *NodeInfo {
	for i := range t.Nodes {
		if t.Nodes[i].ID == id {
			return &t.Nodes[i]
		}
	}
	return nil
}

// Hosts는 정렬된 호스트 목록이다.
func (t *Table) Hosts() []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(t.Routes))
	for _, r := range t.Routes {
		if !seen[r.Host] {
			seen[r.Host] = true
			out = append(out, r.Host)
		}
	}
	sort.Strings(out)
	return out
}

// hasHost는 이 도메인의 라우트가 하나라도 있는지 (인증서 발급·리다이렉트 판단).
func (t *Table) hasHost(host string) bool {
	for i := range t.Routes {
		if t.Routes[i].Host == host {
			return true
		}
	}
	return false
}

// lookup은 도메인과 경로에 맞는 라우트 중 접두사가 가장 긴 것을 고른다.
func (t *Table) lookup(host, path string) *Route {
	return lookupIn(t.Routes, host, path)
}

func lookupIn(routes []Route, host, path string) *Route {
	var best *Route
	for i := range routes {
		r := &routes[i]
		if r.Host != host || !r.matches(path) {
			continue
		}
		if best == nil || len(r.prefix()) > len(best.prefix()) {
			best = r
		}
	}
	return best
}

// isPublicPath는 경로가 로그인 예외 접두사에 해당하는지 본다.
// "/api/push/"는 "/api/push/abc"와 맞고, "/api/push"는 "/api/push"·"/api/push/…"와 맞지만 "/api/pushx"와는 안 맞는다.
func (r *Route) isPublicPath(path string) bool {
	for _, p := range r.PublicPaths {
		if strings.HasSuffix(p, "/") {
			if strings.HasPrefix(path, p) {
				return true
			}
		} else if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// LoadTable은 저장된 라우팅 표를 읽는다.
func LoadTable(path string) (*Table, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Table
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, err
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return &t, nil
}

// SaveTable은 라우팅 표를 원자적으로 저장한다.
func SaveTable(path string, t *Table) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Config는 노드 로컬 설정(/etc/douve-agent/edge.json, 선택)이다. 없으면 기본값.
type Config struct {
	HTTPAddr  string `json:"http_addr"`  // 기본 ":80" (ACME HTTP-01 + https 리다이렉트)
	HTTPSAddr string `json:"https_addr"` // 기본 ":443"
	// ACME 자동 발급 (기본 true). false면 FallbackCerts만 쓴다.
	ACME *bool `json:"acme"`
	// ACME 디렉터리 (비우면 Let's Encrypt 운영). 시험용 staging 등.
	ACMEDirectory string `json:"acme_directory"`
	// 발급 전·실패 시 쓸 기존 인증서 (예: certbot의 fullchain.pem/privkey.pem)
	FallbackCerts []CertFiles `json:"fallback_certs"`
	// 시험용: HTTPAddr에서 TLS 없이 프록시 (https 리다이렉트 대신)
	ServePlain bool `json:"serve_plain"`
}

type CertFiles struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

func (c *Config) acmeEnabled() bool { return c.ACME == nil || *c.ACME }

// LoadConfig는 edge.json을 읽는다. 파일이 없으면 기본값.
func LoadConfig(path string) (*Config, error) {
	c := &Config{}
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		if err := json.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	if c.HTTPAddr == "" {
		c.HTTPAddr = ":80"
	}
	if c.HTTPSAddr == "" && !c.ServePlain {
		c.HTTPSAddr = ":443"
	}
	return c, nil
}
