package devnet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/5sick/douve/agent/internal/edge"
)

// fakeProxy는 내부 길이 넘긴 요청을 기록한다.
type fakeProxy struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeProxy) ServeInternal(w http.ResponseWriter, r *http.Request, route *edge.Route, user string) {
	f.mu.Lock()
	f.calls = append(f.calls, route.Host+" "+user)
	f.mu.Unlock()
	fmt.Fprintf(w, "app=%s user=%s", route.Host, user)
}

func selfSigned(t *testing.T) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		DNSNames:  []string{"app.example.com", "secret.example.com", "douve.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil }
}

type phone struct {
	priv, pub string // base64
	dev       *device.Device
	tnet      *netstack.Net
}

func newKey() (priv, pub [32]byte) {
	_, _ = rand.Read(priv[:])
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	p, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
	copy(pub[:], p)
	return
}

// newPhone은 기기 하나를 흉내 낸다 (WireGuard 앱 + 그 기기의 TCP/IP).
type keyPair struct {
	priv [32]byte
	pub  string
}

func newKeyPair() keyPair {
	priv, pub := newKey()
	return keyPair{priv, base64.StdEncoding.EncodeToString(pub[:])}
}

func newPhone(t *testing.T, ip string, k keyPair, gwPub string, gwPort int) *phone {
	priv := k.priv
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(ip)}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	gk, _ := base64.StdEncoding.DecodeString(gwPub)
	cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=10.201.0.0/24\npersistent_keepalive_interval=1\n",
		hex.EncodeToString(priv[:]), hex.EncodeToString(gk), gwPort)
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)
	return &phone{priv: base64.StdEncoding.EncodeToString(priv[:]), pub: k.pub, dev: dev, tnet: tnet}
}

// get은 기기에서 https://host/로 요청한다 (DNS 없이 입구 주소로 바로).
func (p *phone) get(host string) (int, string, error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return p.tnet.DialContext(ctx, network, "10.201.0.1:443")
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: host}, //nolint:gosec
	}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get("https://" + host + "/")
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

func (p *phone) dns(t *testing.T, name string, typ dnsmessage.Type) []byte {
	c, err := p.tnet.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("10.201.0.1:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 77, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: typ, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("DNS %s: %v", name, err)
	}
	return buf[:n]
}

func freeUDPPort(t *testing.T) int {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// 서버의 DNS 흉내: 무엇을 물어도 192.0.2.7
func fakeUpstream(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, _ := p.Start(buf[:n])
			q, _ := p.Question()
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true})
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 5}, dnsmessage.AResource{A: [4]byte{192, 0, 2, 7}})
			out, _ := b.Finish()
			_, _ = pc.WriteTo(out, from)
		}
	}()
	return pc.LocalAddr().String()
}

func aRecords(t *testing.T, resp []byte) []string {
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		t.Fatal(err)
	}
	_ = p.SkipAllQuestions()
	var out []string
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		if h.Type == dnsmessage.TypeA {
			a, _ := p.AResource()
			out = append(out, netip.AddrFrom4(a.A).String())
		} else {
			_ = p.SkipAnswer()
		}
	}
	return out
}

func TestGateway(t *testing.T) {
	proxy := &fakeProxy{}
	dir := t.TempDir()
	g, err := New(dir, proxy, selfSigned(t), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	g.Upstream = func() string { return fakeUpstream(t) }
	defer g.Close()
	port := freeUDPPort(t)

	meKey, limitedKey := newKeyPair(), newKeyPair()
	cfg := &edge.Devnet{ListenPort: port, Address: "10.201.0.1",
		Peers: []edge.Peer{
			{PubKey: meKey.pub, IP: "10.201.0.2", User: "me@example.com", All: true},
			{PubKey: limitedKey.pub, IP: "10.201.0.3", User: "op@example.com", Services: []int64{1}},
		},
		Routes: []edge.Route{
			{ID: 1, Host: "app.example.com", Upstream: "10.200.0.2:8080", Auth: "douve"},
			{ID: 2, Host: "secret.example.com", Upstream: "10.200.0.2:9000", Auth: "douve"},
		}}
	g.Apply(cfg)
	// 기기는 입구가 뜬 뒤에 연결한다 (먼저 뜨면 첫 핸드셰이크 재시도까지 5초)
	me := newPhone(t, "10.201.0.2", meKey, g.PublicKey(), port)
	limited := newPhone(t, "10.201.0.3", limitedKey, g.PublicKey(), port)
	stranger := newPhone(t, "10.201.0.4", newKeyPair(), g.PublicKey(), port) // 등록 안 된 기기
	if !g.Running() {
		t.Fatal("내부 길이 안 떴음")
	}

	// DNS: 내부 도메인은 입구 주소로, 나머지는 서버의 DNS로
	if got := aRecords(t, me.dns(t, "App.Example.com", dnsmessage.TypeA)); len(got) != 1 || got[0] != "10.201.0.1" {
		t.Fatalf("내부 도메인 DNS: %v", got)
	}
	if got := aRecords(t, me.dns(t, "app.example.com", dnsmessage.TypeAAAA)); len(got) != 0 {
		t.Fatalf("AAAA는 비어야 함: %v", got)
	}
	if got := aRecords(t, me.dns(t, "www.google.com", dnsmessage.TypeA)); len(got) != 1 || got[0] != "192.0.2.7" {
		t.Fatalf("바깥 도메인은 서버 DNS로: %v", got)
	}

	// 기기 신원 = 사용자, 로그인 화면 없이
	code, body, err := me.get("app.example.com")
	if err != nil || code != 200 || body != "app=app.example.com user=me@example.com" {
		t.Fatalf("내 기기: %d %q %v", code, body, err)
	}
	if code, body, _ := limited.get("app.example.com"); code != 200 || !strings.Contains(body, "op@example.com") {
		t.Fatalf("허락된 앱: %d %q", code, body)
	}
	if code, _, _ := limited.get("secret.example.com"); code != http.StatusForbidden {
		t.Fatalf("허락 안 된 앱: %d", code)
	}
	if code, _, _ := me.get("unknown.example.com"); code != http.StatusNotFound {
		t.Fatalf("모르는 도메인: %d", code)
	}
	// 등록 안 된 기기는 WireGuard 연결 자체가 안 된다
	if _, _, err := stranger.get("app.example.com"); err == nil {
		t.Fatal("등록 안 된 기기가 연결됨")
	}

	// 상태 확인
	var st *PeerStatus
	for _, s := range g.Status() {
		if s.PubKey == me.pub {
			s := s
			st = &s
		}
	}
	if st == nil || st.LastHandshake == 0 || st.RxBytes == 0 {
		t.Fatalf("상태: %+v", g.Status())
	}

	// 기기를 지우면 (주소 그대로 재시작 없이) 더는 못 들어온다
	cfg2 := *cfg
	cfg2.Peers = cfg.Peers[:1]
	g.Apply(&cfg2)
	if _, _, err := limited.get("app.example.com"); err == nil {
		t.Fatal("지운 기기가 계속 들어옴")
	}
	if code, _, _ := me.get("app.example.com"); code != 200 {
		t.Fatalf("남은 기기: %d", code)
	}

	// 같은 상태 디렉터리면 같은 키 (기기 설정이 계속 맞게)
	g2, _ := New(dir, proxy, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if g2.PublicKey() != g.PublicKey() {
		t.Fatal("재시작 후 키가 바뀜")
	}

	// 끄면 닫힌다
	g.Apply(nil)
	if g.Running() {
		t.Fatal("끄기")
	}
}

func TestAnswerIgnoresGarbage(t *testing.T) {
	c := &edge.Devnet{Address: "10.201.0.1", Routes: []edge.Route{{Host: "a.example.com"}}}
	for _, q := range [][]byte{nil, {1, 2, 3}, make([]byte, 12)} {
		if answer(c, q) != nil {
			t.Fatalf("이상한 질의에 답함: %v", q)
		}
	}
}
