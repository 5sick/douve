// probe는 시험용 기기다 (tests/e2e/devnet_flow.sh): Douve가 준 WireGuard 설정 파일로 연결하고, 그 설정의
// DNS로 이름을 풀어 HTTPS로 요청한 뒤 "코드 본문"을 출력한다. 배포에는 들어가지 않는다.
//
//	go build -o probe ./internal/devnet/probe
//	probe -conf device.conf -url https://app.example.test/ [-endpoint 127.0.0.1:51821] [-timeout 5s]
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func hexKey(b64 string) string {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(b) != 32 {
		fail("잘못된 키: " + b64)
	}
	return hex.EncodeToString(b)
}

func fail(msg string) {
	fmt.Println("ERR", msg)
	os.Exit(1)
}

func main() {
	confPath := flag.String("conf", "", "WireGuard 설정 파일")
	target := flag.String("url", "", "요청할 주소")
	endpoint := flag.String("endpoint", "", "설정의 Endpoint 대신 (시험용)")
	timeout := flag.Duration("timeout", 5*time.Second, "제한 시간")
	flag.Parse()

	f, err := os.Open(*confPath)
	if err != nil {
		fail(err.Error())
	}
	kv := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok {
			kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	f.Close()
	addr := netip.MustParsePrefix(kv["Address"]).Addr()
	dns := netip.MustParseAddr(kv["DNS"])
	ep := kv["Endpoint"]
	if *endpoint != "" {
		ep = *endpoint
	}
	host, port, _ := net.SplitHostPort(ep)
	if ips, err := net.LookupHost(host); err == nil && len(ips) > 0 {
		host = ips[0]
	}
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, 1420)
	if err != nil {
		fail(err.Error())
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=%s\npersistent_keepalive_interval=25\n",
		hexKey(kv["PrivateKey"]), hexKey(kv["PublicKey"]), net.JoinHostPort(host, port), kv["AllowedIPs"])
	if err := dev.IpcSet(cfg); err != nil {
		fail(err.Error())
	}
	if err := dev.Up(); err != nil {
		fail(err.Error())
	}
	defer dev.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	// 기기처럼: 설정의 DNS(입구)로 A 레코드를 묻는다
	resolve := func(name string) (string, error) {
		c, err := tnet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(dns, 53))
		if err != nil {
			return "", err
		}
		defer c.Close()
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
		_ = b.StartQuestions()
		_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
		q, _ := b.Finish()
		dl, _ := ctx.Deadline()
		_ = c.SetDeadline(dl)
		for {
			if _, err := c.Write(q); err != nil {
				return "", err
			}
			buf := make([]byte, 1500)
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			n, err := c.Read(buf)
			if err != nil {
				if ctx.Err() != nil {
					return "", fmt.Errorf("DNS 응답 없음")
				}
				continue // 첫 핸드셰이크 중
			}
			var p dnsmessage.Parser
			if _, err := p.Start(buf[:n]); err != nil {
				return "", err
			}
			_ = p.SkipAllQuestions()
			for {
				h, err := p.AnswerHeader()
				if err != nil {
					return "", fmt.Errorf("A 레코드 없음")
				}
				if h.Type == dnsmessage.TypeA {
					a, _ := p.AResource()
					return netip.AddrFrom4(a.A).String(), nil
				}
				_ = p.SkipAnswer()
			}
		}
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, hostport string) (net.Conn, error) {
			h, p, _ := net.SplitHostPort(hostport)
			ip, err := resolve(h)
			if os.Getenv("PROBE_DEBUG") != "" {
				fmt.Fprintln(os.Stderr, "resolve", h, ip, err)
			}
			if err != nil {
				return nil, err
			}
			return tnet.DialContext(ctx, network, net.JoinHostPort(ip, p))
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 시험용 자체 서명 인증서
	}
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, *target, nil)
	resp, err := client.Do(req)
	if err != nil {
		fail(err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	fmt.Println(resp.StatusCode, strings.TrimSpace(string(body)))
}
