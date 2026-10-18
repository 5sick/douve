package devnet

import (
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/5sick/douve/agent/internal/edge"
)

// 기기의 DNS: 내부 길에 있는 도메인은 입구 내부 주소(A)로 답하고, 나머지는 서버의 DNS에 그대로 넘긴다.
// 기기는 연결돼 있는 동안 이 DNS를 쓴다 (WireGuard 설정의 DNS =).

const dnsTTL = 60

// answer는 내부 길 도메인에 대한 응답을 만든다. 내부 도메인이 아니면 nil (넘김).
func answer(c *edge.Devnet, query []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil || h.Response {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
	if q.Class != dnsmessage.ClassINET || !c.HasHost(name) {
		return nil
	}
	addr, err := netip.ParseAddr(c.Address)
	if err != nil {
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true,
		RecursionDesired: h.RecursionDesired, RecursionAvailable: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(q)
	_ = b.StartAnswers()
	if q.Type == dnsmessage.TypeA {
		_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: dnsTTL},
			dnsmessage.AResource{A: addr.As4()})
	}
	// AAAA 등 다른 종류: 답 없이 NOERROR (기기가 A로 연결하게)
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

func (g *Gateway) serveDNS(pc net.PacketConn, stop chan struct{}) {
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-stop:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		q := append([]byte(nil), buf[:n]...)
		c := g.cfg.Load()
		if c == nil {
			continue
		}
		if a := answer(c, q); a != nil {
			_, _ = pc.WriteTo(a, from)
			continue
		}
		go g.forward(pc, from, q)
	}
}

// forward는 질의를 서버의 DNS로 넘기고 답을 그대로 돌려준다.
func (g *Gateway) forward(pc net.PacketConn, to net.Addr, q []byte) {
	up, err := net.DialTimeout("udp", g.Upstream(), 3*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	_ = up.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := up.Write(q); err != nil {
		return
	}
	buf := make([]byte, 4096)
	n, err := up.Read(buf)
	if err != nil {
		return
	}
	_, _ = pc.WriteTo(buf[:n], to)
}
