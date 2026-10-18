package reach

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

// fakeSTUN은 받은 요청에 mapped(nil이면 보낸 쪽 주소 그대로)를 XOR-MAPPED-ADDRESS로 답한다.
func fakeSTUN(t *testing.T, mapped func(from *net.UDPAddr) netip.AddrPort) string {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 20 {
				continue
			}
			ap := netip.AddrPortFrom(netip.AddrFrom4([4]byte(from.IP.To4())), uint16(from.Port))
			if mapped != nil {
				ap = mapped(from)
			}
			resp := make([]byte, 32)
			binary.BigEndian.PutUint16(resp[0:], 0x0101)
			binary.BigEndian.PutUint16(resp[2:], 12)
			copy(resp[4:20], buf[4:20]) // cookie + transaction id
			binary.BigEndian.PutUint16(resp[20:], 0x0020)
			binary.BigEndian.PutUint16(resp[22:], 8)
			resp[25] = 0x01
			binary.BigEndian.PutUint16(resp[26:], ap.Port()^(magicCookie>>16))
			ip := ap.Addr().As4()
			binary.BigEndian.PutUint32(resp[28:], binary.BigEndian.Uint32(ip[:])^magicCookie)
			_, _ = c.WriteToUDP(resp, from)
		}
	}()
	return c.LocalAddr().String()
}

func TestSTUNNAT(t *testing.T) {
	ctx := context.Background()
	pub := func(port uint16) func(*net.UDPAddr) netip.AddrPort {
		return func(*net.UDPAddr) netip.AddrPort { return netip.MustParseAddrPort("203.0.113.5:" + itoa(port)) }
	}
	// 공유기 뒤, 두 서버가 같은 주소를 본다 → 일반 NAT
	r := STUN(ctx, []string{fakeSTUN(t, pub(40000)), fakeSTUN(t, pub(40000))}, "192.168.0.10")
	if !r.OK || r.PublicIP != "203.0.113.5" || r.NAT != "cone" || len(r.Mapped) != 2 {
		t.Fatalf("cone: %+v", r)
	}
	// 서버마다 다른 포트 → 대칭 NAT
	r = STUN(ctx, []string{fakeSTUN(t, pub(40000)), fakeSTUN(t, pub(40001))}, "192.168.0.10")
	if r.NAT != "symmetric" {
		t.Fatalf("symmetric: %+v", r)
	}
	// 인터페이스 주소 = 공인 주소 → NAT 없음
	r = STUN(ctx, []string{fakeSTUN(t, pub(40000))}, "203.0.113.5")
	if r.NAT != "none" {
		t.Fatalf("none: %+v", r)
	}
	// 응답 없음 → 실패 (UDP 막힘)
	dead, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	addr := dead.LocalAddr().String()
	dead.Close()
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	r = STUN(cctx, []string{addr}, "192.168.0.10")
	if r.OK || r.Error == "" || r.NAT != "unknown" {
		t.Fatalf("응답 없음: %+v", r)
	}
}

func itoa(p uint16) string {
	b := []byte{}
	for p >= 10 {
		b = append([]byte{byte('0' + p%10)}, b...)
		p /= 10
	}
	return string(append([]byte{byte('0' + p)}, b...))
}

func TestParseResponseRejects(t *testing.T) {
	_, id := bindingRequest()
	for _, b := range [][]byte{nil, make([]byte, 19), make([]byte, 20)} {
		if _, err := parseResponse(b, id); err == nil {
			t.Fatal("잘못된 응답 통과")
		}
	}
	// 다른 트랜잭션의 응답 (스푸핑)
	ok := make([]byte, 20)
	binary.BigEndian.PutUint16(ok[0:], 0x0101)
	binary.BigEndian.PutUint32(ok[4:], magicCookie)
	if _, err := parseResponse(ok, id); err == nil {
		t.Fatal("다른 요청의 응답 통과")
	}
}

func FuzzParseResponse(f *testing.F) {
	f.Add(make([]byte, 32))
	f.Fuzz(func(t *testing.T, b []byte) {
		var id [12]byte
		if len(b) >= 20 {
			copy(id[:], b[8:20])
		}
		_, _ = parseResponse(b, id)
	})
}

func TestProbe(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	open := l.Addr().(*net.TCPAddr).Port
	cl, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := cl.Addr().(*net.TCPAddr).Port
	cl.Close()
	rs := Probe(context.Background(), "127.0.0.1", []int{open, closed}, time.Second)
	if !rs[0].Open || rs[1].Open || rs[1].Error != "refused" {
		t.Fatalf("%+v", rs)
	}
}
