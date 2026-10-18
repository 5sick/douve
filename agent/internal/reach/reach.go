// Package reach는 서버의 네트워크 환경 진단이다 (집 서버 외부 접속).
//
//   - STUN(RFC 5389 Binding)으로 인터넷에서 보이는 주소를 두 서버에 묻는다: 공인 IP, NAT 여부,
//     두 서버가 본 포트가 다르면 대칭 NAT(목적지마다 다른 포트 → P2P가 어렵다)
//   - 공유기(UPnP/NAT-PMP)가 알려 주는 외부 주소: 100.64/10이면 통신사 NAT(CGNAT), 사설이면 이중 공유기
//   - Probe: 다른 서버의 공인 주소:포트로 TCP 접속 시도 (외부 접속 검증의 "밖")
//
// 판단(사람이 읽는 말)은 Hub 화면이 한다. 여기서는 사실만 모은다.
package reach

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// DefaultSTUN은 공개 STUN 서버다 (서로 다른 회사 → 대칭 NAT 판별).
var DefaultSTUN = []string{"stun.l.google.com:19302", "stun.cloudflare.com:3478"}

const magicCookie = 0x2112A442

// STUNResult는 STUN으로 본 결과다.
type STUNResult struct {
	OK       bool     `json:"ok"`
	Mapped   []string `json:"mapped,omitempty"` // 서버별로 본 내 주소 (ip:port)
	PublicIP string   `json:"public_ip,omitempty"`
	NAT      string   `json:"nat"` // none | cone | symmetric | unknown
	Error    string   `json:"error,omitempty"`
}

func bindingRequest() ([]byte, [12]byte) {
	var id [12]byte
	_, _ = rand.Read(id[:])
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:], 0x0001) // Binding Request
	binary.BigEndian.PutUint16(b[2:], 0)
	binary.BigEndian.PutUint32(b[4:], magicCookie)
	copy(b[8:], id[:])
	return b, id
}

// parseResponse는 Binding Success Response에서 (XOR-)MAPPED-ADDRESS를 꺼낸다.
func parseResponse(b []byte, id [12]byte) (netip.AddrPort, error) {
	if len(b) < 20 || binary.BigEndian.Uint16(b[0:]) != 0x0101 || binary.BigEndian.Uint32(b[4:]) != magicCookie {
		return netip.AddrPort{}, errors.New("STUN 응답 형식 오류")
	}
	if [12]byte(b[8:20]) != id {
		return netip.AddrPort{}, errors.New("다른 요청의 응답")
	}
	n := int(binary.BigEndian.Uint16(b[2:]))
	if 20+n > len(b) {
		return netip.AddrPort{}, errors.New("STUN 길이 오류")
	}
	attrs := b[20 : 20+n]
	var plain netip.AddrPort
	for len(attrs) >= 4 {
		t := binary.BigEndian.Uint16(attrs[0:])
		l := int(binary.BigEndian.Uint16(attrs[2:]))
		if 4+l > len(attrs) {
			break
		}
		v := attrs[4 : 4+l]
		if (t == 0x0020 || t == 0x0001) && l >= 8 && v[1] == 0x01 { // IPv4
			port := binary.BigEndian.Uint16(v[2:])
			ip := [4]byte(v[4:8])
			if t == 0x0020 {
				port ^= magicCookie >> 16
				binary.BigEndian.PutUint32(ip[:], binary.BigEndian.Uint32(ip[:])^magicCookie)
				return netip.AddrPortFrom(netip.AddrFrom4(ip), port), nil
			}
			plain = netip.AddrPortFrom(netip.AddrFrom4(ip), port)
		}
		attrs = attrs[4+((l+3)&^3):] // 4바이트 정렬
	}
	if plain.IsValid() {
		return plain, nil
	}
	return netip.AddrPort{}, errors.New("STUN 응답에 주소 없음")
}

// query는 같은 소켓으로 한 서버에 묻는다 (최대 3번).
func query(ctx context.Context, conn *net.UDPConn, server string) (netip.AddrPort, error) {
	addr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return netip.AddrPort{}, err
	}
	req, id := bindingRequest()
	buf := make([]byte, 1500)
	for try := 0; try < 3 && ctx.Err() == nil; try++ {
		if _, err := conn.WriteToUDP(req, addr); err != nil {
			return netip.AddrPort{}, err
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				break // 시간 초과 → 다시 보냄
			}
			if !from.IP.Equal(addr.IP) {
				continue
			}
			if ap, err := parseResponse(buf[:n], id); err == nil {
				return ap, nil
			}
		}
	}
	return netip.AddrPort{}, fmt.Errorf("%s 응답 없음 (UDP가 막혔을 수 있음)", server)
}

// STUN은 servers에 차례로 물어 NAT를 판단한다. localIP는 인터넷으로 나가는 인터페이스 주소.
func STUN(ctx context.Context, servers []string, localIP string) STUNResult {
	r := STUNResult{NAT: "unknown"}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		r.Error = err.Error()
		return r
	}
	defer conn.Close()
	var got []netip.AddrPort
	var lastErr error
	for _, s := range servers {
		ap, err := query(ctx, conn, s)
		if err != nil {
			lastErr = err
			continue
		}
		got = append(got, ap)
		r.Mapped = append(r.Mapped, ap.String())
	}
	if len(got) == 0 {
		if lastErr != nil {
			r.Error = lastErr.Error()
		}
		return r
	}
	r.OK = true
	r.PublicIP = got[0].Addr().String()
	switch {
	case r.PublicIP == localIP:
		r.NAT = "none" // 인터페이스에 공인 IP가 바로 있다
	case len(got) >= 2 && (got[0] != got[1]):
		r.NAT = "symmetric" // 목적지마다 다른 주소·포트
	case len(got) >= 2:
		r.NAT = "cone"
	}
	return r
}

// OutboundIP는 인터넷으로 나갈 때 쓰는 내 주소다 (실제로 보내지 않는다).
func OutboundIP() string {
	c, err := net.Dial("udp4", "1.1.1.1:53")
	if err != nil {
		return ""
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

// ProbeResult는 TCP 접속 시도 결과다.
type ProbeResult struct {
	Port  int    `json:"port"`
	Open  bool   `json:"open"`
	MS    int64  `json:"ms,omitempty"`
	Error string `json:"error,omitempty"` // refused | timeout | 기타
}

// Probe는 host의 포트들로 TCP 접속을 시도한다 (외부 접속 검증).
func Probe(ctx context.Context, host string, ports []int, timeout time.Duration) []ProbeResult {
	out := make([]ProbeResult, len(ports))
	done := make(chan struct{}, len(ports))
	for i, p := range ports {
		go func(i, p int) {
			defer func() { done <- struct{}{} }()
			start := time.Now()
			d := net.Dialer{Timeout: timeout}
			c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(p)))
			r := ProbeResult{Port: p}
			if err == nil {
				c.Close()
				r.Open, r.MS = true, time.Since(start).Milliseconds()
			} else {
				var ne net.Error
				switch {
				case errors.As(err, &ne) && ne.Timeout():
					r.Error = "timeout" // 방화벽이 버림
				case isRefused(err):
					r.Error = "refused" // 닿았지만 듣는 프로그램 없음
				default:
					r.Error = "unreachable"
				}
			}
			out[i] = r
		}(i, p)
	}
	for range ports {
		<-done
	}
	return out
}
