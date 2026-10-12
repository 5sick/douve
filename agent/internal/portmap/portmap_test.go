package portmap

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// 가짜 NAT-PMP 공유기: 외부 주소 ext, 매핑을 기록한다. taken 포트는 다른 외부 포트를 준다.
func fakeNATPMP(t *testing.T, ext net.IP, taken int) (string, *sync.Map) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	maps := &sync.Map{}
	go func() {
		buf := make([]byte, 64)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			switch {
			case n == 2 && buf[1] == 0:
				r := make([]byte, 12)
				r[1] = 128
				copy(r[8:], ext.To4())
				pc.WriteTo(r, addr)
			case n == 12 && (buf[1] == 1 || buf[1] == 2):
				port := binary.BigEndian.Uint16(buf[4:6])
				life := binary.BigEndian.Uint32(buf[8:12])
				r := make([]byte, 16)
				r[1] = 128 + buf[1]
				copy(r[8:10], buf[4:6])
				ext := port
				if int(port) == taken {
					ext = port + 1
				}
				binary.BigEndian.PutUint16(r[10:12], ext)
				binary.BigEndian.PutUint32(r[12:16], life)
				key := fmt.Sprintf("%d/%d", buf[1], port)
				if life == 0 {
					maps.Delete(key)
				} else {
					maps.Store(key, life)
				}
				pc.WriteTo(r, addr)
			}
		}
	}()
	return pc.LocalAddr().String(), maps
}

func TestNATPMP(t *testing.T) {
	addr, maps := fakeNATPMP(t, net.ParseIP("203.0.113.9"), 0)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	gw, err := Discover(ctx, Options{Gateway: net.ParseIP("127.0.0.1"), NATPMP: addr, SSDP: "127.0.0.1:9", Timeout: time.Second})
	if err != nil || gw.Kind() != "natpmp" {
		t.Fatalf("%v %v", gw, err)
	}
	ip, err := gw.ExternalIP(ctx)
	if err != nil || ip.String() != "203.0.113.9" {
		t.Fatalf("%v %v", ip, err)
	}
	if err := gw.Add(ctx, Mapping{"tcp", 443}, nil, time.Hour, "Douve"); err != nil {
		t.Fatal(err)
	}
	if v, ok := maps.Load("2/443"); !ok || v.(uint32) != 3600 {
		t.Fatalf("매핑 없음 %v", v)
	}
	if err := gw.Delete(ctx, Mapping{"tcp", 443}); err != nil {
		t.Fatal(err)
	}
	if _, ok := maps.Load("2/443"); ok {
		t.Fatal("삭제 안 됨")
	}
}

func TestNATPMPPortTaken(t *testing.T) {
	addr, maps := fakeNATPMP(t, net.ParseIP("203.0.113.9"), 80)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	gw := &natPMP{addr: addr}
	err := gw.Add(ctx, Mapping{"tcp", 80}, nil, time.Hour, "Douve")
	if err == nil || !strings.Contains(err.Error(), "다른 기기") {
		t.Fatalf("외부 포트가 다르면 실패해야 함: %v", err)
	}
	if _, ok := maps.Load("2/80"); ok {
		t.Fatal("잘못 받은 매핑은 되돌려야 함")
	}
}

// 가짜 UPnP 공유기: SSDP 응답 + 기기 설명 + SOAP
func fakeUPnP(t *testing.T, onlyPermanent bool) (string, *sync.Map) {
	maps := &sync.Map{}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/desc.xml", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><deviceList><device>
<deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><deviceList><device>
<serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<controlURL>/ctl/IPConn</controlURL></service></serviceList></device></deviceList></device></deviceList></device></root>`)
	})
	mux.HandleFunc("/ctl/IPConn", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body := string(b)
		action := r.Header.Get("SOAPAction")
		field := func(name string) string {
			i := strings.Index(body, "<"+name+">")
			j := strings.Index(body, "</"+name+">")
			if i < 0 || j < 0 {
				return ""
			}
			return body[i+len(name)+2 : j]
		}
		fault := func(code int) {
			w.WriteHeader(500)
			fmt.Fprintf(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><detail><UPnPError><errorCode>%d</errorCode><errorDescription>x</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`, code)
		}
		switch {
		case strings.HasSuffix(action, `#GetExternalIPAddress"`):
			fmt.Fprint(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewExternalIPAddress>100.70.1.2</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`)
		case strings.HasSuffix(action, `#AddPortMapping"`):
			if onlyPermanent && field("NewLeaseDuration") != "0" {
				fault(725)
				return
			}
			maps.Store(field("NewProtocol")+"/"+field("NewExternalPort"), field("NewInternalClient")+" "+field("NewPortMappingDescription"))
			fmt.Fprint(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body></s:Body></s:Envelope>`)
		case strings.HasSuffix(action, `#DeletePortMapping"`):
			maps.Delete(field("NewProtocol") + "/" + field("NewExternalPort"))
			fmt.Fprint(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body></s:Body></s:Envelope>`)
		default:
			fault(401)
		}
	})
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if strings.HasPrefix(string(buf[:n]), "M-SEARCH") {
				pc.WriteTo([]byte("HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLOCATION: "+srv.URL+"/desc.xml\r\n\r\n"), addr)
			}
		}
	}()
	return pc.LocalAddr().String(), maps
}

func TestUPnP(t *testing.T) {
	for _, perm := range []bool{false, true} {
		ssdp, maps := fakeUPnP(t, perm)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		// NAT-PMP는 닫힌 포트 → UPnP로 넘어간다
		gw, err := Discover(ctx, Options{Gateway: net.ParseIP("127.0.0.1"), NATPMP: "127.0.0.1:9", SSDP: ssdp, Timeout: 2 * time.Second})
		if err != nil || gw.Kind() != "upnp" {
			t.Fatalf("perm=%v: %v %v", perm, gw, err)
		}
		ip, err := gw.ExternalIP(ctx)
		if err != nil || ip.String() != "100.70.1.2" || !IsCGNAT(ip) {
			t.Fatalf("외부 주소 %v %v (100.64/10은 CGNAT)", ip, err)
		}
		if err := gw.Add(ctx, Mapping{"tcp", 80}, net.ParseIP("192.168.0.10"), time.Hour, "Douve"); err != nil {
			t.Fatalf("perm=%v: %v", perm, err)
		}
		if v, ok := maps.Load("TCP/80"); !ok || v.(string) != "192.168.0.10 Douve" {
			t.Fatalf("매핑 %v", v)
		}
		if err := gw.Delete(ctx, Mapping{"tcp", 80}); err != nil {
			t.Fatal(err)
		}
		if _, ok := maps.Load("TCP/80"); ok {
			t.Fatal("삭제 안 됨")
		}
		cancel()
	}
}

func TestNoGateway(t *testing.T) {
	ctx := context.Background()
	_, err := Discover(ctx, Options{Gateway: net.ParseIP("127.0.0.1"), NATPMP: "127.0.0.1:9", SSDP: "127.0.0.1:9", Timeout: 600 * time.Millisecond})
	if err != ErrNoGateway {
		t.Fatal(err)
	}
}

func TestManagerAllowListAndRelease(t *testing.T) {
	addr, maps := fakeNATPMP(t, net.ParseIP("203.0.113.9"), 0)
	var mu sync.Mutex
	var reports []Status
	m := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)), func(s Status) {
		mu.Lock()
		reports = append(reports, s)
		mu.Unlock()
	})
	m.Opts = Options{Gateway: net.ParseIP("127.0.0.1"), NATPMP: addr, SSDP: "127.0.0.1:9", Timeout: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	last := func() Status {
		for i := 0; i < 50; i++ {
			mu.Lock()
			n := len(reports)
			var s Status
			if n > 0 {
				s = reports[n-1]
			}
			mu.Unlock()
			if n > 0 {
				return s
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("보고 없음")
		return Status{}
	}
	m.Set([]Mapping{{"tcp", 443}, {"tcp", 22}, {"tcp", 443}}) // 22는 허용 안 됨, 중복 제거
	s := last()
	if s.Gateway != "natpmp" || s.ExternalIP != "203.0.113.9" || s.CGNAT || len(s.Mappings) != 1 || !s.Mappings[0].OK {
		t.Fatalf("%+v", s)
	}
	if _, ok := maps.Load("2/22"); ok {
		t.Fatal("허용하지 않은 포트를 열었음")
	}
	mu.Lock()
	reports = nil
	mu.Unlock()
	m.Set(nil) // 끄면 닫는다
	last()
	if _, ok := maps.Load("2/443"); ok {
		t.Fatal("끈 포트가 남아 있음")
	}
	cancel()
	<-done
}

func TestDefaultGateway(t *testing.T) {
	p := filepath.Join(t.TempDir(), "route")
	os.WriteFile(p, []byte("Iface\tDestination\tGateway \tFlags\nwg0\t0000C80A\t00000000\t0001\neth0\t00000000\t0100A8C0\t0003\n"), 0o644)
	ip, err := DefaultGateway(p)
	if err != nil || ip.String() != "192.168.0.1" {
		t.Fatalf("%v %v", ip, err)
	}
}
