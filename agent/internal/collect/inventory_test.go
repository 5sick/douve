package collect

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFailedUnits(t *testing.T) {
	got := parseFailedUnits("● nginx.service loaded failed failed The nginx\nfoo.timer loaded failed failed x\n\n")
	if len(got) != 2 || got[0] != "nginx.service" || got[1] != "foo.timer" {
		t.Fatalf("%v", got)
	}
}

func TestParseTimerTriggered(t *testing.T) {
	got := parseTimerTriggered("Id=dnf-makecache.service\nTriggeredBy=dnf-makecache.timer\n\n" +
		"Id=sshd.service\nTriggeredBy=\n\nId=ssh.service\nTriggeredBy=ssh.socket\n\n" +
		"TriggeredBy=a.timer b.path\nId=both.service\n")
	if len(got) != 2 || got[0] != "dnf-makecache.service" || got[1] != "both.service" {
		t.Fatalf("%v", got)
	}
}

func TestParseWGDump(t *testing.T) {
	dump := "wg0\tPRIV\tPUB\t51820\toff\n" +
		"wg0\tpeerA=\t(none)\t1.2.3.4:51820\t10.200.0.1/32\t1700000000\t100\t200\t25\n" +
		"wg0\tpeerB=\t(none)\t(none)\t10.200.0.3/32\t0\t0\t0\toff\n"
	p := parseWGDump(dump)
	if len(p) != 2 || p[0].Endpoint != "1.2.3.4:51820" || p[0].LastHandshake != 1700000000 || p[1].Endpoint != "" {
		t.Fatalf("%+v", p)
	}
}

func TestDecodeAddr(t *testing.T) {
	cases := map[string]string{
		"0100007F:1F90":                         "127.0.0.1:8080",
		"00000000:0016":                         "0.0.0.0:22",
		"0200C80A:21FC":                         "10.200.0.2:8700",
		"00000000000000000000000000000000:01BB": ":::443",
		"00000000000000000000000001000000:0050": "::1:80",
	}
	for in, want := range cases {
		a, p, ok := decodeAddr(in)
		got := a + ":" + itoa(p)
		if !ok || got != want {
			t.Errorf("%s → %s (want %s)", in, got, want)
		}
	}
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func TestListeningPortsFindsOwnSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	for _, p := range listeningPorts("/proc") {
		if p.Port == port && p.Address == "127.0.0.1" {
			if p.Process == "" {
				t.Error("프로세스 이름을 못 찾음")
			}
			return
		}
	}
	t.Fatalf("포트 %d를 못 찾음", port)
}

func TestDockerContainersViaFakeSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[
		 {"Names":["/web"],"Image":"nginx","State":"running","Status":"Up 2 hours (healthy)","Ports":[{"IP":"0.0.0.0","PrivatePort":80,"PublicPort":8080,"Type":"tcp"},{"IP":"::","PrivatePort":80,"PublicPort":8080,"Type":"tcp"},{"IP":"127.0.0.1","PrivatePort":81,"PublicPort":8081,"Type":"tcp"},{"PublicPort":5353,"Type":"udp"},{"PrivatePort":9000}]},
		 {"Names":["/crash"],"Image":"x","State":"exited","Status":"Exited (137) 5 minutes ago","Ports":[]},
		 {"Names":["/db"],"Image":"mariadb","State":"running","Status":"Up 1 minute (unhealthy)","Ports":[]}]`))
	})}
	go srv.Serve(ln)
	defer srv.Close()
	cs, err := dockerContainers(context.Background(), sock)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 3 || cs[0].Name != "crash" || cs[0].ExitCode != 137 || cs[1].Health != "unhealthy" ||
		cs[2].Health != "healthy" || len(cs[2].Ports) != 2 {
		t.Fatalf("%+v", cs)
	}
	b := cs[2].Bindings
	if len(b) != 3 || b[0] != (Binding{IP: "0.0.0.0", Port: 8080, PrivatePort: 80}) || b[1].IP != "::" ||
		b[2] != (Binding{IP: "127.0.0.1", Port: 8081, PrivatePort: 81}) {
		t.Fatalf("bindings %+v", b)
	}
}

func TestDetectCloud(t *testing.T) {
	cases := []struct {
		files map[string]string
		want  string
	}{
		{map[string]string{"sys_vendor": "QEMU", "chassis_asset_tag": "OracleCloud.com"}, "oci"},
		{map[string]string{"sys_vendor": "Amazon EC2", "product_name": "t3.micro"}, "aws"},
		{map[string]string{"sys_vendor": "Google", "product_name": "Google Compute Engine"}, "gcp"},
		{map[string]string{"sys_vendor": "Hetzner", "product_name": "vServer"}, "hetzner"},
		{map[string]string{"sys_vendor": "Microsoft Corporation", "chassis_asset_tag": "7783-7084-3265-9085-8269-3286-77"}, "azure"},
		{map[string]string{"sys_vendor": "Microsoft Corporation", "product_name": "Virtual Machine"}, ""}, // 집의 Hyper-V
		{map[string]string{"sys_vendor": "ASUSTeK COMPUTER INC."}, ""},
		{map[string]string{}, ""},
	}
	for _, c := range cases {
		d := t.TempDir()
		for k, v := range c.files {
			os.WriteFile(filepath.Join(d, k), []byte(v+"\n"), 0o644)
		}
		if got := DetectCloud(d); got != c.want {
			t.Fatalf("%v → %q, want %q", c.files, got, c.want)
		}
	}
}

func TestExposedListeners(t *testing.T) {
	// 가짜 /proc: 0.0.0.0:22, 127.0.0.1:5432, 10.200.0.2:8080(WireGuard), 203.0.113.9:9000(공인)
	proc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1\n" +
		"   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1\n" +
		"   2: 0200C80A:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1003 1\n" +
		"   3: 097100CB:2328 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1004 1\n"
	if err := os.WriteFile(filepath.Join(proc, "net", "tcp"), []byte(tcp), 0o644); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(ExposedListeners(proc), ",")
	if got != "22,9000" && got != "9000,22" {
		t.Fatalf("인터넷 쪽 포트: %q", got)
	}
}
