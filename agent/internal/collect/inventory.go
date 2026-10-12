package collect

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Inventory는 Hub에 60초마다 보내는 구성 정보다.
type Inventory struct {
	Type        string      `json:"type"`
	System      System      `json:"system"`
	FailedUnits []string    `json:"failed_units"`
	Containers  []Container `json:"containers"`
	WireGuard   []WGPeer    `json:"wireguard"`
	Ports       []Port      `json:"ports"`
	// 웹 터미널로 열 수 있는 계정
	TerminalUsers []string `json:"terminal_users"`
}

type System struct {
	OS       string `json:"os"`
	Kernel   string `json:"kernel"`
	Arch     string `json:"arch"`
	CPUs     int    `json:"cpus"`
	Hostname string `json:"hostname"`
	Docker   bool   `json:"docker"`
	// 클라우드 (oci, aws, gcp, azure, hetzner, digitalocean, vultr, linode, scaleway), 아니면 빈 값
	Cloud string `json:"cloud,omitempty"`
	// 물리·WireGuard 인터페이스 주소 (Hub가 메시 주소·업스트림을 정할 때 사용)
	Addresses []Address `json:"addresses"`
}

type Address struct {
	Interface string `json:"interface"`
	CIDR      string `json:"cidr"`
}

type Container struct {
	Name     string `json:"name"`
	Image    string `json:"image"`
	State    string `json:"state"`
	Status   string `json:"status"`
	Health   string `json:"health,omitempty"`
	ExitCode int    `json:"exit_code"`
	Ports    []int  `json:"ports,omitempty"` // 호스트에 공개된 포트
	// 공개된 포트별 바인드 주소·컨테이너 안 포트 (앱 공개 제안용)
	Bindings []Binding `json:"bindings,omitempty"`
}

type Binding struct {
	IP          string `json:"ip"` // 0.0.0.0, ::, 127.0.0.1 …
	Port        int    `json:"port"`
	PrivatePort int    `json:"private_port"`
}

type WGPeer struct {
	Interface     string `json:"interface"`
	PublicKey     string `json:"public_key"`
	Endpoint      string `json:"endpoint"`
	AllowedIPs    string `json:"allowed_ips"`
	LastHandshake int64  `json:"last_handshake"` // 유닉스 초, 0 = 없음
	RX            uint64 `json:"rx"`
	TX            uint64 `json:"tx"`
}

// Port는 LISTEN 중인 TCP 소켓이다 (서비스 자동 탐지용).
type Port struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Process string `json:"process,omitempty"`
}

// InventoryCollector는 명령 실행 경로를 바꿀 수 있게 해 테스트한다.
type InventoryCollector struct {
	Proc          string
	DockerSocket  string
	TerminalUsers func() []string
}

func NewInventoryCollector() *InventoryCollector {
	return &InventoryCollector{Proc: "/proc", DockerSocket: "/var/run/docker.sock"}
}

func (c *InventoryCollector) Collect(ctx context.Context) Inventory {
	inv := Inventory{Type: "inventory", FailedUnits: []string{}, Containers: []Container{},
		WireGuard: []WGPeer{}, Ports: []Port{}}
	inv.System = readSystem(c.Proc)
	inv.FailedUnits = failedUnits(ctx)
	if cs, err := dockerContainers(ctx, c.DockerSocket); err == nil {
		inv.Containers = cs
		inv.System.Docker = true
	}
	inv.WireGuard = wgPeers(ctx)
	inv.Ports = listeningPorts(c.Proc)
	inv.TerminalUsers = []string{}
	if c.TerminalUsers != nil {
		if u := c.TerminalUsers(); u != nil {
			inv.TerminalUsers = u
		}
	}
	return inv
}

// DMIDir는 시험에서 바꾼다.
var DMIDir = "/sys/class/dmi/id"

// DetectCloud는 DMI 정보로 클라우드 업체를 알아낸다 (방화벽 안내용).
func DetectCloud(dir string) string {
	read := func(f string) string {
		b, _ := os.ReadFile(filepath.Join(dir, f))
		return strings.ToLower(strings.TrimSpace(string(b)))
	}
	vendor, product, bios, tag := read("sys_vendor"), read("product_name"), read("bios_vendor"), read("chassis_asset_tag")
	all := vendor + " " + product + " " + bios + " " + tag
	switch {
	case strings.Contains(tag, "oraclecloud"):
		return "oci"
	case strings.Contains(all, "amazon ec2"):
		return "aws"
	case strings.Contains(product, "google compute engine") || vendor == "google":
		return "gcp"
	case vendor == "microsoft corporation" && strings.Contains(tag, "7783-7084-3265-9085-8269-3286-77"):
		return "azure" // Azure VM의 고정 자산 태그
	case strings.Contains(vendor, "hetzner"):
		return "hetzner"
	case strings.Contains(vendor, "digitalocean"):
		return "digitalocean"
	case strings.Contains(vendor, "vultr"):
		return "vultr"
	case strings.Contains(vendor, "linode") || strings.Contains(vendor, "akamai"):
		return "linode"
	case strings.Contains(vendor, "scaleway"):
		return "scaleway"
	}
	return ""
}

func readSystem(proc string) System {
	s := System{Arch: runtime.GOARCH, CPUs: runtime.NumCPU(), Cloud: DetectCloud(DMIDir)}
	s.Hostname, _ = os.Hostname()
	if b, err := os.ReadFile(filepath.Join(proc, "sys/kernel/osrelease")); err == nil {
		s.Kernel = strings.TrimSpace(string(b))
	}
	s.OS = osPrettyName()
	s.Addresses = interfaceAddresses()
	return s
}

func interfaceAddresses() []Address {
	out := []Address{}
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || virtualIface(i.Name) {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() {
				out = append(out, Address{Interface: i.Name, CIDR: ipn.String()})
			}
		}
	}
	return out
}

func osPrettyName() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return runtime.GOOS
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return runtime.GOOS
}

func failedUnits(ctx context.Context) []string {
	out := []string{}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "systemctl", "list-units", "--state=failed", "--plain",
		"--no-legend", "--no-pager").Output()
	if err != nil {
		return out
	}
	return parseFailedUnits(string(b))
}

func parseFailedUnits(s string) []string {
	out := []string{}
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := strings.TrimPrefix(fields[0], "●")
		if name == "" && len(fields) > 1 {
			name = fields[1]
		}
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

var exitRe = regexp.MustCompile(`^Exited \((-?\d+)\)`)

func dockerContainers(ctx context.Context, socket string) ([]Container, error) {
	if _, err := os.Stat(socket); err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/json?all=1", nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker API HTTP %d", resp.StatusCode)
	}
	var raw []struct {
		Names  []string
		Image  string
		State  string
		Status string
		Ports  []struct {
			IP          string
			PrivatePort int
			PublicPort  int
			Type        string
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	out := make([]Container, 0, len(raw))
	for _, r := range raw {
		c := Container{Image: r.Image, State: r.State, Status: r.Status}
		if len(r.Names) > 0 {
			c.Name = strings.TrimPrefix(r.Names[0], "/")
		}
		switch {
		case strings.Contains(r.Status, "(unhealthy)"):
			c.Health = "unhealthy"
		case strings.Contains(r.Status, "(healthy)"):
			c.Health = "healthy"
		case strings.Contains(r.Status, "(health: starting)"):
			c.Health = "starting"
		}
		if m := exitRe.FindStringSubmatch(r.Status); m != nil {
			c.ExitCode, _ = strconv.Atoi(m[1])
		}
		seen := map[int]bool{}
		seenB := map[string]bool{}
		for _, p := range r.Ports {
			if p.PublicPort <= 0 || (p.Type != "" && p.Type != "tcp") {
				continue
			}
			if !seen[p.PublicPort] {
				seen[p.PublicPort] = true
				c.Ports = append(c.Ports, p.PublicPort)
			}
			k := p.IP + "|" + strconv.Itoa(p.PublicPort)
			if !seenB[k] {
				seenB[k] = true
				c.Bindings = append(c.Bindings, Binding{IP: p.IP, Port: p.PublicPort, PrivatePort: p.PrivatePort})
			}
		}
		sort.Ints(c.Ports)
		sort.Slice(c.Bindings, func(i, j int) bool {
			if c.Bindings[i].Port != c.Bindings[j].Port {
				return c.Bindings[i].Port < c.Bindings[j].Port
			}
			return c.Bindings[i].IP < c.Bindings[j].IP
		})
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func wgPeers(ctx context.Context) []WGPeer {
	out := []WGPeer{}
	if _, err := exec.LookPath("wg"); err != nil {
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "wg", "show", "all", "dump").Output()
	if err != nil {
		return out
	}
	return parseWGDump(string(b))
}

// parseWGDump: 인터페이스 줄은 필드 5개, 피어 줄은 9개 (탭 구분).
func parseWGDump(s string) []WGPeer {
	out := []WGPeer{}
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 9 {
			continue
		}
		p := WGPeer{Interface: f[0], PublicKey: f[1], Endpoint: f[3], AllowedIPs: f[4]}
		if p.Endpoint == "(none)" {
			p.Endpoint = ""
		}
		p.LastHandshake, _ = strconv.ParseInt(f[5], 10, 64)
		p.RX, _ = strconv.ParseUint(f[6], 10, 64)
		p.TX, _ = strconv.ParseUint(f[7], 10, 64)
		out = append(out, p)
	}
	return out
}

// PublicListeners는 루프백이 아닌 주소에서 LISTEN 중인 "포트 프로세스" 목록이다 (보안 감시용).
func PublicListeners(proc string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range listeningPorts(proc) {
		// 루프백과 Agent 자신(입구 80/443 등 의도한 포트)은 제외
		if strings.HasPrefix(p.Address, "127.") || p.Address == "::1" || p.Process == "douve-agent" {
			continue
		}
		k := strconv.Itoa(p.Port) + " " + p.Process
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

// listeningPorts는 /proc/net/tcp{,6}의 LISTEN 소켓과 소유 프로세스 이름을 찾는다.
func listeningPorts(proc string) []Port {
	inodes := map[string]Port{}
	for _, name := range []string{"net/tcp", "net/tcp6"} {
		parseProcNetTCP(filepath.Join(proc, name), inodes)
	}
	if len(inodes) > 0 {
		attachProcesses(proc, inodes)
	}
	seen := map[string]bool{}
	out := []Port{}
	for _, p := range inodes {
		key := p.Address + ":" + strconv.Itoa(p.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Address < out[j].Address
	})
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

func parseProcNetTCP(path string, out map[string]Port) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // 헤더
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 || fields[3] != "0A" { // 0A = LISTEN
			continue
		}
		addr, port, ok := decodeAddr(fields[1])
		if !ok {
			continue
		}
		out[fields[9]] = Port{Address: addr, Port: port}
	}
}

// decodeAddr: "0100007F:1F90" → 127.0.0.1, 8080 (커널은 32비트 단위 little-endian)
func decodeAddr(s string) (string, int, bool) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return "", 0, false
	}
	if len(h) != 8 && len(h) != 32 {
		return "", 0, false
	}
	ip := make(net.IP, len(h)/2)
	for i := 0; i < len(h)/8; i++ {
		w, err := strconv.ParseUint(h[i*8:i*8+8], 16, 32)
		if err != nil {
			return "", 0, false
		}
		ip[i*4] = byte(w)
		ip[i*4+1] = byte(w >> 8)
		ip[i*4+2] = byte(w >> 16)
		ip[i*4+3] = byte(w >> 24)
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.String(), int(port), true
}

func attachProcesses(proc string, inodes map[string]Port) {
	pids, _ := os.ReadDir(proc)
	for _, d := range pids {
		if _, err := strconv.Atoi(d.Name()); err != nil {
			continue
		}
		fdDir := filepath.Join(proc, d.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		var comm string
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			ino := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			p, ok := inodes[ino]
			if !ok || p.Process != "" {
				continue
			}
			if comm == "" {
				b, _ := os.ReadFile(filepath.Join(proc, d.Name(), "comm"))
				comm = strings.TrimSpace(string(b))
			}
			p.Process = comm
			inodes[ino] = p
		}
	}
}
