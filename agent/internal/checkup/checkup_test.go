package checkup

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// fakeHost는 가짜 서버다: 파일은 root 아래, 명령은 기록하고 정해진 답을 낸다.
type fakeHost struct {
	t        *testing.T
	root     string
	calls    []string
	packages map[string]bool // 설치된 패키지
	units    map[string]string
	ntp      string
	failSSHD bool // sshd -t 실패
}

func newHost(t *testing.T, distro string) *fakeHost {
	h := &fakeHost{t: t, root: t.TempDir(), packages: map[string]bool{}, units: map[string]string{}, ntp: "yes"}
	id := map[string]string{"ubuntu": "ID=ubuntu\nID_LIKE=debian\n", "rocky": "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n"}[distro]
	h.write("/etc/os-release", id)
	h.write("/usr/sbin/sshd", "")
	h.write("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\nPermitRootLogin yes\nUsePAM yes\n")
	return h
}

func (h *fakeHost) write(p, body string) {
	full := filepath.Join(h.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

// sshdT는 sshd처럼 설정을 읽는다: Include 위치에서 sshd_config.d/*.conf를 이름 순으로, 처음 정한 값이 이긴다.
func (h *fakeHost) sshdT() string {
	vals := map[string]string{"passwordauthentication": "yes", "kbdinteractiveauthentication": "no", "permitrootlogin": "prohibit-password", "usepam": "no"}
	set := map[string]bool{}
	var read func(p string)
	read = func(p string) {
		b, _ := os.ReadFile(filepath.Join(h.root, p))
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 || strings.HasPrefix(f[0], "#") {
				continue
			}
			k := strings.ToLower(f[0])
			if k == "match" {
				return
			}
			if k == "include" {
				m, _ := filepath.Glob(filepath.Join(h.root, f[1]))
				sort.Strings(m)
				for _, x := range m {
					read(strings.TrimPrefix(x, h.root))
				}
				continue
			}
			if !set[k] {
				set[k], vals[k] = true, strings.ToLower(f[1])
			}
		}
	}
	read("/etc/ssh/sshd_config")
	var b strings.Builder
	for k, v := range vals {
		b.WriteString(k + " " + v + "\n")
	}
	return b.String()
}

func (h *fakeHost) run(_ context.Context, name string, args ...string) (string, error) {
	cmd := strings.TrimSpace(filepath.Base(name) + " " + strings.Join(args, " "))
	h.calls = append(h.calls, cmd)
	switch {
	case cmd == "sshd -T":
		return h.sshdT(), nil
	case cmd == "sshd -t":
		if h.failSSHD {
			return "bad configuration option", errors.New("exit 255")
		}
		return "", nil
	case strings.HasPrefix(cmd, "dpkg-query"):
		if h.packages["unattended-upgrades"] {
			return "install ok installed", nil
		}
		return "", errors.New("exit 1")
	case strings.HasPrefix(cmd, "rpm -q "):
		if h.packages[args[len(args)-1]] {
			return args[len(args)-1] + "-4.3", nil
		}
		return "not installed", errors.New("exit 1")
	case strings.HasPrefix(cmd, "apt-get install"), strings.HasPrefix(cmd, "dnf -y -q install"):
		pkg := args[len(args)-1]
		h.packages[pkg] = true
		if pkg == "dnf-automatic" {
			h.write("/etc/dnf/automatic.conf", "[commands]\nupgrade_type = default\napply_updates = no\n")
		}
		return "", nil
	case strings.HasPrefix(cmd, "systemctl is-enabled "), strings.HasPrefix(cmd, "systemctl is-active "):
		if st, ok := h.units[args[1]]; ok {
			return st, nil
		}
		return "inactive", errors.New("exit 3")
	case strings.HasPrefix(cmd, "systemctl enable --now "):
		h.units[args[2]] = "enabled"
		return "", nil
	case strings.HasPrefix(cmd, "systemctl reload "):
		return "", nil
	case strings.HasPrefix(cmd, "timedatectl show"):
		return "NTP=" + h.ntp + "\nNTPSynchronized=" + h.ntp + "\n", nil
	case cmd == "timedatectl set-ntp true":
		h.ntp = "yes"
		return "", nil
	case cmd == "needs-restarting -r":
		return "", nil
	}
	h.t.Fatalf("예상하지 못한 명령: %s", cmd)
	return "", nil
}

func (h *fakeHost) checker() *Checker {
	return &Checker{Root: h.root, Run: h.run, DropIn: SSHDropIn,
		Listen:   func() []string { return []string{"5432 postgres", "22 sshd"} },
		LookPath: func(n string) (string, error) { return "/usr/bin/" + n, nil }}
}

func byID(rs []Result) map[string]Result {
	m := map[string]Result{}
	for _, r := range rs {
		m[r.ID] = r
	}
	return m
}

func TestChecksAndFixesUbuntu(t *testing.T) {
	h := newHost(t, "ubuntu")
	h.ntp = "no"
	h.write("/etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
	h.write("/etc/ssh/sshd_config.d/10-hardening.conf", "Match User legacy\n  PasswordAuthentication yes\n")
	h.write("/run/reboot-required", "")
	h.write("/run/reboot-required.pkgs", "linux-image-6.8\nlibc6\n")
	c := h.checker()
	r := byID(c.All(context.Background()))
	if r["ssh_password"].Status != Fail || !r["ssh_password"].Fixable {
		t.Fatalf("비밀번호 SSH: %+v", r["ssh_password"])
	}
	if r["ssh_root"].Status != Fail || r["ssh_root"].Facts["value"] != "yes" {
		t.Fatalf("root: %+v", r["ssh_root"])
	}
	if r["ssh_match"].Status != Warn || !strings.Contains(r["ssh_match"].Facts["where"], "10-hardening.conf: Match User legacy") {
		t.Fatalf("Match 예외 (약한 비밀번호 계정이 다시 열림): %+v", r["ssh_match"])
	}
	if r["auto_updates"].Status != Fail || !r["auto_updates"].Fixable {
		t.Fatalf("자동 업데이트: %+v", r["auto_updates"])
	}
	if r["time_sync"].Status != Fail || r["reboot"].Status != Warn || !strings.Contains(r["reboot"].Facts["packages"], "linux-image") {
		t.Fatalf("시간·재부팅: %+v %+v", r["time_sync"], r["reboot"])
	}
	if r["public_ports"].Status != Info || r["public_ports"].Facts["ports"] != "22 sshd, 5432 postgres" {
		t.Fatalf("포트: %+v", r["public_ports"])
	}

	// 고치기: 00-douve.conf가 50-cloud-init.conf보다 먼저 읽혀 이긴다
	for _, id := range []string{"ssh_password", "ssh_root", "auto_updates", "time_sync"} {
		if msg, err := c.Fix(context.Background(), id); err != nil || msg == "" {
			t.Fatalf("%s 고치기: %q %v", id, msg, err)
		}
	}
	b, _ := os.ReadFile(filepath.Join(h.root, SSHDropIn))
	if !strings.Contains(string(b), "PasswordAuthentication no") || !strings.Contains(string(b), "PermitRootLogin no") {
		t.Fatalf("설정 파일 (두 번 고쳐도 둘 다 남아야): %s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(h.root, "/etc/apt/apt.conf.d/20auto-upgrades")); !strings.Contains(string(b), `Unattended-Upgrade "1"`) {
		t.Fatalf("20auto-upgrades: %s", b)
	}
	r = byID(c.All(context.Background()))
	for _, id := range []string{"ssh_password", "ssh_root", "auto_updates", "time_sync"} {
		if r[id].Status != OK {
			t.Fatalf("고친 뒤 %s: %+v", id, r[id])
		}
	}
	if r["ssh_match"].Status != Warn {
		t.Fatal("Match 예외는 사람이 판단 (고치기 없음)")
	}
	if _, err := c.Fix(context.Background(), "ssh_match"); err == nil {
		t.Fatal("고칠 수 없는 항목")
	}
}

func TestFixAutoUpdatesRocky(t *testing.T) {
	h := newHost(t, "rocky")
	c := h.checker()
	if r := byID(c.All(context.Background()))["auto_updates"]; r.Status != Fail || r.Facts["tool"] != "dnf-automatic" {
		t.Fatalf("%+v", r)
	}
	if _, err := c.Fix(context.Background(), "auto_updates"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(h.root, "/etc/dnf/automatic.conf"))
	if !strings.Contains(string(b), "upgrade_type = security") {
		t.Fatalf("보안 업데이트만: %s", b)
	}
	if r := byID(c.All(context.Background()))["auto_updates"]; r.Status != OK {
		t.Fatalf("고친 뒤: %+v", r)
	}
}

func TestFixSSHRollsBack(t *testing.T) {
	h := newHost(t, "ubuntu")
	h.write(SSHDropIn, "# 기존\nPermitRootLogin no\n")
	h.failSSHD = true
	c := h.checker()
	if _, err := c.Fix(context.Background(), "ssh_password"); err == nil || !strings.Contains(err.Error(), "되돌렸습니다") {
		t.Fatalf("sshd -t 실패: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(h.root, SSHDropIn)); string(b) != "# 기존\nPermitRootLogin no\n" {
		t.Fatalf("되돌리기: %q", b)
	}
	for _, call := range h.calls {
		if strings.HasPrefix(call, "systemctl reload") {
			t.Fatal("검사 실패인데 reload함")
		}
	}
}

func TestNoIncludeNotFixable(t *testing.T) {
	h := newHost(t, "ubuntu")
	h.write("/etc/ssh/sshd_config", "PasswordAuthentication yes\nUsePAM yes\n") // sshd_config.d를 읽지 않음
	c := h.checker()
	r := byID(c.All(context.Background()))
	if r["ssh_password"].Status != Fail || r["ssh_password"].Fixable || r["ssh_password"].Facts["no_include"] != "1" {
		t.Fatalf("%+v", r["ssh_password"])
	}
	if _, err := c.Fix(context.Background(), "ssh_password"); err == nil {
		t.Fatal("Include 없이 고침")
	}
	// Match 뒤의 Include도 전역이 아니다
	h.write("/etc/ssh/sshd_config", "Match User x\n  X11Forwarding no\nInclude /etc/ssh/sshd_config.d/*.conf\n")
	if c.includesDropIns() {
		t.Fatal("Match 뒤 Include")
	}
}

func TestNoSSHD(t *testing.T) {
	h := newHost(t, "ubuntu")
	os.Remove(filepath.Join(h.root, "/usr/sbin/sshd"))
	r := byID(h.checker().All(context.Background()))
	if r["ssh_password"].Status != NA || r["ssh_root"].Status != NA {
		t.Fatalf("sshd 없음: %+v", r)
	}
}

func TestRebootRocky(t *testing.T) {
	h := newHost(t, "rocky")
	c := h.checker()
	c.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "needs-restarting" {
			return "Reboot is required to fully utilize these updates.", exec.Command("sh", "-c", "exit 1").Run()
		}
		return h.run(ctx, name, args...)
	}
	if r := byID(c.All(context.Background()))["reboot"]; r.Status != Warn {
		t.Fatalf("needs-restarting 1 → 재부팅 필요: %+v", r)
	}
}

func TestSSHDSocketActivated(t *testing.T) {
	// /run/sshd가 없으면 systemd-run RuntimeDirectory로 다시 (Root가 비어 있을 때만 = 실제 서버)
	var calls []string
	c := &Checker{Run: func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "/usr/sbin/sshd" {
			return "Missing privilege separation directory: /run/sshd", errors.New("exit 255")
		}
		return "passwordauthentication no\n", nil
	}}
	out, err := c.sshd(context.Background(), "/usr/sbin/sshd", "-T")
	if err != nil || !strings.Contains(out, "passwordauthentication no") {
		t.Fatal(out, err)
	}
	if len(calls) != 2 || !strings.Contains(calls[1], "RuntimeDirectory=sshd -- /usr/sbin/sshd -T") {
		t.Fatalf("%q", calls)
	}
}

func TestRebootRockyErrorIsNotReboot(t *testing.T) {
	// 샌드박스에서 needs-restarting이 오류(종료 1)로 끝나도 "재부팅 필요"가 아니다
	h := newHost(t, "rocky")
	c := h.checker()
	c.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "needs-restarting" {
			return "Config error: [Errno 30] Read-only file system: '/var/log/dnf.log'", exec.Command("sh", "-c", "exit 1").Run()
		}
		return h.run(ctx, name, args...)
	}
	if r := byID(c.All(context.Background()))["reboot"]; r.Status != Unknown || !strings.Contains(r.ErrorMsg, "Read-only") {
		t.Fatalf("오류는 확인 불가: %+v", r)
	}
}
