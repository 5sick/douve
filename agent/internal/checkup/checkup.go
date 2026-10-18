// Package checkup은 서버 보안 점검표다: 출입에 관한 설정을 읽어 상태를 알리고, 고칠 수 있는 항목은
// 사람이 패스키로 승인했을 때(Agent가 서명을 직접 확인한 뒤) 고친다.
//
// 항목 (id):
//
//	ssh_password  SSH 비밀번호 로그인 (sshd -T)           고치기: 설정 파일 하나 추가 → sshd -t → reload
//	ssh_root      SSH root 로그인                        고치기: 같은 파일에 PermitRootLogin no
//	ssh_match     Match 블록에서 비밀번호를 다시 허용      (알림만: 계정별 예외는 사람이 판단)
//	auto_updates  자동 보안 업데이트 (unattended-upgrades / dnf-automatic) 고치기: 설치·켜기
//	time_sync     시간 동기화 (터미널 서명 확인에 필요)   고치기: timedatectl set-ntp true
//	reboot        재부팅 필요 (업데이트 적용 대기)        (알림만)
//	public_ports  인터넷 쪽 주소에서 열린 포트            (참고)
//
// 화면 문구는 Hub 화면(web)이 id로 만든다. 여기서는 상태와 사실(facts)만 보낸다.
package checkup

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/5sick/douve/agent/internal/sockexec"
)

// 상태
const (
	OK      = "ok"
	Warn    = "warn"
	Fail    = "fail"
	Info    = "info"
	Unknown = "unknown" // 확인할 수 없음 (도구 없음·권한 없음)
	NA      = "na"      // 이 서버에는 해당 없음
)

// Result는 항목 하나의 점검 결과다.
type Result struct {
	ID       string            `json:"id"`
	Status   string            `json:"status"`
	Facts    map[string]string `json:"facts,omitempty"`
	Fixable  bool              `json:"fixable,omitempty"`
	ErrorMsg string            `json:"error,omitempty"`
}

// Runner는 명령을 실행한다 (시험에서 바꿈).
type Runner func(ctx context.Context, name string, args ...string) (string, error)

// execRunner는 소켓 쌍으로 입출력을 잇는다 (systemd-run --pipe가 SELinux에서도 되게, sockexec 참고).
func execRunner(ctx context.Context, name string, args ...string) (string, error) {
	return sockexec.Output(ctx, append(os.Environ(), "LANG=C", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive"), name, args...)
}

// Checker는 점검·고치기를 한다. Root는 파일 경로 앞에 붙는다 (시험용, 보통 "").
type Checker struct {
	Root     string
	Run      Runner
	Listen   func() []string // 인터넷 쪽에서 열린 포트 ("포트 프로세스")
	DropIn   string          // 우리가 쓰는 sshd 설정 파일
	LookPath func(string) (string, error)
}

// SSHDropIn은 Douve가 관리하는 sshd 설정 파일이다. 00-으로 시작해 다른 설정보다 먼저 읽힌다
// (sshd는 처음 정한 값을 쓴다).
const SSHDropIn = "/etc/ssh/sshd_config.d/00-douve.conf"

func New() *Checker {
	return &Checker{Run: execRunner, DropIn: SSHDropIn, LookPath: exec.LookPath}
}

// UseTestRoot는 시험용: 파일은 root 아래에서 읽고, 명령은 경로 없이 이름으로(PATH의 가짜 명령) 실행한다.
func (c *Checker) UseTestRoot(root string) {
	c.Root = root
	c.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		return execRunner(ctx, filepath.Base(name), args...)
	}
}

func (c *Checker) path(p string) string { return filepath.Join(c.Root, p) }

func (c *Checker) read(p string) (string, error) {
	b, err := os.ReadFile(c.path(p))
	return string(b), err
}

func (c *Checker) exists(p string) bool {
	_, err := os.Stat(c.path(p))
	return err == nil
}

// Fixable은 고칠 수 있는 항목 id다.
var Fixable = map[string]bool{"ssh_password": true, "ssh_root": true, "auto_updates": true, "time_sync": true}

// All은 모든 항목을 점검한다.
func (c *Checker) All(ctx context.Context) []Result {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var out []Result
	out = append(out, c.ssh(ctx)...)
	out = append(out, c.autoUpdates(ctx), c.timeSync(ctx), c.reboot(ctx), c.publicPorts())
	return out
}

// ---- SSH ----

func (c *Checker) sshdPath() string {
	for _, p := range []string{"/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"} {
		if c.exists(p) {
			return p
		}
	}
	return ""
}

// sshdConfig는 sshd -T(실제로 적용되는 값)를 읽는다.
func (c *Checker) sshdConfig(ctx context.Context) (map[string]string, error) {
	bin := c.sshdPath()
	if bin == "" {
		return nil, os.ErrNotExist
	}
	out, err := c.sshd(ctx, bin, "-T")
	if err != nil {
		return nil, fmt.Errorf("sshd -T: %v %s", err, firstLine(out))
	}
	m := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if ok {
			m[strings.ToLower(k)] = strings.ToLower(strings.TrimSpace(v))
		}
	}
	if len(m) == 0 {
		return nil, errors.New("sshd -T 결과 없음")
	}
	return m, nil
}

// sshd는 sshd -T/-t를 실행한다. 소켓 활성화(Ubuntu 24.04+ ssh.socket)라 ssh.service가 떠 있지 않으면
// /run/sshd가 없어 실패하는데, 그때는 systemd-run의 RuntimeDirectory로 잠깐 만들어(끝나면 지워짐) 다시 한다.
// (Agent 샌드박스는 /run에 쓸 수 없다)
func (c *Checker) sshd(ctx context.Context, bin string, args ...string) (string, error) {
	out, err := c.Run(ctx, bin, args...)
	if err == nil || !strings.Contains(out, "privilege separation directory") || c.Root != "" {
		return out, err
	}
	full := append([]string{"--wait", "--pipe", "--quiet", "--collect", "-p", "RuntimeDirectory=sshd", "--", bin}, args...)
	return c.Run(ctx, "systemd-run", full...)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// sshFiles는 sshd 설정 파일들 (본 파일 + 포함 디렉터리)
func (c *Checker) sshFiles() []string {
	files := []string{"/etc/ssh/sshd_config"}
	matches, _ := filepath.Glob(c.path("/etc/ssh/sshd_config.d/*.conf"))
	sort.Strings(matches)
	for _, m := range matches {
		files = append(files, strings.TrimPrefix(m, c.Root))
	}
	return files
}

var matchRe = regexp.MustCompile(`(?i)^\s*match\s+(.+)$`)
var pwYesRe = regexp.MustCompile(`(?i)^\s*(passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication)\s+yes\b`)

// matchPasswords는 Match 블록 안에서 비밀번호 로그인을 다시 켠 곳을 찾는다 ("파일: Match 조건").
func (c *Checker) matchPasswords() []string {
	var out []string
	for _, f := range c.sshFiles() {
		body, err := c.read(f)
		if err != nil {
			continue
		}
		cond := ""
		for _, line := range strings.Split(body, "\n") {
			if m := matchRe.FindStringSubmatch(line); m != nil {
				cond = strings.TrimSpace(m[1])
				if strings.EqualFold(cond, "all") {
					cond = ""
				}
				continue
			}
			if cond != "" && pwYesRe.MatchString(line) {
				out = append(out, filepath.Base(f)+": Match "+cond)
			}
		}
	}
	return out
}

func (c *Checker) ssh(ctx context.Context) []Result {
	cfg, err := c.sshdConfig(ctx)
	if errors.Is(err, os.ErrNotExist) {
		return []Result{{ID: "ssh_password", Status: NA}, {ID: "ssh_root", Status: NA}, {ID: "ssh_match", Status: NA}}
	}
	if err != nil {
		e := err.Error()
		return []Result{{ID: "ssh_password", Status: Unknown, ErrorMsg: e}, {ID: "ssh_root", Status: Unknown, ErrorMsg: e}}
	}
	pw := Result{ID: "ssh_password", Status: OK, Facts: map[string]string{
		"password": cfg["passwordauthentication"], "kbd": cfg["kbdinteractiveauthentication"]}}
	// UsePAM이면 kbd-interactive로도 비밀번호를 받는다
	if cfg["passwordauthentication"] == "yes" || (cfg["kbdinteractiveauthentication"] == "yes" && cfg["usepam"] == "yes") {
		pw.Status, pw.Fixable = Fail, true
	}
	root := Result{ID: "ssh_root", Status: OK, Facts: map[string]string{"value": cfg["permitrootlogin"]}}
	switch cfg["permitrootlogin"] {
	case "yes":
		root.Status, root.Fixable = Fail, true
	case "no":
	default: // prohibit-password, without-password, forced-commands-only: 키로는 root 로그인 가능
		root.Status, root.Fixable = Warn, true
	}
	if !c.includesDropIns() {
		// 포함 디렉터리를 읽지 않으면 우리 파일이 효과가 없다
		pw.Fixable, root.Fixable = false, false
		pw.Facts["no_include"], root.Facts["no_include"] = "1", "1"
	}
	match := Result{ID: "ssh_match", Status: OK}
	if m := c.matchPasswords(); len(m) > 0 {
		match.Status = Warn
		match.Facts = map[string]string{"where": strings.Join(m, ", ")}
	}
	return []Result{pw, root, match}
}

var includeRe = regexp.MustCompile(`(?im)^\s*include\s+/etc/ssh/sshd_config\.d/\*\.conf\s*$`)

func (c *Checker) includesDropIns() bool {
	body, err := c.read("/etc/ssh/sshd_config")
	if err != nil {
		return false
	}
	// Include는 Match보다 앞에 있어야 전역 설정이 된다
	loc := includeRe.FindStringIndex(body)
	if loc == nil {
		return false
	}
	m := regexp.MustCompile(`(?im)^\s*match\s`).FindStringIndex(body)
	return m == nil || loc[0] < m[0]
}

// ---- 자동 보안 업데이트 ----

func (c *Checker) distro() string {
	body, _ := c.read("/etc/os-release")
	id := ""
	for _, line := range strings.Split(body, "\n") {
		k, v, _ := strings.Cut(line, "=")
		v = strings.Trim(v, `"`)
		if k == "ID" || k == "ID_LIKE" {
			id += " " + v
		}
	}
	switch {
	case strings.Contains(id, "debian") || strings.Contains(id, "ubuntu"):
		return "apt"
	case strings.Contains(id, "rhel") || strings.Contains(id, "fedora") || strings.Contains(id, "centos"):
		return "dnf"
	}
	return ""
}

var aptUnattendedRe = regexp.MustCompile(`APT::Periodic::Unattended-Upgrade\s+"1"`)

func (c *Checker) autoUpdates(ctx context.Context) Result {
	r := Result{ID: "auto_updates", Facts: map[string]string{}}
	switch c.distro() {
	case "apt":
		r.Facts["tool"] = "unattended-upgrades"
		out, err := c.Run(ctx, "dpkg-query", "-W", "-f=${Status}", "unattended-upgrades")
		installed := err == nil && strings.Contains(out, "install ok installed")
		on := false
		for _, f := range []string{"/etc/apt/apt.conf.d/20auto-upgrades", "/etc/apt/apt.conf.d/10periodic"} {
			if b, err := c.read(f); err == nil && aptUnattendedRe.MatchString(b) {
				on = true
			}
		}
		r.Status, r.Fixable = OK, false
		if !installed || !on {
			r.Status, r.Fixable = Fail, true
		}
	case "dnf":
		r.Facts["tool"] = "dnf-automatic"
		_, err := c.Run(ctx, "rpm", "-q", "dnf-automatic")
		installed := err == nil
		enabled := false
		if installed {
			if out, err := c.Run(ctx, "systemctl", "is-enabled", "dnf-automatic-install.timer"); err == nil && strings.TrimSpace(out) == "enabled" {
				enabled = true
			}
			if out, err := c.Run(ctx, "systemctl", "is-enabled", "dnf-automatic.timer"); err == nil && strings.TrimSpace(out) == "enabled" {
				if b, err := c.read("/etc/dnf/automatic.conf"); err == nil && regexp.MustCompile(`(?m)^\s*apply_updates\s*=\s*(yes|true|1)\s*$`).MatchString(b) {
					enabled = true
				}
			}
		}
		r.Status, r.Fixable = OK, false
		if !enabled {
			r.Status, r.Fixable = Fail, true
		}
	default:
		r.Status = Unknown
	}
	return r
}

// ---- 시간 동기화 ----

func (c *Checker) timeSync(ctx context.Context) Result {
	r := Result{ID: "time_sync"}
	out, err := c.Run(ctx, "timedatectl", "show", "-p", "NTP", "-p", "NTPSynchronized")
	if err != nil {
		r.Status, r.ErrorMsg = Unknown, firstLine(out)
		return r
	}
	v := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, val, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			v[k] = val
		}
	}
	r.Facts = map[string]string{"ntp": v["NTP"], "synced": v["NTPSynchronized"]}
	switch {
	case v["NTPSynchronized"] == "yes":
		r.Status = OK
	case v["NTP"] == "no":
		r.Status, r.Fixable = Fail, true
	default:
		r.Status = Warn // 켜져 있지만 아직 맞추지 못함 (네트워크·NTP 서버 확인)
	}
	return r
}

// ---- 재부팅 필요 ----

func (c *Checker) reboot(ctx context.Context) Result {
	r := Result{ID: "reboot", Status: OK}
	if c.exists("/run/reboot-required") || c.exists("/var/run/reboot-required") {
		r.Status = Warn
		if b, err := c.read("/run/reboot-required.pkgs"); err == nil {
			pk := strings.Fields(b)
			if len(pk) > 8 {
				pk = append(pk[:8], "…")
			}
			r.Facts = map[string]string{"packages": strings.Join(pk, " ")}
		}
		return r
	}
	if c.distro() == "dnf" {
		if _, err := c.LookPath("needs-restarting"); err != nil {
			r.Status = Unknown
			return r
		}
		// 종료 코드 1은 "재부팅 필요"와 오류(예: Agent 샌드박스에서 /var/log/dnf.log를 못 씀) 둘 다라
		// 문구로 구분한다. 오류면 샌드박스 밖(systemd-run)에서 다시 (읽기만 한다).
		out, err := c.Run(ctx, "needs-restarting", "-r")
		if err != nil && !strings.Contains(out, "Reboot is required") && c.Root == "" {
			out, err = c.Run(ctx, "systemd-run", "--wait", "--pipe", "--quiet", "--collect", "-E", "LANG=C", "--", "needs-restarting", "-r")
		}
		switch {
		case strings.Contains(out, "Reboot is required"):
			r.Status = Warn
		case err == nil:
			r.Status = OK
		default:
			r.Status, r.ErrorMsg = Unknown, firstLine(out)
		}
	}
	return r
}

// ---- 열린 포트 ----

func (c *Checker) publicPorts() Result {
	r := Result{ID: "public_ports", Status: Info}
	if c.Listen == nil {
		r.Status = Unknown
		return r
	}
	ports := c.Listen()
	sort.Strings(ports)
	r.Facts = map[string]string{"ports": strings.Join(ports, ", ")}
	if len(ports) == 0 {
		r.Status = OK
	}
	return r
}
