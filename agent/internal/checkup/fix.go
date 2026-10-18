package checkup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Fix는 항목 하나를 고친다. 호출자(Agent)가 사람의 패스키 서명을 먼저 확인했다.
// 성공하면 무엇을 했는지 한 줄로 돌려준다. 고친 뒤에는 다시 점검해 결과를 보고한다.
func (c *Checker) Fix(ctx context.Context, id string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute) // 패키지 설치 포함
	defer cancel()
	switch id {
	case "ssh_password":
		return c.fixSSH(ctx, map[string]string{"PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no"})
	case "ssh_root":
		return c.fixSSH(ctx, map[string]string{"PermitRootLogin": "no"})
	case "auto_updates":
		return c.fixAutoUpdates(ctx)
	case "time_sync":
		if out, err := c.Run(ctx, "timedatectl", "set-ntp", "true"); err != nil {
			return "", fmt.Errorf("timedatectl set-ntp true: %v %s", err, firstLine(out))
		}
		return "시간 동기화(NTP)를 켰습니다", nil
	}
	return "", fmt.Errorf("고칠 수 없는 항목: %s", id)
}

const dropInHeader = "# Douve가 관리하는 파일 (보안 점검표 → 고치기). 직접 고치면 다음 고치기 때 덮어쓸 수 있습니다.\n"

var dropInLine = regexp.MustCompile(`^\s*([A-Za-z]+)\s+(\S+)\s*$`)

// fixSSH는 Douve 설정 파일에 값을 더하고, sshd -t로 검사한 뒤 다시 읽게 한다. 검사에 실패하면 되돌린다.
func (c *Checker) fixSSH(ctx context.Context, set map[string]string) (string, error) {
	bin := c.sshdPath()
	if bin == "" {
		return "", errors.New("sshd가 없습니다")
	}
	if !c.includesDropIns() {
		return "", errors.New("/etc/ssh/sshd_config가 sshd_config.d/*.conf를 (Match보다 앞에서) 읽지 않아 고칠 수 없습니다")
	}
	path := c.path(c.DropIn)
	old, readErr := os.ReadFile(path)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return "", readErr
	}
	// 기존 값 유지 + 새 값
	vals := map[string]string{}
	var order []string
	for _, line := range strings.Split(string(old), "\n") {
		if m := dropInLine.FindStringSubmatch(line); m != nil {
			if _, ok := vals[m[1]]; !ok {
				order = append(order, m[1])
			}
			vals[m[1]] = m[2]
		}
	}
	for _, k := range []string{"PasswordAuthentication", "KbdInteractiveAuthentication", "PermitRootLogin"} {
		v, ok := set[k]
		if !ok {
			continue
		}
		if _, had := vals[k]; !had {
			order = append(order, k)
		}
		vals[k] = v
	}
	var b strings.Builder
	b.WriteString(dropInHeader)
	for _, k := range order {
		fmt.Fprintf(&b, "%s %s\n", k, vals[k])
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	restore := func() {
		if readErr == nil {
			_ = os.WriteFile(path, old, 0o644)
		} else {
			_ = os.Remove(path)
		}
	}
	if out, err := c.sshd(ctx, bin, "-t"); err != nil {
		restore()
		return "", fmt.Errorf("sshd -t 실패, 되돌렸습니다: %s", firstLine(out))
	}
	// 실제로 적용되는지 확인 (다른 파일이 먼저 정했으면 소용없다)
	cfg, err := c.sshdConfig(ctx)
	if err != nil {
		restore()
		return "", err
	}
	for k, v := range set {
		if got := cfg[strings.ToLower(k)]; got != strings.ToLower(v) {
			restore()
			return "", fmt.Errorf("%s가 %s로 적용되지 않습니다 (다른 설정이 먼저 정함), 되돌렸습니다", k, got)
		}
	}
	// 다시 읽기: Ubuntu는 ssh.service, Rocky는 sshd.service. 소켓으로만 뜨면 다음 접속부터 새 설정.
	reloaded := false
	for _, unit := range []string{"ssh.service", "sshd.service"} {
		if out, err := c.Run(ctx, "systemctl", "is-active", unit); err == nil && strings.TrimSpace(out) == "active" {
			if out, err := c.Run(ctx, "systemctl", "reload", unit); err != nil {
				return "", fmt.Errorf("systemctl reload %s: %s", unit, firstLine(out))
			}
			reloaded = true
		}
	}
	keys := make([]string, 0, len(set))
	for _, k := range []string{"PasswordAuthentication", "KbdInteractiveAuthentication", "PermitRootLogin"} {
		if v, ok := set[k]; ok {
			keys = append(keys, k+" "+v)
		}
	}
	msg := c.DropIn + ": " + strings.Join(keys, ", ")
	if !reloaded {
		msg += " (다음 접속부터 적용)"
	}
	return msg, nil
}

func (c *Checker) fixAutoUpdates(ctx context.Context) (string, error) {
	switch c.distro() {
	case "apt":
		if out, err := c.Run(ctx, "apt-get", "install", "-y", "-q", "unattended-upgrades"); err != nil {
			return "", fmt.Errorf("apt-get install unattended-upgrades: %s", lastLine(out))
		}
		conf := "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
		_ = os.MkdirAll(c.path("/etc/apt/apt.conf.d"), 0o755)
		if err := os.WriteFile(c.path("/etc/apt/apt.conf.d/20auto-upgrades"), []byte(conf), 0o644); err != nil {
			return "", err
		}
		return "unattended-upgrades를 설치하고 켰습니다 (보안 업데이트 자동 설치)", nil
	case "dnf":
		if _, err := c.Run(ctx, "rpm", "-q", "dnf-automatic"); err != nil {
			if out, err := c.Run(ctx, "dnf", "-y", "-q", "install", "dnf-automatic"); err != nil {
				return "", fmt.Errorf("dnf install dnf-automatic: %s", lastLine(out))
			}
		}
		// 보안 업데이트만 자동으로 (커널 등 전체 업데이트는 사람이)
		if b, err := c.read("/etc/dnf/automatic.conf"); err == nil {
			re := regexp.MustCompile(`(?m)^\s*upgrade_type\s*=.*$`)
			nb := b
			if re.MatchString(b) {
				nb = re.ReplaceAllString(b, "upgrade_type = security")
			}
			if nb != b {
				if err := os.WriteFile(c.path("/etc/dnf/automatic.conf"), []byte(nb), 0o644); err != nil {
					return "", err
				}
			}
		}
		if out, err := c.Run(ctx, "systemctl", "enable", "--now", "dnf-automatic-install.timer"); err != nil {
			return "", fmt.Errorf("dnf-automatic-install.timer: %s", lastLine(out))
		}
		return "dnf-automatic을 설치하고 켰습니다 (보안 업데이트만 매일 자동 설치)", nil
	}
	return "", errors.New("이 배포판은 아직 지원하지 않습니다")
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
