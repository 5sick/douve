// Package install은 `douve-agent install`: 빈 서버에 Douve(Hub + 이 서버의 Agent)를 설치한다.
//
// 대화형(번호 선택, Enter = 추천)이며 같은 선택을 옵션으로 줄 수 있다.
// 다른 서버 추가는 웹의 "서버 추가"(설치 질문 없음 — Hub 설정을 받아 그대로)로 한다.
package install

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/5sick/douve/agent/internal/collect"
	"github.com/5sick/douve/agent/internal/i18n"
	"github.com/5sick/douve/agent/internal/portmap"
	"github.com/5sick/douve/agent/internal/sign"
	"github.com/5sick/douve/agent/internal/update"
)

// Options는 설치 선택이다. 비어 있는 값은 대화형으로 묻는다 (Yes면 추천값).
type Options struct {
	Mode       string // tailscale | public
	Domain     string // public: Douve 주소 (예: douve.example.com)
	Email      string // public: 관리자 이메일 (첫 초대·인증서 연락처)
	Features   string // recommended | custom (custom이면 항목별로 묻는다)
	FeatureSet map[string]bool
	Yes        bool   // 묻지 않고 추천값
	From       string // 로컬 릴리스 폴더 (douve-hub-linux-*, douve-agent-linux-*, SHA256SUMS(.minisig), VERSION)
	TrustedKey string // 공식 릴리스 키 말고도 믿을 공개키 파일 (직접 빌드한 릴리스) — Agent 업데이트에도 쓰도록 저장
	Release    string // 릴리스 주소 (기본 GitHub 최신)
	TestPlain  bool   // 시험용: 입구를 :80 평문으로 (인증서 없이)
}

const DefaultRelease = "https://github.com/5sick/douve/releases/latest/download"

type Installer struct {
	Opt           Options
	cloud         string // 클라우드 업체 (방화벽 안내)
	portForward   bool   // 공유기 포트 자동 열기를 켰는지
	signedVersion string // 서명된 릴리스 버전
	In            *bufio.Reader
	Out           io.Writer
	arch          string
	tmp           string
}

func New(opt Options, out io.Writer) *Installer {
	in := bufio.NewReader(os.Stdin)
	// `curl ... | sudo sh`로 실행되면 표준입력이 파이프라 터미널에서 직접 읽는다
	if tty, err := os.Open("/dev/tty"); err == nil {
		in = bufio.NewReader(tty)
	}
	return &Installer{Opt: opt, In: in, Out: out}
}

func (s *Installer) say(format string, a ...any) { fmt.Fprintf(s.Out, i18n.T(format)+"\n", a...) }
func (s *Installer) step(n int, msg string)      { fmt.Fprintf(s.Out, "\n[%d] %s\n", n, i18n.T(msg)) }

// choose는 번호 선택을 받는다. Enter면 0번(추천).
func (s *Installer) choose(question string, options []string) int {
	if s.Opt.Yes {
		return 0
	}
	fmt.Fprintf(s.Out, "\n? %s\n", i18n.T(question))
	for i, o := range options {
		o = i18n.T(o)
		mark := " "
		if i == 0 {
			mark = "▸"
		}
		fmt.Fprintf(s.Out, "  %s %d) %s\n", mark, i+1, o)
	}
	for {
		fmt.Fprint(s.Out, i18n.T("  번호 [1]: "))
		line, err := s.In.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" || err != nil {
			return 0
		}
		var n int
		if _, e := fmt.Sscan(line, &n); e == nil && n >= 1 && n <= len(options) {
			return n - 1
		}
	}
}

func (s *Installer) ask(question, def string) string {
	question = i18n.T(question)
	if s.Opt.Yes && def != "" {
		return def
	}
	if def != "" {
		fmt.Fprintf(s.Out, "? %s [%s]: ", question, def)
	} else {
		fmt.Fprintf(s.Out, "? %s: ", question)
	}
	line, _ := s.In.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func (s *Installer) yesNo(question string, def bool) bool {
	question = i18n.T(question)
	if s.Opt.Yes {
		return def
	}
	d := "Y/n"
	if !def {
		d = "y/N"
	}
	fmt.Fprintf(s.Out, "  %s [%s]: ", question, d)
	line, _ := s.In.ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes", "예", "ㅇ":
		return true
	case "n", "no", "아니오", "ㄴ":
		return false
	}
	return def
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Run은 설치 전체다.
func (s *Installer) Run(ctx context.Context) error {
	s.say("Douve 설치 — 작은 서버들을 위한 보안 현관")
	if err := s.preflight(); err != nil {
		return err
	}
	if err := s.decide(); err != nil {
		return err
	}
	s.summary()
	if !s.Opt.Yes && !s.yesNo("이대로 설치할까요?", true) {
		return errors.New(i18n.T("취소했습니다"))
	}
	var err error
	s.tmp, err = os.MkdirTemp("", "douve-install-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(s.tmp)

	s.step(1, "프로그램 받기 (체크섬 확인)")
	if err := s.fetch(ctx); err != nil {
		return err
	}
	s.step(2, "Hub 설치")
	if err := s.installHub(ctx); err != nil {
		return err
	}
	s.step(3, "이 서버를 Douve에 등록 (Agent)")
	if err := s.installAgent(ctx); err != nil {
		return err
	}
	s.step(4, "접속 확인")
	return s.finish(ctx)
}

func (s *Installer) preflight() error {
	if os.Geteuid() != 0 {
		return errors.New(i18n.T("root 권한이 필요합니다 (sudo로 실행하세요)"))
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New(i18n.T("systemd가 필요합니다"))
	}
	switch runtime.GOARCH {
	case "amd64", "arm64":
		s.arch = runtime.GOARCH
	default:
		return fmt.Errorf(i18n.T("지원하지 않는 CPU: %s"), runtime.GOARCH)
	}
	if _, err := os.Stat("/etc/douve/hub.json"); err == nil {
		return errors.New(i18n.T("이미 Douve가 설치되어 있습니다 (/etc/douve/hub.json). 업그레이드는 웹 설정 또는 install-hub를 쓰세요"))
	}
	return nil
}

type tsStatus struct {
	BackendState string
	Self         struct {
		DNSName string
		UserID  int64
	}
	User map[string]struct{ LoginName string }
}

func tailscaleStatus() (*tsStatus, error) {
	out, err := exec.Command("tailscale", "status", "--json").Output()
	if err != nil {
		return nil, err
	}
	var st tsStatus
	if err := json.Unmarshal(out, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (s *Installer) decide() error {
	if s.Opt.Mode == "" {
		_, hasTS := exec.LookPath("tailscale")
		opts := []string{
			"Tailscale 안에서만 쓰기 (도메인 필요 없음, 공개 포트 0개, 내 기기에서만 접속)",
			"인터넷에 공개 (내 도메인 + 이 서버의 80/443 포트)",
		}
		if hasTS != nil {
			opts[0] = i18n.T(opts[0]) + i18n.T(" — Tailscale 먼저 설치 필요")
		}
		if s.choose("어떻게 접속할까요?", opts) == 0 {
			s.Opt.Mode = "tailscale"
		} else {
			s.Opt.Mode = "public"
		}
	}
	switch s.Opt.Mode {
	case "tailscale":
		st, err := tailscaleStatus()
		if err != nil {
			return errors.New(i18n.T("Tailscale이 없거나 실행 중이 아닙니다.\n  설치: curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up\n  그다음 다시 실행하세요"))
		}
		if st.BackendState != "Running" || st.Self.DNSName == "" {
			return errors.New(i18n.T("Tailscale에 로그인되어 있지 않습니다: sudo tailscale up"))
		}
		s.Opt.Domain = strings.TrimSuffix(st.Self.DNSName, ".")
		if u, ok := st.User[fmt.Sprint(st.Self.UserID)]; ok && s.Opt.Email == "" {
			s.Opt.Email = strings.ToLower(u.LoginName)
		}
		if s.Opt.Email == "" {
			s.Opt.Email = s.ask("Douve를 쓸 Tailscale 사용자 (로그인 이메일)", "")
		}
	case "public":
		if s.Opt.Domain == "" {
			s.say("\n  도메인의 DNS에서 이 주소(와 *.같은 도메인)를 이 서버의 공인 IP로 연결해 두세요.")
			s.Opt.Domain = s.ask("Douve 주소 (예: douve.example.com)", "")
		}
		if s.Opt.Email == "" {
			s.Opt.Email = s.ask("관리자 이메일 (첫 로그인 초대·인증서 알림)", "")
		}
		if !s.Opt.TestPlain {
			for _, p := range []string{":80", ":443"} {
				if ln, err := net.Listen("tcp", p); err != nil {
					return fmt.Errorf(i18n.T("%s 포트를 이미 다른 프로그램이 쓰고 있습니다 (nginx 등). 끄고 다시 실행하세요"), p)
				} else {
					ln.Close()
				}
			}
		}
	default:
		return fmt.Errorf(i18n.T("--mode는 tailscale 또는 public: %q"), s.Opt.Mode)
	}
	if s.Opt.Domain == "" || !strings.Contains(s.Opt.Domain, ".") || strings.ContainsAny(s.Opt.Domain, "/: ") {
		return fmt.Errorf(i18n.T("주소가 올바르지 않습니다: %q"), s.Opt.Domain)
	}
	if !strings.Contains(s.Opt.Email, "@") {
		return fmt.Errorf(i18n.T("이메일이 올바르지 않습니다: %q"), s.Opt.Email)
	}
	s.FeatureSet()
	return nil
}

// FeatureSet은 기능 선택 (추천 = 모두 켬).
func (s *Installer) FeatureSet() {
	if s.Opt.FeatureSet != nil {
		return
	}
	all := map[string]bool{"monitoring": true, "service_checks": true, "terminal": true, "security": true}
	if s.Opt.Features == "" {
		if s.choose("구성", []string{"추천 구성 (모니터링·서비스 감시·웹 터미널·보안 감시 모두 켜기)", "직접 고르기"}) == 0 {
			s.Opt.Features = "recommended"
		} else {
			s.Opt.Features = "custom"
		}
	}
	if s.Opt.Features == "custom" {
		all["monitoring"] = s.yesNo("리소스 모니터링 (CPU·메모리·디스크 그래프와 알림)", true)
		all["service_checks"] = s.yesNo("서비스 감시 (등록한 서비스가 응답하는지)", true)
		all["terminal"] = s.yesNo("웹 터미널 (SSH 대신 브라우저에서)", true)
		all["security"] = s.yesNo("보안 감시 (SSH 로그인·sudo·중요 파일·새 포트)", true)
	}
	s.Opt.FeatureSet = all
}

func (s *Installer) featuresJSON() string {
	f := s.Opt.FeatureSet
	sec := f["security"]
	b, _ := json.Marshal(map[string]any{
		"monitoring": f["monitoring"], "service_checks": f["service_checks"], "terminal": f["terminal"],
		"security": map[string]bool{"ssh": sec, "sudo": sec, "account": sec, "files": sec, "ports": sec},
	})
	return string(b)
}

func (s *Installer) publicURL() string { return "https://" + s.Opt.Domain }

func (s *Installer) summary() {
	s.say("\n설치 내용")
	if s.Opt.Mode == "tailscale" {
		s.say("  접속      Tailscale 안에서만 — %s (로그인은 Tailscale 사용자 %s)", s.publicURL(), s.Opt.Email)
	} else {
		s.say("  접속      %s (Let's Encrypt 인증서 자동, 이 서버가 입구)", s.publicURL())
		s.say("  관리자    %s (설치 후 초대 링크로 패스키 등록)", s.Opt.Email)
	}
	on := func(k string) string {
		if s.Opt.FeatureSet[k] {
			return i18n.T("켬")
		}
		return i18n.T("끔")
	}
	s.say("  기능      모니터링 %s · 서비스 감시 %s · 웹 터미널 %s · 보안 감시 %s",
		on("monitoring"), on("service_checks"), on("terminal"), on("security"))
}

// ---------- 받기 ----------

func (s *Installer) get(name string) (string, error) {
	dst := filepath.Join(s.tmp, name)
	if s.Opt.From != "" {
		b, err := os.ReadFile(filepath.Join(s.Opt.From, name))
		if err != nil {
			return "", err
		}
		return dst, os.WriteFile(dst, b, 0o644)
	}
	base := s.Opt.Release
	if base == "" {
		base = DefaultRelease
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/"+name, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf(i18n.T("%s 받기 실패: HTTP %d"), name, resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer f.Close()
	_, err = io.Copy(f, io.LimitReader(resp.Body, 128<<20))
	return dst, err
}

func sha256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Installer) fetch(ctx context.Context) error {
	sums, err := s.get("SHA256SUMS")
	if err != nil {
		return err
	}
	b, _ := os.ReadFile(sums)
	// 체크섬 목록은 서명으로 확인한다 (공식 릴리스 키, --trusted-key)
	sigPath, err := s.get("SHA256SUMS.minisig")
	if err != nil {
		return fmt.Errorf(i18n.T("릴리스 서명(SHA256SUMS.minisig)을 받지 못했습니다: %w"), err)
	}
	sig, _ := os.ReadFile(sigPath)
	keys := update.TrustedKeys("")
	if s.Opt.TrustedKey != "" {
		kb, err := os.ReadFile(s.Opt.TrustedKey)
		if err != nil {
			return err
		}
		k, err := sign.ParsePublicKey(string(kb))
		if err != nil {
			return err
		}
		keys = append(keys, k)
	}
	trusted, err := sign.Verify(keys, b, string(sig))
	if err != nil {
		return fmt.Errorf(i18n.T("릴리스 서명 확인 실패: %w"), err)
	}
	s.say("  %s ✓", "SHA256SUMS.minisig")
	s.signedVersion = sign.CommentField(trusted, "version")
	want := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			want[strings.TrimPrefix(f[1], "*")] = f[0]
		}
	}
	for _, name := range []string{"douve-hub-linux-" + s.arch, "douve-agent-linux-amd64", "douve-agent-linux-arm64", "VERSION"} {
		p, err := s.get(name)
		if err != nil {
			return err
		}
		if name == "VERSION" {
			v, _ := os.ReadFile(p)
			if strings.TrimSpace(string(v)) != s.signedVersion {
				return fmt.Errorf(i18n.T("VERSION(%s)이 서명된 버전(%s)과 다릅니다"), strings.TrimSpace(string(v)), s.signedVersion)
			}
			continue
		}
		got, _ := sha256File(p)
		if want[name] == "" || got != want[name] {
			return fmt.Errorf(i18n.T("%s 체크섬이 맞지 않습니다"), name)
		}
		s.say("  %s ✓", name)
	}
	return nil
}

// ---------- Hub ----------

func installFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	if _, err := exec.LookPath("restorecon"); err == nil {
		_, _ = run("restorecon", dst) // SELinux 레이블
	}
	return nil
}

func (s *Installer) installHub(ctx context.Context) error {
	hub := "/usr/local/bin/douve-hub"
	if err := installFile(filepath.Join(s.tmp, "douve-hub-linux-"+s.arch), hub, 0o755); err != nil {
		return err
	}
	// 다른 서버 추가 때 내려줄 Agent
	for _, f := range []string{"douve-agent-linux-amd64", "douve-agent-linux-arm64", "SHA256SUMS", "SHA256SUMS.minisig", "VERSION"} {
		if err := installFile(filepath.Join(s.tmp, f), "/usr/local/share/douve/agent/"+f, 0o644); err != nil {
			return err
		}
	}
	if err := os.MkdirAll("/etc/douve", 0o755); err != nil {
		return err
	}
	args := []string{"init", "--public-url", s.publicURL(), "--email", s.Opt.Email, "--listen", "127.0.0.1:8700",
		"--language", i18n.Lang()}
	if s.Opt.Mode == "tailscale" {
		args = append(args, "--tailscale-auth", "--cookie-domain", s.Opt.Domain)
	}
	if s.Opt.TestPlain {
		args[2] = "http://localhost:8700" // 시험용 (TLS 없음)
		args = append(args, "--cookie-domain", "localhost")
	}
	if _, err := run(hub, args...); err != nil {
		return err
	}
	if _, err := run(hub, "install-service"); err != nil {
		return err
	}
	if _, err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	// 기능 설정은 DB에 들어가므로 한 번 시작해서 DB를 만든 뒤 넣고 다시 시작
	if _, err := run("systemctl", "enable", "--now", "douve-hub"); err != nil {
		return err
	}
	if err := waitHTTP(ctx, "http://127.0.0.1:8700/healthz", 30*time.Second); err != nil {
		return fmt.Errorf(i18n.T("Hub가 시작되지 않았습니다 (journalctl -u douve-hub): %w"), err)
	}
	if _, err := run(hub, "configure", "--features", s.featuresJSON()); err != nil {
		return err
	}
	if _, err := run("systemctl", "restart", "douve-hub"); err != nil {
		return err
	}
	if err := waitHTTP(ctx, "http://127.0.0.1:8700/healthz", 30*time.Second); err != nil {
		return err
	}
	s.say("  douve-hub 실행 중 (127.0.0.1:8700)")
	if s.Opt.Mode == "tailscale" {
		if _, err := run("tailscale", "serve", "--bg", "--https=443", "http://127.0.0.1:8700"); err != nil {
			return fmt.Errorf(i18n.T("tailscale serve 실패 — Tailscale 관리 화면에서 HTTPS 인증서를 켜야 할 수 있습니다\n  (https://login.tailscale.com/admin/dns → HTTPS Certificates)\n%w"), err)
		}
		s.say("  tailscale serve: %s → Douve", s.publicURL())
	}
	return nil
}

func waitHTTP(ctx context.Context, url string, d time.Duration) error {
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		last = err
		time.Sleep(time.Second)
	}
	return last
}

// ---------- Agent ----------

func (s *Installer) installAgent(ctx context.Context) error {
	agent := "/usr/local/bin/douve-agent"
	if err := installFile(filepath.Join(s.tmp, "douve-agent-linux-"+s.arch), agent, 0o755); err != nil {
		return err
	}
	host, _ := os.Hostname()
	name := strings.ToLower(strings.SplitN(host, ".", 2)[0])
	outb, err := exec.Command("/usr/local/bin/douve-hub", "join-token", "--name", name).Output()
	if err != nil {
		return fmt.Errorf(i18n.T("등록 토큰 생성 실패: %w"), err)
	}
	out := string(outb)
	f := strings.Fields(strings.TrimSpace(out))
	if len(f) == 0 {
		return errors.New(i18n.T("등록 토큰을 만들지 못했습니다"))
	}
	token := f[len(f)-1]
	if _, err := run(agent, "join", "--hub", "http://127.0.0.1:8700", "--token", token); err != nil {
		return err
	}
	// 직접 빌드한 릴리스의 키: 이 서버 Agent의 자동 업데이트도 이 키를 믿게
	if s.Opt.TrustedKey != "" {
		kb, err := os.ReadFile(s.Opt.TrustedKey)
		if err != nil {
			return err
		}
		if err := os.WriteFile("/etc/douve-agent/"+update.TrustedKeysFile, kb, 0o600); err != nil {
			return err
		}
	}
	if s.Opt.Mode == "public" {
		if s.Opt.TestPlain {
			_ = os.MkdirAll("/etc/douve-agent", 0o700)
			_ = os.WriteFile("/etc/douve-agent/edge.json", []byte(`{"http_addr":":80","serve_plain":true}`), 0o600)
		}
		if _, err := run("/usr/local/bin/douve-hub", "node-set", "--name", name, "--edge", "on"); err != nil {
			return err
		}
		// 집 공유기 뒤라면 80/443 포트포워딩을 공유기에 요청할지 (클라우드는 방화벽 안내만)
		s.cloud = collect.DetectCloud(collect.DMIDir)
		if s.cloud == "" && behindNAT() && !s.Opt.TestPlain {
			s.say("\n  이 서버는 공유기 뒤(사설 IP)에 있습니다.")
			if s.yesNo("공유기에서 80·443을 자동으로 열까요? (UPnP/NAT-PMP, 나중에 서버 화면에서 끌 수 있음)", true) {
				if _, err := run("/usr/local/bin/douve-hub", "node-set", "--name", name, "--port-forward", "on"); err != nil {
					return err
				}
				s.portForward = true
			}
		}
	}
	if _, err := run(agent, "install-service"); err != nil {
		return err
	}
	if _, err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := run("systemctl", "enable", "--now", "douve-agent"); err != nil {
		return err
	}
	s.say("  douve-agent 실행 중 (서버 이름: %s)", name)
	return nil
}

func (s *Installer) finish(ctx context.Context) error {
	if s.Opt.Mode == "tailscale" {
		s.say("\n완료! Tailscale에 연결된 기기에서 여세요:\n\n    %s\n", s.publicURL())
		s.say("  Tailscale 사용자 %s로 바로 로그인됩니다 (비밀번호 없음). 웹 터미널을 쓰려면 계정 화면에서 패스키를 등록하세요.", s.Opt.Email)
		s.say("  다른 서버 추가: Douve → 서버 → \"서버 추가\"")
		return nil
	}
	url := s.publicURL() + "/healthz"
	if s.Opt.TestPlain {
		url = "http://127.0.0.1/healthz"
	}
	s.say("  %s 확인 중 (인증서 발급에 1분쯤 걸릴 수 있음)…", s.publicURL())
	reqHost := ""
	if s.Opt.TestPlain {
		reqHost = "localhost"
	}
	if err := waitHost(ctx, url, reqHost, 120*time.Second); err != nil {
		s.say("  ! 아직 접속되지 않습니다: %v", err)
		s.say("    DNS에서 %s 와 *.%s 가 이 서버의 공인 IP를 가리키는지, 방화벽(클라우드 보안 그룹)에서 80·443이 열려 있는지 확인하세요.",
			s.Opt.Domain, parentDomain(s.Opt.Domain))
		if g, ok := cloudGuide[s.cloud]; ok {
			s.say("    %s: %s", g[0], i18n.T(g[1]))
		} else if s.portForward {
			s.say("    공유기 포트 자동 열기 결과는 Douve → 서버 → 이 서버의 '외부에서 접속'에서 볼 수 있습니다. 공유기가 지원하지 않으면 공유기 관리 화면에서 TCP 80·443을 이 서버로 포트포워딩하세요.")
		}
	} else {
		s.say("  접속 확인 ✓")
	}
	outb, err := exec.Command("/usr/local/bin/douve-hub", "invite", "--email", s.Opt.Email).Output()
	if err != nil {
		return fmt.Errorf(i18n.T("초대 링크 생성 실패: %w"), err)
	}
	out := string(outb)
	s.say("\n완료! 아래 링크를 열어 이 브라우저(기기)에 패스키를 만들면 바로 시작합니다 (24시간 유효):\n\n    %s\n", strings.TrimSpace(out))
	if codes, err := exec.Command("/usr/local/bin/douve-hub", "recovery-codes", "--email", s.Opt.Email).Output(); err == nil {
		s.say("  비상용 복구 코드 (패스키 기기를 모두 잃었을 때 한 번씩 사용 — 지금 서버 밖에 적어 두세요):\n")
		for _, c := range strings.Fields(string(codes)) {
			s.say("    %s", c)
		}
		s.say("")
	}
	s.say("  다른 서버 추가: Douve → 서버 → \"서버 추가\"")
	return nil
}

func waitHost(ctx context.Context, url, host string, d time.Duration) error {
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if host != "" {
			req.Host = host
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		last = err
		time.Sleep(2 * time.Second)
	}
	return last
}

func parentDomain(d string) string {
	if i := strings.Index(d, "."); i > 0 && strings.Count(d, ".") >= 2 {
		return d[i+1:]
	}
	return d
}

// behindNAT: 기본 경로로 나가는 이 서버의 주소가 사설 IP인지 (공유기 뒤).
func behindNAT() bool {
	gw, err := portmap.DefaultGateway("/proc/net/route")
	if err != nil {
		return false
	}
	ip, err := portmap.LocalIPFor(net.JoinHostPort(gw.String(), "5351"))
	return err == nil && ip.IsPrivate()
}

// cloudGuide: 클라우드 방화벽에서 80·443을 여는 곳 (웹 화면의 안내와 같은 문구)
var cloudGuide = map[string][2]string{
	"oci":          {"Oracle Cloud", "OCI 콘솔 → 네트워킹 → 가상 클라우드 네트워크 → 서브넷의 보안 목록 → 수신 규칙 추가: 소스 0.0.0.0/0, TCP 80과 443."},
	"aws":          {"AWS", "EC2 콘솔 → 인스턴스 → 보안 → 보안 그룹 → 인바운드 규칙 편집: HTTP(80)·HTTPS(443), 소스 0.0.0.0/0."},
	"gcp":          {"Google Cloud", "VPC 네트워크 → 방화벽 → 방화벽 규칙 만들기: 수신, 이 VM, tcp:80,443, 소스 0.0.0.0/0 (또는 VM 수정에서 HTTP·HTTPS 트래픽 허용)."},
	"azure":        {"Azure", "가상 머신 → 네트워킹 → 인바운드 포트 규칙 추가: 80, 443."},
	"hetzner":      {"Hetzner", "Cloud 콘솔 → 방화벽(쓰는 경우) → 인바운드 규칙: TCP 80, 443."},
	"digitalocean": {"DigitalOcean", "Networking → Firewalls(쓰는 경우) → Inbound Rules: HTTP, HTTPS."},
	"vultr":        {"Vultr", "Network → Firewall(쓰는 경우) → TCP 80, 443 허용."},
	"linode":       {"Linode/Akamai", "Cloud Firewalls(쓰는 경우) → Inbound: TCP 80, 443 허용."},
	"scaleway":     {"Scaleway", "Security Groups → Inbound: TCP 80, 443 허용."},
}
