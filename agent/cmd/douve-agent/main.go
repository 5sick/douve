// douve-agent는 각 노드에서 실행되어 Hub에 먼저 연결(outbound)하는 에이전트다.
//
//	douve-agent join --hub <주소> --token <토큰>   이 서버를 Hub에 등록
//	douve-agent run                               Hub에 접속해 상태 전송 (systemd가 실행)
//	douve-agent install-service                   systemd 유닛 설치
//	douve-agent status                            등록 정보 출력
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/5sick/douve/agent/internal/client"
	"github.com/5sick/douve/agent/internal/collect"
	"github.com/5sick/douve/agent/internal/config"
	"github.com/5sick/douve/agent/internal/ctl"
	"github.com/5sick/douve/agent/internal/edge"
	"github.com/5sick/douve/agent/internal/features"
	"github.com/5sick/douve/agent/internal/health"
	"github.com/5sick/douve/agent/internal/i18n"
	"github.com/5sick/douve/agent/internal/install"
	"github.com/5sick/douve/agent/internal/portmap"
	"github.com/5sick/douve/agent/internal/security"
	"github.com/5sick/douve/agent/internal/service"
	"github.com/5sick/douve/agent/internal/term"
	"github.com/5sick/douve/agent/internal/tunnel"
	"github.com/5sick/douve/agent/internal/update"
	"github.com/5sick/douve/agent/internal/version"
)

func usage() {
	fmt.Fprint(os.Stderr, i18n.T(`사용법:
  douve-agent install [--mode tailscale|public] [--domain 주소] [--email 이메일]
                    [--features recommended|custom] [--yes] [--from 폴더]   (빈 서버에 Douve 설치)
  douve-agent join --hub <Hub 주소> --token <토큰> [--force]
  douve-agent run
  douve-agent expose <포트> [--name 이름] [--host 도메인] [--path /경로] [--public]
  douve-agent unexpose <이름>
  douve-agent exposed
  douve-agent install-service
  douve-agent status
  douve-agent version
공통 옵션: --dir <설정 디렉터리> (기본 /etc/douve-agent)
`))
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	if cmd == "install" { // 자체 옵션을 쓴다
		if err := runInstall(args); err != nil {
			fmt.Fprintln(os.Stderr, "douve-agent install:", err)
			os.Exit(1)
		}
		return
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dir := fs.String("dir", config.DefaultDir, i18n.T("설정 디렉터리"))
	hub := fs.String("hub", "", i18n.T("Hub 주소 (join)"))
	token := fs.String("token", "", i18n.T("일회용 등록 토큰 (join)"))
	force := fs.Bool("force", false, i18n.T("이미 등록되어 있어도 다시 등록 (join)"))
	_ = fs.Parse(args)
	paths := config.Paths{Dir: *dir}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	var err error
	switch cmd {
	case "join":
		err = join(paths, *hub, *token, *force)
	case "run":
		err = run(paths, log)
	case "install-service":
		exe, e := os.Executable()
		if e != nil {
			err = e
			break
		}
		err = service.Install(exe)
		if err == nil {
			fmt.Println(i18n.T("설치됨:"), service.UnitPath)
		}
	case "expose", "unexpose", "exposed":
		err = runCtl(cmd, args)
	case "status":
		c, e := paths.Load()
		if e != nil {
			err = e
			break
		}
		fmt.Printf(i18n.T("Hub: %s\n노드: %s (id %d)\n"), c.HubURL, c.Name, c.NodeID)
	case "version", "--version", "-version":
		fmt.Println(version.String())
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "douve-agent:", err)
		os.Exit(1)
	}
}

// pendingReqs는 Hub에 보낸 요청(rid)의 답을 기다린다.
type pendingReqs struct {
	mu sync.Mutex
	m  map[string]chan json.RawMessage
}

func (p *pendingReqs) add(rid string) chan json.RawMessage {
	ch := make(chan json.RawMessage, 1)
	p.mu.Lock()
	p.m[rid] = ch
	p.mu.Unlock()
	return ch
}

func (p *pendingReqs) done(rid string) {
	p.mu.Lock()
	delete(p.m, rid)
	p.mu.Unlock()
}

func (p *pendingReqs) deliver(rid string, raw json.RawMessage) {
	p.mu.Lock()
	ch := p.m[rid]
	p.mu.Unlock()
	if ch != nil {
		select {
		case ch <- raw:
		default:
		}
	}
}

// runCtl은 expose/unexpose/exposed CLI다 (실행 중인 Agent 데몬에 요청).
func runCtl(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	name := fs.String("name", "", i18n.T("서비스 이름 (기본: 포트를 쓰는 프로세스·컨테이너 이름)"))
	host := fs.String("host", "", i18n.T("공개 도메인 (기본: <이름>.<기본 도메인>)"))
	path := fs.String("path", "", i18n.T("경로 접두사 (예: /api)"))
	public := fs.Bool("public", false, i18n.T("로그인 없이 누구나 (기본: Douve 로그인 필요)"))
	var positional []string
	// 플래그와 위치 인자를 섞어 쓸 수 있게 (expose 3000 --public)
	rest := args
	for len(rest) > 0 {
		_ = fs.Parse(rest)
		rest = fs.Args()
		if len(rest) > 0 {
			positional = append(positional, rest[0])
			rest = rest[1:]
		}
	}
	req := ctl.Request{Lang: i18n.Lang(), Op: map[string]string{"expose": "expose", "unexpose": "unexpose", "exposed": "list"}[cmd],
		Name: *name, Host: *host, Path: *path, Auth: "douve"}
	if *public {
		req.Auth = "public"
	}
	switch cmd {
	case "expose":
		if len(positional) != 1 {
			return errors.New(i18n.T("사용: douve-agent expose <포트> [--name 이름] [--host 도메인] [--path /경로] [--public]"))
		}
		port, err := strconv.Atoi(positional[0])
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf(i18n.T("포트가 올바르지 않습니다: %s"), positional[0])
		}
		req.Port = port
	case "unexpose":
		if len(positional) != 1 {
			return errors.New(i18n.T("사용: douve-agent unexpose <이름>"))
		}
		req.Name = positional[0]
	}
	resp, err := ctl.Call(update.StateDir(), req)
	if err != nil {
		return err
	}
	if !resp.OK {
		return errors.New(resp.Error)
	}
	switch cmd {
	case "expose":
		fmt.Println(i18n.T("공개됨:"), resp.URL)
		if resp.Warning != "" {
			fmt.Println(i18n.T("주의:"), resp.Warning)
		}
		if req.Auth == "douve" {
			fmt.Println(i18n.T("(Douve 로그인 필요. 누구나 열게 하려면 --public)"))
		}
	case "unexpose":
		fmt.Println(i18n.T("공개 해제됨"))
	default:
		if len(resp.Services) == 0 {
			fmt.Println(i18n.T("이 서버에서 공개한 서비스가 없습니다"))
		}
		for _, raw := range resp.Services {
			var s struct {
				Name, URL, Upstream, Auth string
			}
			_ = json.Unmarshal(raw, &s)
			fmt.Printf("%-16s %-40s → %s (%s)\n", s.Name, s.URL, s.Upstream, s.Auth)
		}
	}
	return nil
}

// hubLink는 현재 Hub 연결로 보내는 함수를 들고 있다 (연결이 바뀌면 교체).
type hubLink struct {
	mu sync.Mutex
	fn func(v any) error
}

func (h *hubLink) set(fn func(v any) error) {
	h.mu.Lock()
	h.fn = fn
	h.mu.Unlock()
}

func (h *hubLink) send(v any) error {
	h.mu.Lock()
	fn := h.fn
	h.mu.Unlock()
	if fn == nil {
		return errors.New(i18n.T("Hub에 연결되어 있지 않음"))
	}
	return fn(v)
}

func join(paths config.Paths, hub, token string, force bool) error {
	if hub == "" || token == "" {
		return errors.New(i18n.T("--hub 와 --token 이 필요합니다"))
	}
	hubURL, err := config.ValidateHubURL(hub)
	if err != nil {
		return err
	}
	if c, err := paths.Load(); err == nil && !force {
		return fmt.Errorf(i18n.T("이미 %s에 '%s'(으)로 등록되어 있습니다 (다시 등록하려면 --force)"), c.HubURL, c.Name)
	}
	if force {
		// 재등록은 새 키로 (예전 키가 유출됐을 수도 있으므로)
		_ = os.Remove(paths.KeyFile())
	}
	key, err := paths.LoadOrCreateKey()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := client.Enroll(ctx, hubURL, token, key)
	if err != nil {
		return err
	}
	if err := paths.Save(c); err != nil {
		return err
	}
	fmt.Printf(i18n.T("등록 완료: %s (id %d)\n"), c.Name, c.NodeID)
	return nil
}

func run(paths config.Paths, log *slog.Logger) error {
	c, err := paths.Load()
	if err != nil {
		return err
	}
	if _, err := config.ValidateHubURL(c.HubURL); err != nil {
		return err
	}
	key, err := paths.LoadKey()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("douve-agent 시작", "version", version.Version, "node", c.Name, "hub", c.HubURL)

	// 입구(edge) 역할: Hub가 라우팅 표를 보내면 시작. 저장된 표가 있으면 Hub 접속 전에도 바로 서비스.
	edgeCfg, err := edge.LoadConfig(filepath.Join(paths.Dir, "edge.json"))
	if err != nil {
		return err
	}
	edgeMgr := edge.NewManager(edgeCfg, update.StateDir(), log.With("part", "edge"))
	edgeMgr.Start()
	defer edgeMgr.Close()

	terms := term.NewManager(log.With("part", "term"))
	defer terms.CloseAll()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				terms.ReapIdle()
			}
		}
	}()

	// 보안 감시: 30초마다 모아 Hub로. 연결이 끊긴 동안의 사건은 쌓아 뒀다가 보낸다 (최대 2000개).
	hub := &hubLink{}
	if os.Geteuid() == 0 || security.TestHooksEnabled() {
		sec := security.New(update.StateDir(), terms.TTYOwner)
		sec.Enabled = func(kind string) bool { return features.Get().SecurityKind(kind) }
		interval := 30 * time.Second
		if d, err := time.ParseDuration(os.Getenv("DOUVE_TEST_SECURITY_INTERVAL")); err == nil && d > 0 {
			interval = d
		}
		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			var pending []security.Event
			for {
				pending = append(pending, sec.Collect(ctx, collect.PublicListeners("/proc"))...)
				if len(pending) > 2000 {
					pending = pending[len(pending)-2000:]
				}
				for len(pending) > 0 {
					n := min(len(pending), 200)
					if hub.send(map[string]any{"type": "security", "events": pending[:n]}) != nil {
						break
					}
					pending = pending[n:]
				}
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		}()
	}

	// 같은 서버의 root가 쓰는 제어 소켓 (douve-agent expose 등) → Hub에 물어서 답한다
	reqs := &pendingReqs{m: map[string]chan json.RawMessage{}}
	_ = ctl.Serve(ctx, update.StateDir(), func(rctx context.Context, req ctl.Request) ctl.Response {
		rid := fmt.Sprintf("%d", time.Now().UnixNano())
		ch := reqs.add(rid)
		defer reqs.done(rid)
		if err := hub.send(map[string]any{"type": "expose_req", "rid": rid, "op": req.Op, "port": req.Port,
			"name": req.Name, "host": req.Host, "path": req.Path, "auth": req.Auth, "lang": req.Lang}); err != nil {
			return ctl.Response{Error: i18n.In(req.Lang, "Hub에 연결되어 있지 않습니다")}
		}
		select {
		case raw := <-ch:
			var resp ctl.Response
			if json.Unmarshal(raw, &resp) != nil {
				return ctl.Response{Error: i18n.In(req.Lang, "Hub 응답 형식 오류")}
			}
			return resp
		case <-rctx.Done():
			return ctl.Response{Error: i18n.In(req.Lang, "Hub 응답 시간 초과")}
		}
	})

	// 터널: 이 서버의 서비스를 입구가 쓸 수 있게 (직통 길이 없어도). Hub가 주소·허용 목록을 보낸다.
	tun := tunnel.NewClient(c.NodeID, key, log.With("part", "tunnel"))
	go tun.Run(ctx)

	// 공유기 포트 자동 열기 (Hub가 원하는 포트만, 허용 목록 안에서)
	var lastPortmap atomic.Value // portmap.Status
	pm := portmap.NewManager(log.With("part", "portmap"), func(s portmap.Status) {
		lastPortmap.Store(s)
		_ = hub.send(map[string]any{"type": "portmap_status", "status": s})
	})
	if a := os.Getenv("DOUVE_TEST_NATPMP"); a != "" { // 시험용: 가짜 공유기
		pm.Opts = portmap.Options{Gateway: net.ParseIP("127.0.0.1"), NATPMP: a, SSDP: "127.0.0.1:9", Timeout: time.Second}
	}
	go pm.Run(ctx)
	// 서비스 상태 확인: 1분마다 로컬에서 확인해 Hub에 보고
	var checksMu sync.Mutex
	var checks []health.Check
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			checksMu.Lock()
			list := append([]health.Check(nil), checks...)
			checksMu.Unlock()
			if len(list) == 0 || !features.Get().ServiceChecks {
				continue
			}
			_ = hub.send(map[string]any{"type": "service_health", "results": health.Run(ctx, list)})
		}
	}()

	runErr := client.Run(ctx, c, key, client.Handlers{
		TerminalUsers: terms.AllowedUsers,
		Connected: func(send func(v any) error) {
			terms.SetSender(send)
			hub.set(send)
			if s, ok := lastPortmap.Load().(portmap.Status); ok {
				_ = send(map[string]any{"type": "portmap_status", "status": s})
			}
		},
		Disconnected: func() {
			hub.set(nil)
			terms.SetSender(nil)
			terms.CloseAll() // Hub 연결이 끊기면 터미널도 닫는다 (보이지 않는 셸 방지)
		},
		Message: func(typ string, raw []byte) {
			var m struct {
				SID  string `json:"sid"`
				User string `json:"user"`
				Data string `json:"data"`
				Cols int    `json:"cols"`
				Rows int    `json:"rows"`
			}
			if json.Unmarshal(raw, &m) != nil {
				return
			}
			if typ == "tunnel" {
				var tm struct {
					URL    string         `json:"url"`
					Allow  []string       `json:"allow"`
					Checks []health.Check `json:"checks"`
				}
				if json.Unmarshal(raw, &tm) == nil {
					log.Debug("터널 설정 수신", "url", tm.URL, "allow", len(tm.Allow))
					tun.Configure(tm.URL, tm.Allow)
					checksMu.Lock()
					checks = tm.Checks
					checksMu.Unlock()
				}
				return
			}
			if typ == "portmap" {
				var pmm struct {
					Mappings []portmap.Mapping `json:"mappings"`
				}
				if json.Unmarshal(raw, &pmm) == nil {
					pm.Set(pmm.Mappings)
				}
				return
			}
			if typ == "expose_res" {
				var r struct {
					RID string `json:"rid"`
				}
				if json.Unmarshal(raw, &r) == nil {
					reqs.deliver(r.RID, raw)
				}
				return
			}
			switch typ {
			case "term_open":
				if !features.Get().Terminal {
					_ = hub.send(map[string]any{"type": "term_exit", "sid": m.SID, "code": -1, "error": "이 서버에서 웹 터미널이 꺼져 있습니다"})
					return
				}
				go terms.Open(m.SID, m.User, m.Cols, m.Rows)
			case "term_in":
				terms.Input(m.SID, m.Data)
			case "term_resize":
				terms.Resize(m.SID, m.Cols, m.Rows)
			case "term_close":
				terms.Close(m.SID)
			}
		},
		Routes: func(raw []byte) {
			var t edge.Table
			if err := json.Unmarshal(raw, &t); err != nil {
				log.Warn("라우팅 표 형식 오류", "err", err)
				return
			}
			if err := edgeMgr.Apply(&t); err != nil {
				log.Warn("라우팅 표 거부", "err", err)
			}
		},
	}, log)
	if errors.Is(runErr, client.ErrUpdated) {
		// 프로세스를 끝내고 systemd 재시작(수 초)을 기다리는 대신 같은 PID에서 새 실행 파일로 바로 교체한다.
		// 입구(80/443)가 끊기는 시간이 수십 ms로 줄어든다. exec는 defer를 실행하지 않으므로 직접 정리.
		terms.CloseAll()
		edgeMgr.Close()
		exe, err := os.Executable()
		if err == nil {
			exe, err = filepath.EvalSymlinks(exe)
		}
		if err == nil {
			err = syscall.Exec(exe, os.Args, os.Environ())
		}
		log.Error("새 실행 파일로 교체 실패 — 종료해서 systemd가 재시작하게 함", "err", err)
		os.Exit(1)
	}
	return nil
}

func runInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	var o install.Options
	fs.StringVar(&o.Mode, "mode", "", "tailscale (Tailscale 안에서만) | public (내 도메인으로 공개)")
	fs.StringVar(&o.Domain, "domain", "", "public: Douve 주소 (예: douve.example.com)")
	fs.StringVar(&o.Email, "email", "", "관리자 이메일")
	fs.StringVar(&o.Features, "features", "", "recommended | custom")
	fs.BoolVar(&o.Yes, "yes", false, "묻지 않고 추천값으로")
	fs.StringVar(&o.From, "from", "", "릴리스 파일이 있는 로컬 폴더")
	fs.StringVar(&o.Release, "release", "", "릴리스 주소 (기본 GitHub 최신)")
	fs.BoolVar(&o.TestPlain, "test-plain", false, "시험용: 인증서 없이 평문 :80")
	_ = fs.Parse(args)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return install.New(o, os.Stdout).Run(ctx)
}
