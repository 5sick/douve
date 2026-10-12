package portmap

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"
)

// MapStatus는 포트 하나의 결과.
type MapStatus struct {
	Mapping
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Status는 Hub에 보고하는 공유기 상태.
type Status struct {
	Gateway    string      `json:"gateway"` // upnp | natpmp | "" (없음)
	ExternalIP string      `json:"external_ip,omitempty"`
	CGNAT      bool        `json:"cgnat"`
	Mappings   []MapStatus `json:"mappings"`
	Error      string      `json:"error,omitempty"`
	CheckedAt  int64       `json:"checked_at"`
}

const (
	lease = time.Hour
	renew = 20 * time.Minute
	desc  = "Douve"
)

// Manager는 Hub가 원하는 포트를 공유기에 열어 두고(수명 1시간, 20분마다 갱신) 결과를 보고한다.
type Manager struct {
	Opts   Options
	Log    *slog.Logger
	Report func(Status)

	mu      sync.Mutex
	desired []Mapping
	opened  map[Mapping]bool
	kick    chan struct{}
}

func NewManager(log *slog.Logger, report func(Status)) *Manager {
	return &Manager{Log: log, Report: report, opened: map[Mapping]bool{}, kick: make(chan struct{}, 1)}
}

// Set은 원하는 포트 목록을 바꾼다 (허용된 포트만). 바로 적용한다.
func (m *Manager) Set(ms []Mapping) {
	var ok []Mapping
	seen := map[Mapping]bool{}
	for _, x := range ms {
		if Allowed(x) && !seen[x] {
			seen[x] = true
			ok = append(ok, x)
		}
	}
	sort.Slice(ok, func(i, j int) bool { return ok[i].String() < ok[j].String() })
	m.mu.Lock()
	m.desired = ok
	m.mu.Unlock()
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// Run은 ctx가 끝날 때까지 돈다. 끝날 때 연 포트를 닫는다.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(renew)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.closeAll()
			return
		case <-m.kick:
		case <-t.C:
		}
		m.mu.Lock()
		want := append([]Mapping(nil), m.desired...)
		m.mu.Unlock()
		if len(want) == 0 && len(m.opened) == 0 {
			continue // 원하는 것도 연 것도 없으면 공유기를 건드리지 않는다
		}
		st := m.apply(ctx, want)
		if m.Report != nil {
			m.Report(st)
		}
	}
}

func (m *Manager) apply(ctx context.Context, want []Mapping) Status {
	st := Status{CheckedAt: time.Now().Unix(), Mappings: []MapStatus{}}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	gw, err := Discover(cctx, m.Opts)
	if err != nil {
		st.Error = err.Error()
		for _, w := range want {
			st.Mappings = append(st.Mappings, MapStatus{Mapping: w, Error: err.Error()})
		}
		return st
	}
	st.Gateway = gw.Kind()
	if ip, err := gw.ExternalIP(cctx); err == nil {
		st.ExternalIP = ip.String()
		st.CGNAT = IsCGNAT(ip)
	}
	gwAddr := m.Opts.NATPMP
	if gwAddr == "" {
		if g, err := DefaultGateway("/proc/net/route"); err == nil {
			gwAddr = net.JoinHostPort(g.String(), "5351")
		}
	}
	local, err := LocalIPFor(gwAddr)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	keep := map[Mapping]bool{}
	for _, w := range want {
		keep[w] = true
		ms := MapStatus{Mapping: w}
		if err := gw.Add(cctx, w, local, lease, desc); err != nil {
			ms.Error = err.Error()
			m.Log.Warn("공유기 포트 열기 실패", "port", w.String(), "gateway", gw.Kind(), "err", err)
		} else {
			ms.OK = true
			if !m.opened[w] {
				m.Log.Info("공유기 포트 열림", "port", w.String(), "gateway", gw.Kind(), "external_ip", st.ExternalIP)
			}
			m.opened[w] = true
		}
		st.Mappings = append(st.Mappings, ms)
	}
	for o := range m.opened {
		if !keep[o] {
			if err := gw.Delete(cctx, o); err != nil {
				m.Log.Warn("공유기 포트 닫기 실패", "port", o.String(), "err", err)
			} else {
				m.Log.Info("공유기 포트 닫음", "port", o.String())
			}
			delete(m.opened, o)
		}
	}
	return st
}

func (m *Manager) closeAll() {
	if len(m.opened) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gw, err := Discover(ctx, m.Opts)
	if err != nil {
		return
	}
	for o := range m.opened {
		_ = gw.Delete(ctx, o)
	}
}
