// Package client는 Hub와의 통신(등록, WebSocket 상시 접속)을 담당한다.
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/5sick/douve/agent/internal/collect"
	"github.com/5sick/douve/agent/internal/config"
	"github.com/5sick/douve/agent/internal/features"
	"github.com/5sick/douve/agent/internal/update"
	"github.com/5sick/douve/agent/internal/version"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

// AuthMessage는 Hub의 agentAuthMessage와 같아야 한다.
func AuthMessage(nonce string, nodeID int64) string {
	return "douve-agent-auth:v1:" + nonce + ":" + strconv.FormatInt(nodeID, 10)
}

var b64 = base64.RawURLEncoding

// Enroll은 일회용 토큰으로 Hub에 이 노드를 등록한다.
func Enroll(ctx context.Context, hubURL, token string, key ed25519.PrivateKey) (*config.Config, error) {
	host, _ := os.Hostname()
	body, _ := json.Marshal(map[string]string{
		"token":    token,
		"pubkey":   b64.EncodeToString(key.Public().(ed25519.PublicKey)),
		"hostname": host,
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
		"version":  version.Version,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hubURL+"/api/agent/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Hub 접속 실패: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var out struct {
		NodeID int64  `json:"node_id"`
		Name   string `json:"name"`
		Error  string `json:"error"`
	}
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusOK || out.NodeID <= 0 {
		if out.Error == "" {
			out.Error = strings.TrimSpace(string(raw))
		}
		return nil, fmt.Errorf("등록 거부 (HTTP %d): %s", resp.StatusCode, out.Error)
	}
	return &config.Config{HubURL: hubURL, NodeID: out.NodeID, Name: out.Name}, nil
}

func wsURL(hubURL string) string {
	switch {
	case strings.HasPrefix(hubURL, "https://"):
		return "wss://" + strings.TrimPrefix(hubURL, "https://") + "/api/agent/connect"
	case strings.HasPrefix(hubURL, "http://"):
		return "ws://" + strings.TrimPrefix(hubURL, "http://") + "/api/agent/connect"
	}
	return hubURL
}

// ErrUpdated는 자동 업데이트로 실행 파일을 교체했음을 뜻한다. 프로세스를 끝내 systemd가 새 버전을 띄우게 한다.
var ErrUpdated = errors.New("새 버전으로 교체됨")

// ErrRejected는 Hub가 인증을 거부했음을 뜻한다 (노드 삭제 등). 재시도 간격을 길게 둔다.
var ErrRejected = errors.New("Hub가 인증을 거부했습니다")

// Run은 ctx가 끝날 때까지 Hub에 접속을 유지한다 (끊기면 지수 백오프로 재접속).
// 자동 업데이트로 실행 파일을 바꿨으면 ErrUpdated를 돌려준다 (호출자가 새 실행 파일로 교체 실행).
func Run(ctx context.Context, cfg *config.Config, key ed25519.PrivateKey, h Handlers, log *slog.Logger) error {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := session(ctx, cfg, key, h, log)
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, ErrUpdated) {
			log.Info("자동 업데이트 완료, 새 버전으로 재시작합니다")
			return ErrUpdated
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second // 한동안 잘 붙어 있었으면 처음부터
		}
		wait := backoff + time.Duration(rand.Int64N(int64(backoff/2)+1))
		if errors.Is(err, ErrRejected) {
			wait = 5 * time.Minute
		}
		log.Warn("Hub 접속 끊김, 재접속 대기", "err", err, "wait", wait.Round(time.Second))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		backoff = min(backoff*2, time.Minute)
	}
	return nil
}

type hubMsg struct {
	Type              string          `json:"type"`
	Version           string          `json:"version"`
	Path              string          `json:"path"`
	SHA256            string          `json:"sha256"`
	Nonce             string          `json:"nonce"`
	Name              string          `json:"name"`
	Error             string          `json:"error"`
	MetricsInterval   int             `json:"metrics_interval"`
	InventoryInterval int             `json:"inventory_interval"`
	Features          json.RawMessage `json:"features"`
}

func applyUpdate(ctx context.Context, cfg *config.Config, msg hubMsg, log *slog.Logger) error {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return err
	}
	log.Info("자동 업데이트 시작", "from", version.Version, "to", msg.Version)
	err = update.Apply(ctx, cfg.HubURL, msg.Path, msg.SHA256, exe, update.StateDir())
	if err != nil {
		log.Warn("자동 업데이트 실패", "err", err)
	}
	return err
}

func readMsg(ctx context.Context, c *websocket.Conn) (hubMsg, error) {
	m, _, err := readRaw(ctx, c)
	return m, err
}

func readRaw(ctx context.Context, c *websocket.Conn) (hubMsg, []byte, error) {
	var m hubMsg
	_, data, err := c.Read(ctx)
	if err != nil {
		return m, nil, err
	}
	err = json.Unmarshal(data, &m)
	return m, data, err
}

// Handlers는 Hub가 보내는 역할별 메시지 처리기다 (nil이면 무시).
type Handlers struct {
	// Routes는 입구(edge) 라우팅 표 메시지 원문을 받는다.
	Routes func(raw []byte)
	// Connected는 인증이 끝난 연결로 Hub에 보낼 함수를 준다. 끊기면 Disconnected.
	Connected    func(send func(v any) error)
	Disconnected func()
	// Message는 그 밖의 메시지(터미널 등) 원문을 받는다.
	Message func(typ string, raw []byte)
	// Inventory에 덧붙일 값 (예: 터미널 허용 계정)
	TerminalUsers func() []string
}

func writeJSON(ctx context.Context, c *websocket.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return c.Write(ctx, websocket.MessageText, b)
}

func session(ctx context.Context, cfg *config.Config, key ed25519.PrivateKey, h Handlers, log *slog.Logger) error {
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	c, _, err := websocket.Dial(dialCtx, wsURL(cfg.HubURL), &websocket.DialOptions{
		HTTPHeader: http.Header{"User-Agent": {version.String()}},
	})
	cancel()
	if err != nil {
		return err
	}
	defer c.CloseNow()
	c.SetReadLimit(1 << 20)

	// 1) 챌린지 → 서명
	hsCtx, hsCancel := context.WithTimeout(ctx, 10*time.Second)
	defer hsCancel()
	m, err := readMsg(hsCtx, c)
	if err != nil {
		return fmt.Errorf("챌린지 수신: %w", err)
	}
	if m.Type != "challenge" || m.Nonce == "" {
		return fmt.Errorf("예상하지 못한 메시지: %s", m.Type)
	}
	sig := ed25519.Sign(key, []byte(AuthMessage(m.Nonce, cfg.NodeID)))
	if err := writeJSON(hsCtx, c, map[string]any{
		"type": "auth", "node_id": cfg.NodeID, "sig": b64.EncodeToString(sig), "version": version.Version,
	}); err != nil {
		return err
	}
	m, err = readMsg(hsCtx, c)
	if err != nil {
		var ce websocket.CloseError
		if errors.As(err, &ce) && ce.Code == websocket.StatusPolicyViolation {
			return fmt.Errorf("%w: %s", ErrRejected, ce.Reason)
		}
		return fmt.Errorf("인증 응답: %w", err)
	}
	if m.Type == "error" {
		return fmt.Errorf("%w: %s", ErrRejected, m.Error)
	}
	if m.Type != "welcome" {
		return fmt.Errorf("예상하지 못한 메시지: %s", m.Type)
	}
	log.Info("Hub 접속 완료", "name", m.Name, "hub", cfg.HubURL)
	if len(m.Features) > 0 {
		if err := features.Apply(m.Features); err != nil {
			log.Warn("기능 설정 형식 오류", "err", err)
		}
	}

	metricsEvery := time.Duration(max(m.MetricsInterval, 5)) * time.Second
	invEvery := time.Duration(max(m.InventoryInterval, 30)) * time.Second

	// 2) 읽기 루프 (Hub 메시지 처리 + 끊김 감지)
	sessCtx, sessCancel := context.WithCancel(ctx)
	defer sessCancel()
	readErr := make(chan error, 1)
	go func() {
		for {
			msg, raw, err := readRaw(sessCtx, c)
			if err != nil {
				readErr <- err
				return
			}
			switch msg.Type {
			case "routes":
				if h.Routes != nil {
					h.Routes(raw)
				}
			case "config":
				if len(msg.Features) > 0 && features.Apply(msg.Features) == nil {
					log.Info("기능 설정 갱신", "features", string(msg.Features))
				}
			case "error":
				readErr <- fmt.Errorf("%w: %s", ErrRejected, msg.Error)
				return
			case "update":
				if err := applyUpdate(sessCtx, cfg, msg, log); err == nil {
					readErr <- ErrUpdated
					return
				}
			default:
				if h.Message != nil {
					h.Message(msg.Type, raw)
				}
			}
		}
	}()

	if h.Connected != nil {
		h.Connected(func(v any) error { return writeJSON(sessCtx, c, v) })
	}
	if h.Disconnected != nil {
		defer h.Disconnected()
	}

	// 3) 보내기 루프
	mc := collect.NewCollector()
	ic := collect.NewInventoryCollector()
	ic.TerminalUsers = h.TerminalUsers
	mc.Collect() // CPU·네트워크 기준값
	if err := writeJSON(sessCtx, c, ic.Collect(sessCtx)); err != nil {
		return err
	}
	mt := time.NewTicker(metricsEvery)
	it := time.NewTicker(invEvery)
	defer mt.Stop()
	defer it.Stop()
	for {
		select {
		case <-ctx.Done():
			c.Close(websocket.StatusNormalClosure, "agent 종료")
			return nil
		case err := <-readErr:
			return err
		case <-mt.C:
			m := mc.Collect() // 끈 상태여도 CPU·네트워크 기준값은 계속 갱신
			if !features.Get().Monitoring {
				continue
			}
			if err := writeJSON(sessCtx, c, m); err != nil {
				return err
			}
		case <-it.C:
			if err := writeJSON(sessCtx, c, ic.Collect(sessCtx)); err != nil {
				return err
			}
		}
	}
}
