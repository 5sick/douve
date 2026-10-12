// Package update는 Hub가 지시한 Agent 자동 업데이트를 수행한다.
// 내려받은 파일의 SHA-256이 Hub가 (인증된 WebSocket으로) 알려준 값과 같을 때만 실행 파일을 교체하고,
// 프로세스를 끝내 systemd(Restart=always)가 새 버전으로 다시 띄우게 한다.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const maxSize = 64 << 20

// ErrRecentlyTried는 같은 체크섬을 최근(1시간)에 이미 시도했음을 뜻한다 (재시작 반복 방지).
var ErrRecentlyTried = errors.New("최근에 같은 업데이트를 시도함")

type guard struct {
	SHA256 string    `json:"sha256"`
	At     time.Time `json:"at"`
}

// StateDir는 systemd StateDirectory(없으면 /var/lib/douve-agent)다.
func StateDir() string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
		return d
	}
	return "/var/lib/douve-agent"
}

// Apply는 hubURL+path에서 새 바이너리를 받아 exe를 교체한다.
func Apply(ctx context.Context, hubURL, path, wantSHA, exe, stateDir string) error {
	if len(wantSHA) != 64 {
		return fmt.Errorf("체크섬 형식 오류")
	}
	guardPath := filepath.Join(stateDir, "last-update.json")
	if b, err := os.ReadFile(guardPath); err == nil {
		var g guard
		if json.Unmarshal(b, &g) == nil && g.SHA256 == wantSHA && time.Since(g.At) < time.Hour {
			return ErrRecentlyTried
		}
	}
	// 시도 기록을 먼저 남긴다 (교체 후 재시작이 실패해도 반복하지 않도록)
	if b, err := json.Marshal(guard{SHA256: wantSHA, At: time.Now()}); err == nil {
		_ = os.MkdirAll(stateDir, 0o700)
		_ = os.WriteFile(guardPath, b, 0o600)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hubURL+path, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("다운로드 HTTP %d", resp.StatusCode)
	}

	tmp := filepath.Join(filepath.Dir(exe), ".douve-agent.new")
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return err
	}
	defer os.Remove(tmp) // 성공하면 rename 후라 무해
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxSize+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > maxSize {
		return fmt.Errorf("파일이 너무 큼")
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA {
		return fmt.Errorf("체크섬 불일치 (받은 파일 %s…)", got[:12])
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, exe)
}
