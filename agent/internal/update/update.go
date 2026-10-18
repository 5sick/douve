// Package update는 Hub가 지시한 Agent 자동 업데이트를 수행한다.
// Hub를 그대로 믿지 않는다: Hub가 함께 보낸 SHA256SUMS가 신뢰하는 키(공식 릴리스 키 또는 이 서버의
// trusted-keys)로 서명되어 있고, 서명의 버전이 지시한 버전과 같고 지금보다 이전이 아니며, 내려받은 파일의
// SHA-256이 그 목록과 같을 때만 실행 파일을 교체한다. 그래서 Hub가 뚫려도 서명 없는 프로그램을 심을 수 없다.
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
	"strings"
	"time"

	"github.com/5sick/douve/agent/internal/sign"
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

// Release는 Hub의 업데이트 지시.
type Release struct {
	Version string // 새 버전
	Path    string // 내려받을 경로 (/dl/douve-agent-linux-<arch>)
	SHA256  string // Hub가 알려 준 체크섬 (서명된 목록과 같아야 함)
	Sums    string // SHA256SUMS 원문
	Sig     string // SHA256SUMS.minisig
}

// Verify는 서명을 확인하고 이 아키텍처 파일의 체크섬을 돌려준다.
func Verify(keys []sign.PublicKey, r Release, arch, current string) (string, error) {
	if r.Sig == "" {
		return "", errors.New("서명 없는 릴리스는 받지 않습니다 (SHA256SUMS.minisig 없음)")
	}
	trusted, err := sign.Verify(keys, []byte(r.Sums), r.Sig)
	if err != nil {
		return "", fmt.Errorf("릴리스 서명 확인 실패: %w", err)
	}
	if v := sign.CommentField(trusted, "version"); v != r.Version {
		return "", fmt.Errorf("서명된 버전(%s)과 지시한 버전(%s)이 다릅니다", v, r.Version)
	}
	if sign.Older(r.Version, current) {
		return "", fmt.Errorf("이전 버전(%s → %s)으로는 바꾸지 않습니다", current, r.Version)
	}
	name := "douve-agent-linux-" + arch
	for _, line := range strings.Split(r.Sums, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			if r.SHA256 != "" && r.SHA256 != f[0] {
				return "", errors.New("Hub가 알려 준 체크섬이 서명된 목록과 다릅니다")
			}
			return f[0], nil
		}
	}
	return "", fmt.Errorf("서명된 목록에 %s가 없습니다", name)
}

// Apply는 서명을 확인한 뒤 hubURL+path에서 새 바이너리를 받아 exe를 교체한다.
func Apply(ctx context.Context, hubURL string, r Release, keys []sign.PublicKey, arch, current, exe, stateDir string) error {
	wantSHA, err := Verify(keys, r, arch, current)
	if err != nil {
		return err
	}
	path := r.Path
	if !strings.HasPrefix(path, "/dl/douve-agent-linux-") || strings.ContainsAny(path, "?#") || strings.Contains(path, "..") {
		return errors.New("잘못된 다운로드 경로")
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
