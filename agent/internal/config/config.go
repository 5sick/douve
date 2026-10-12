// Package config는 Agent 설정 파일과 신원 키를 다룬다.
//
//	/etc/douve-agent/agent.json  Hub 주소, 노드 ID, 이름
//	/etc/douve-agent/key         Ed25519 개인키 시드 (32바이트, 권한 600)
package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/5sick/douve/agent/internal/i18n"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// DefaultDir는 설정 디렉터리 기본값이다.
const DefaultDir = "/etc/douve-agent"

// Config는 agent.json 내용이다.
type Config struct {
	HubURL string `json:"hub_url"`
	NodeID int64  `json:"node_id"`
	Name   string `json:"name"`
}

// Paths는 설정 디렉터리 안의 파일 경로를 돌려준다.
type Paths struct{ Dir string }

func (p Paths) ConfigFile() string { return filepath.Join(p.Dir, "agent.json") }
func (p Paths) KeyFile() string    { return filepath.Join(p.Dir, "key") }

// Load는 agent.json을 읽는다.
func (p Paths) Load() (*Config, error) {
	b, err := os.ReadFile(p.ConfigFile())
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", p.ConfigFile(), err)
	}
	if c.HubURL == "" || c.NodeID <= 0 {
		return nil, fmt.Errorf(i18n.T("%s: hub_url·node_id가 없습니다 (douve-agent join 먼저 실행)"), p.ConfigFile())
	}
	return &c, nil
}

// Save는 agent.json을 원자적으로 쓴다.
func (p Paths) Save(c *Config) error {
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return writeAtomic(p.ConfigFile(), append(b, '\n'), 0o600)
}

// LoadOrCreateKey는 개인키를 읽고, 없으면 새로 만든다.
func (p Paths) LoadOrCreateKey() (ed25519.PrivateKey, error) {
	if k, err := p.LoadKey(); err == nil {
		return k, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return nil, err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := writeAtomic(p.KeyFile(), seed, 0o600); err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// LoadKey는 개인키를 읽는다.
func (p Paths) LoadKey() (ed25519.PrivateKey, error) {
	seed, err := os.ReadFile(p.KeyFile())
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf(i18n.T("%s: 키 길이 오류"), p.KeyFile())
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ValidateHubURL은 Hub 주소를 검사해 정규화한다.
// https는 항상 허용, http는 WireGuard 같은 사설망·loopback 주소일 때만 허용한다
// (평문 구간이 공용 인터넷을 지나지 않도록).
func ValidateHubURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf(i18n.T("Hub 주소 형식 오류: %q"), raw)
	}
	if u.Path != "" || u.RawQuery != "" {
		return "", fmt.Errorf(i18n.T("Hub 주소에는 경로를 넣지 마세요: %q"), raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !(ip.IsLoopback() || ip.IsPrivate()) {
			return "", fmt.Errorf(i18n.T("http는 사설망 IP 주소에서만 허용됩니다 (https를 쓰세요): %q"), raw)
		}
	default:
		return "", fmt.Errorf(i18n.T("지원하지 않는 scheme: %q"), u.Scheme)
	}
	return u.String(), nil
}
