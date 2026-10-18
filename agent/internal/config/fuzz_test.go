package config

import (
	"net"
	"net/url"
	"strings"
	"testing"
)

// Hub 주소 검사: 통과한 주소는 http(s)이고 경로·사용자 정보가 없으며, http는 사설 IP에서만
func FuzzValidateHubURL(f *testing.F) {
	for _, s := range []string{"https://hub.example.com", "http://10.200.0.2:8700", "http://example.com", "https://u@x.com", "https://x.com/p"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		out, err := ValidateHubURL(raw)
		if err != nil {
			return
		}
		u, perr := url.Parse(out)
		if perr != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || (u.Path != "" && u.Path != "/") || u.Host == "" {
			t.Fatalf("잘못된 주소 통과: %q → %q", raw, out)
		}
		if u.Scheme == "http" {
			ip := net.ParseIP(strings.Trim(u.Hostname(), "[]"))
			if ip == nil || !(ip.IsPrivate() || ip.IsLoopback()) {
				t.Fatalf("공인 주소에 http 허용: %q", out)
			}
		}
	})
}
