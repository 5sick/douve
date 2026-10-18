package edge

import (
	"encoding/json"
	"strings"
	"testing"
)

// 라우팅 표: 검사를 통과한 표에서 고른 서비스는 요청 호스트가 같고 경로가 접두사 아래여야 한다
func FuzzTable(f *testing.F) {
	f.Add([]byte(`{"verify_url":"http://h/auth/verify","login_url":"https://h/login","routes":[{"host":"a.example.com","upstream":"10.0.0.1:80","auth":"douve","path_prefix":"/api"}]}`), "a.example.com", "/api/x")
	f.Add([]byte(`{"routes":[{"host":"b.example.com","kind":"redirect","redirect_to":"https://x","auth":"public"}]}`), "B.example.com.", "/")
	f.Fuzz(func(t *testing.T, raw []byte, host, path string) {
		var tb Table
		if json.Unmarshal(raw, &tb) != nil || tb.Validate() != nil {
			return
		}
		r := tb.lookup(host, path)
		if r == nil {
			return
		}
		h := strings.ToLower(strings.TrimSuffix(host, "."))
		if i := strings.LastIndex(h, ":"); i >= 0 && !strings.Contains(h, "]") {
			h = h[:i]
		}
		if r.Host != h {
			t.Fatalf("다른 호스트의 서비스 선택: %q → %q", host, r.Host)
		}
		p := r.PathPrefix
		if p != "" && p != "/" && path != p && !strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/") {
			t.Fatalf("경로 접두사 밖: %q → %q", path, p)
		}
	})
}
