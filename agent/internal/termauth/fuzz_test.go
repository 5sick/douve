package termauth

import (
	"testing"
	"time"
)

// 신뢰 목록 파서와 터미널 열기 검사: 어떤 입력에도 죽지 않고, 진짜 서명 없이는 통과하지 않는다
func FuzzOpen(f *testing.F) {
	f.Add(`{"v":1,"version":1,"origin":"https://h","rp_id":"h","keys":[]}`, "id", "e30", "AA", "AA", int64(0))
	f.Fuzz(func(t *testing.T, snap, id, cd, ad, sig string, ts int64) {
		if _, err := Parse(snap); err != nil {
			return
		}
		s := &Store{path: t.TempDir() + "/x", now: time.Now, seen: map[string]time.Time{}}
		if _, err := s.Apply([]Record{{Snapshot: snap}}); err != nil {
			return
		}
		a := &OpenAuth{TS: ts, Nonce: "nonce-0123456789abcdef", Assertion: Assertion{ID: id, ClientData: cd, AuthData: ad, Signature: sig}}
		if _, err := s.CheckOpen(1, "u", a); err == nil {
			t.Fatalf("임의 입력으로 터미널 열림: %q", snap)
		}
		// 서명 없는 변경은 받지 않는다
		if ch, _ := s.Apply([]Record{{Snapshot: snap}}); ch {
			t.Fatal("같은 판으로 바뀜")
		}
	})
}
