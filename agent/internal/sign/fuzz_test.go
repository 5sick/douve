package sign

import (
	"testing"
	"time"
)

// 서명 파일·공개키 파싱: 아무 입력에도 멈추지 않고, 진짜 서명이 아니면 통과하지 않는다
func FuzzVerify(f *testing.F) {
	sk, pk, _ := Generate()
	sig, _ := Sign(sk, []byte("data"), TrustedComment("v1.0.0", "SHA256SUMS", time.Unix(1, 0)))
	f.Add([]byte("data"), sig)
	f.Add([]byte(""), "untrusted comment: x\nRUQ=\ntrusted comment: y\nAAAA\n")
	f.Fuzz(func(t *testing.T, data []byte, s string) {
		tc, err := Verify([]PublicKey{pk}, data, s)
		if err == nil && (string(data) != "data" || CommentField(tc, "version") != "v1.0.0") {
			// 같은 키로 만든 다른 서명은 이 시험에서 만들 수 없으므로, 통과는 원래 서명뿐이어야 한다
			t.Fatalf("위조 서명 통과: %q", tc)
		}
		_, _ = ParsePublicKey(s)
		_, _ = ParseSecretKey(s)
		_ = Older(s, "v1.2.3")
	})
}
