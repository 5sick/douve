package sign

import (
	"strings"
	"testing"
	"time"
)

func TestSignVerify(t *testing.T) {
	t.Setenv("DOUVE_LANG", "ko") // 오류 문구를 한국어로 확인
	sk, pk, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("abc  douve-agent-linux-amd64\n")
	tc := TrustedComment("v0.2.0", "SHA256SUMS", time.Unix(1700000000, 0))
	sig, err := Sign(sk, data, tc)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify([]PublicKey{pk}, data, sig)
	if err != nil || got != tc || CommentField(got, "version") != "v0.2.0" {
		t.Fatalf("%q %v", got, err)
	}
	// 내용·신뢰 주석·다른 키
	if _, err := Verify([]PublicKey{pk}, append(data, 'x'), sig); err == nil {
		t.Fatal("내용이 바뀌면 실패해야 함")
	}
	tampered := strings.Replace(sig, "version:v0.2.0", "version:v9.9.9", 1)
	if _, err := Verify([]PublicKey{pk}, data, tampered); err == nil {
		t.Fatal("신뢰 주석(버전)을 바꾸면 실패해야 함")
	}
	_, other, _ := Generate()
	if _, err := Verify([]PublicKey{other}, data, sig); err == nil || !strings.Contains(err.Error(), "신뢰하는 키") {
		t.Fatalf("다른 키: %v", err)
	}
	if _, err := Verify(nil, data, "garbage"); err == nil {
		t.Fatal("형식 오류")
	}
}

func TestKeyRoundTrip(t *testing.T) {
	sk, pk, _ := Generate()
	p2, err := ParsePublicKey(pk.String())
	if err != nil || !p2.Key.Equal(pk.Key) || p2.ID != pk.ID {
		t.Fatal(err)
	}
	p3, err := ParsePublicKey(pk.Line())
	if err != nil || p3.IDHex() != pk.IDHex() {
		t.Fatal(err)
	}
	s2, err := ParseSecretKey(sk.String())
	if err != nil || !s2.Public().Key.Equal(pk.Key) {
		t.Fatal(err)
	}
}

func TestOlder(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"v0.1.0", "v0.2.0", true},
		{"v0.2.0", "v0.1.0", false},
		{"v0.2.0", "v0.2.0", false},
		{"v0.2.0", "v0.2.0-3-gabc123", true},
		{"v0.2.0-3-gabc", "v0.2.0-12-gdef", true},
		{"v0.10.0", "v0.9.9", false},
		{"ec341c2", "v0.2.0", false}, // 판단할 수 없으면 막지 않음
		{"v0.2.0-dirty-2026", "v0.2.0", false},
	}
	for _, c := range cases {
		if got := Older(c.a, c.b); got != c.want {
			t.Fatalf("Older(%q, %q) = %v", c.a, c.b, got)
		}
	}
}
