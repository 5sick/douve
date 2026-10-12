package config

import (
	"bytes"
	"os"
	"testing"
)

func TestValidateHubURL(t *testing.T) {
	ok := map[string]string{
		"https://douve.example.com":  "https://douve.example.com",
		"https://douve.example.com/": "https://douve.example.com",
		"http://10.200.0.2:8700":     "http://10.200.0.2:8700",
		"http://127.0.0.1:8700":      "http://127.0.0.1:8700",
		"http://192.168.1.5":         "http://192.168.1.5",
	}
	for in, want := range ok {
		got, err := ValidateHubURL(in)
		if err != nil || got != want {
			t.Errorf("%q → %q, %v (want %q)", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"http://douve.example.com", // 공용 인터넷 평문
		"http://8.8.8.8",
		"ftp://10.0.0.1",
		"https://douve.example.com/sub",
		"douve.example.com",
		"",
	} {
		if _, err := ValidateHubURL(bad); err == nil {
			t.Errorf("%q: 거부해야 함", bad)
		}
	}
}

func TestKeyPersistsWithStrictMode(t *testing.T) {
	p := Paths{Dir: t.TempDir()}
	k1, err := p.LoadOrCreateKey()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := p.LoadOrCreateKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("다시 읽은 키가 다름")
	}
	st, _ := os.Stat(p.KeyFile())
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("키 권한 %v", st.Mode().Perm())
	}
}

func TestConfigRoundTrip(t *testing.T) {
	p := Paths{Dir: t.TempDir()}
	if _, err := p.Load(); err == nil {
		t.Fatal("없는 설정은 오류여야 함")
	}
	if err := p.Save(&Config{HubURL: "https://h", NodeID: 3, Name: "n"}); err != nil {
		t.Fatal(err)
	}
	c, err := p.Load()
	if err != nil || c.NodeID != 3 || c.Name != "n" {
		t.Fatalf("%+v %v", c, err)
	}
}
