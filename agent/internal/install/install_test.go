package install

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func newTest(opt Options, input string) *Installer {
	return &Installer{Opt: opt, In: bufio.NewReader(strings.NewReader(input)), Out: io.Discard}
}

func TestChooseDefaultsAndNumbers(t *testing.T) {
	s := newTest(Options{}, "\n9\nx\n2\n")
	if got := s.choose("q", []string{"a", "b"}); got != 0 {
		t.Fatalf("Enter는 추천(0): %d", got)
	}
	if got := s.choose("q", []string{"a", "b"}); got != 1 {
		t.Fatalf("범위 밖·글자는 다시 묻고 2 → 1: %d", got)
	}
	if got := newTest(Options{Yes: true}, "2\n").choose("q", []string{"a", "b"}); got != 0 {
		t.Fatalf("--yes는 추천: %d", got)
	}
}

func TestCustomFeatures(t *testing.T) {
	s := newTest(Options{Features: "custom"}, "\nn\ny\nn\n")
	s.FeatureSet()
	want := map[string]bool{"monitoring": true, "service_checks": false, "terminal": true, "security": false}
	for k, v := range want {
		if s.Opt.FeatureSet[k] != v {
			t.Fatalf("%s = %v", k, s.Opt.FeatureSet[k])
		}
	}
	var j map[string]any
	if err := json.Unmarshal([]byte(s.featuresJSON()), &j); err != nil {
		t.Fatal(err)
	}
	if j["terminal"] != true || j["service_checks"] != false || j["security"].(map[string]any)["ssh"] != false {
		t.Fatalf("features JSON: %s", s.featuresJSON())
	}
}

func TestRecommendedAllOn(t *testing.T) {
	s := newTest(Options{Yes: true}, "")
	s.FeatureSet()
	for _, k := range []string{"monitoring", "service_checks", "terminal", "security"} {
		if !s.Opt.FeatureSet[k] {
			t.Fatalf("%s 꺼짐", k)
		}
	}
}

func TestParentDomain(t *testing.T) {
	for in, want := range map[string]string{"douve.example.com": "example.com", "example.com": "example.com", "a.b.c.d": "b.c.d"} {
		if got := parentDomain(in); got != want {
			t.Fatalf("%s → %s", in, got)
		}
	}
}

func TestMessagesFollowLanguage(t *testing.T) {
	t.Setenv("DOUVE_LANG", "en")
	var b strings.Builder
	s := &Installer{Out: &b}
	s.step(4, "접속 확인")
	s.say("  접속 확인 ✓")
	if got := b.String(); got != "\n[4] Check access\n  Access check ✓\n" {
		t.Fatalf("%q", got)
	}
}
