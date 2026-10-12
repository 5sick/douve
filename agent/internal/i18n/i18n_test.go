package i18n

import (
	"net/http/httptest"
	"regexp"
	"testing"
)

func TestDictionaryVerbs(t *testing.T) {
	load()
	verbs := regexp.MustCompile(`%[a-z]`)
	for k, v := range dict {
		a, b := verbs.FindAllString(k, -1), verbs.FindAllString(v, -1)
		if len(a) != len(b) {
			t.Fatalf("형식 지정자가 다름: %q → %q", k, v)
		}
		for i := range a {
			if a[i] != b[i] {
				t.Fatalf("형식 지정자 순서가 다름: %q → %q", k, v)
			}
		}
	}
}

func TestLangAndIn(t *testing.T) {
	t.Setenv("DOUVE_LANG", "")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "ko_KR.UTF-8")
	if Lang() != "ko" || T("취소했습니다") != "취소했습니다" {
		t.Fatal("ko")
	}
	t.Setenv("LANG", "en_US.UTF-8")
	if Lang() != "en" || T("취소했습니다") != "Cancelled" {
		t.Fatal("en")
	}
	t.Setenv("DOUVE_LANG", "ko")
	if Lang() != "ko" {
		t.Fatal("DOUVE_LANG 우선")
	}
	if In("en", "사전에 없는 말") != "사전에 없는 말" {
		t.Fatal("없는 말은 원문")
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Language", "ko-KR,ko;q=0.9,en;q=0.8")
	if ForRequest(r) != "ko" {
		t.Fatal("Accept-Language ko")
	}
	r.Header.Set("Accept-Language", "en-US,ko;q=0.5")
	if ForRequest(r) != "en" {
		t.Fatal("Accept-Language en")
	}
}
