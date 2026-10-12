// Package i18n은 Agent가 사람에게 보여 주는 문구(설치기·CLI·입구 오류 화면)를 영어로 바꾼다.
// 원문은 한국어 그대로 두고, en.json에 같은 원문(형식 문자열이면 %s 등 포함)이 있으면 영어를 쓴다.
//
//	언어: DOUVE_LANG → LC_ALL → LC_MESSAGES → LANG 순으로 보고 ko로 시작하면 한국어, 아니면 영어
//	입구 오류 화면은 브라우저의 Accept-Language를 따른다 (ForRequest).
package i18n

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
)

//go:embed en.json
var enJSON []byte

var (
	once sync.Once
	dict map[string]string
)

func load() {
	once.Do(func() {
		dict = map[string]string{}
		_ = json.Unmarshal(enJSON, &dict)
	})
}

// Lang은 환경 변수로 정한 CLI 언어다 (ko | en).
func Lang() string {
	for _, k := range []string{"DOUVE_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" && v != "C" && v != "POSIX" {
			if strings.HasPrefix(strings.ToLower(v), "ko") {
				return "ko"
			}
			return "en"
		}
	}
	return "en"
}

// In은 lang이 en이면 영어 문구(없으면 원문), 아니면 원문.
func In(lang, s string) string {
	if lang != "en" {
		return s
	}
	load()
	if v, ok := dict[s]; ok {
		return v
	}
	return s
}

// T는 CLI 언어로 번역한다.
func T(s string) string { return In(Lang(), s) }

// ForRequest는 브라우저가 선호하는 언어 (Accept-Language 첫 항목이 ko면 ko).
func ForRequest(r *http.Request) string {
	al := strings.ToLower(strings.TrimSpace(r.Header.Get("Accept-Language")))
	if strings.HasPrefix(al, "ko") {
		return "ko"
	}
	return "en"
}
