package devnet

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/5sick/douve/agent/internal/edge"
)

// 기기가 보내는 DNS 질의: 어떤 입력에도 죽지 않고, 답한다면 올바른 DNS 응답이며 내부 도메인에만 답한다
func FuzzAnswer(f *testing.F) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("app.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	f.Add(q)
	f.Add([]byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	c := &edge.Devnet{Address: "10.201.0.1", Routes: []edge.Route{{Host: "app.example.com"}}}
	f.Fuzz(func(t *testing.T, query []byte) {
		out := answer(c, query)
		if out == nil {
			return
		}
		var p dnsmessage.Parser
		h, err := p.Start(out)
		if err != nil || !h.Response {
			t.Fatalf("잘못된 응답: %v", err)
		}
		qq, err := p.Question()
		if err != nil || !c.HasHost(lowerName(qq.Name.String())) {
			t.Fatalf("내부 도메인이 아닌 질의에 답함: %v", qq.Name)
		}
	})
}

func lowerName(s string) string {
	b := []byte(s)
	for i, ch := range b {
		if ch >= 'A' && ch <= 'Z' {
			b[i] = ch + 32
		}
	}
	if len(b) > 0 && b[len(b)-1] == '.' {
		b = b[:len(b)-1]
	}
	return string(b)
}
