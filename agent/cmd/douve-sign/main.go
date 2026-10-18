// douve-sign은 릴리스 서명 도구다 (배포하지 않음, CI와 개발자용).
//
//	douve-sign keygen <비밀키 파일> <공개키 파일>
//	douve-sign sign <비밀키 파일> <서명할 파일> <버전>     → <파일>.minisig
//	douve-sign verify <공개키 파일> <파일>                 (minisign -Vm 과 같음)
//
// 비밀키는 DOUVE_SIGNING_KEY 환경 변수로도 줄 수 있다 (파일 자리에 "-").
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/5sick/douve/agent/internal/sign"
)

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "douve-sign: "+format+"\n", a...)
	os.Exit(1)
}

func readKey(path string) string {
	if path == "-" {
		if v := os.Getenv("DOUVE_SIGNING_KEY"); v != "" {
			return v
		}
		die("DOUVE_SIGNING_KEY가 비어 있습니다")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		die("%v", err)
	}
	return string(b)
}

func main() {
	if len(os.Args) < 2 {
		die("사용: keygen | sign | verify")
	}
	switch os.Args[1] {
	case "keygen":
		if len(os.Args) != 4 {
			die("사용: douve-sign keygen <비밀키 파일> <공개키 파일>")
		}
		sk, pk, err := sign.Generate()
		if err != nil {
			die("%v", err)
		}
		if err := os.WriteFile(os.Args[2], []byte(sk.String()), 0o600); err != nil {
			die("%v", err)
		}
		if err := os.WriteFile(os.Args[3], []byte(pk.String()), 0o644); err != nil {
			die("%v", err)
		}
		fmt.Printf("키 ID %s\n공개키: %s\n", pk.IDHex(), pk.Line())
	case "sign":
		if len(os.Args) != 5 {
			die("사용: douve-sign sign <비밀키 파일|-> <파일> <버전>")
		}
		sk, err := sign.ParseSecretKey(readKey(os.Args[2]))
		if err != nil {
			die("%v", err)
		}
		data, err := os.ReadFile(os.Args[3])
		if err != nil {
			die("%v", err)
		}
		sig, err := sign.Sign(sk, data, sign.TrustedComment(os.Args[4], filepath.Base(os.Args[3]), time.Now()))
		if err != nil {
			die("%v", err)
		}
		if err := os.WriteFile(os.Args[3]+".minisig", []byte(sig), 0o644); err != nil {
			die("%v", err)
		}
		fmt.Printf("서명: %s.minisig (키 %s)\n", os.Args[3], sk.Public().IDHex())
	case "verify":
		if len(os.Args) != 4 {
			die("사용: douve-sign verify <공개키 파일> <파일>")
		}
		pk, err := sign.ParsePublicKey(readKey(os.Args[2]))
		if err != nil {
			die("%v", err)
		}
		data, err := os.ReadFile(os.Args[3])
		if err != nil {
			die("%v", err)
		}
		sig, err := os.ReadFile(os.Args[3] + ".minisig")
		if err != nil {
			die("%v", err)
		}
		tc, err := sign.Verify([]sign.PublicKey{pk}, data, string(sig))
		if err != nil {
			die("%v", err)
		}
		fmt.Printf("서명 확인 ✓ (%s)\n", tc)
	default:
		die("알 수 없는 명령 %q", os.Args[1])
	}
}
