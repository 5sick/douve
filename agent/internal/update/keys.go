package update

import (
	"bufio"
	"os"
	"strings"

	"github.com/5sick/douve/agent/internal/sign"
)

// ReleaseKeys는 공식 릴리스 서명 공개키 (minisign 형식, github.com/5sick/douve 릴리스의 SHA256SUMS.minisig).
// 키를 바꿀 때는 새 키를 먼저 추가한 릴리스를 낸 뒤 옛 키를 뺀다.
var ReleaseKeys = []string{
	"RWSAXEv+Y7MKiWfICcWzr0WkYGW6Tt92A6+Zxc5hPK1WlzaRvSgAb1ec", // 890AB363FE4B5C80 (2026-10-12)
}

// TrustedKeysFile은 직접 빌드한 Agent를 쓸 때 추가로 믿을 공개키 목록 (설정 디렉터리, 한 줄에 하나).
const TrustedKeysFile = "trusted-keys"

// TrustedKeys는 공식 키 + 설정 디렉터리의 trusted-keys 파일에 적힌 키.
// 파일은 root만 쓸 수 있는 설정 디렉터리에 있어 Hub가 바꿀 수 없다.
func TrustedKeys(path string) []sign.PublicKey {
	var out []sign.PublicKey
	for _, k := range ReleaseKeys {
		if p, err := sign.ParsePublicKey(k); err == nil {
			out = append(out, p)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "untrusted comment:") {
			continue
		}
		if p, err := sign.ParsePublicKey(line); err == nil {
			out = append(out, p)
		}
	}
	return out
}
