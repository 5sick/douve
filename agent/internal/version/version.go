// Package version은 빌드 시 -ldflags로 주입되는 버전 정보를 담는다.
package version

// Version은 릴리스 빌드에서 -ldflags "-X github.com/5sick/douve/agent/internal/version.Version=..."로 덮어쓴다.
var Version = "0.0.1-dev"

// String은 "douve-agent <버전>" 형식의 문자열을 반환한다.
func String() string {
	return "douve-agent " + Version
}
