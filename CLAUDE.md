# CLAUDE.md

Douve: 개인 서버 관리 도구. Hub(C++20/Drogon) + Agent(Go). 설계는 docs/ 참고.

## 명령
- `make test` — 전체 테스트 (변경 후 반드시 실행)
- `make hub` / `make agent` — 빌드
- `make fmt` — clang-format + gofmt

## 규칙
- 문서·주석·사용자 메시지는 한국어.
- 보안 관련 코드(인증, 세션, WebAuthn, 에이전트 인증)는 테스트 없이 머지하지 않는다.
- 설치 스크립트는 Ubuntu 26.04(sudo-rs, uutils coreutils)와 Rocky 9 양쪽에서 동작해야 한다.
  예: `install /dev/stdin` 금지, sudoers에 `requiretty` 금지.
- Agent는 CGO 없이 정적 빌드 (1GB x86 노드와 ARM 노드 모두 지원).


- 외부 HTTP(S) 요청은 `net/https_client`(libcurl)만 쓴다. Ubuntu의 Drogon/trantor는 TLS 없이 빌드되어 `drogon::HttpClient`가 https를 평문으로 보낸다.
