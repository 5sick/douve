#!/bin/sh
# Agent에 들어가는 Go 모듈(표준 라이브러리 포함)의 라이선스 고지를 모은다 → 표준 출력
set -eu
cd "$(dirname "$0")/../agent"
echo "Third-party software compiled into douve-agent"
echo
echo "================================================================"
echo "Go standard library $(go env GOVERSION) — BSD-3-Clause"
echo
if [ -f "$(go env GOROOT)/LICENSE" ]; then
    cat "$(go env GOROOT)/LICENSE"
else # 배포판 패키지가 LICENSE를 빼 둔 경우: Go 저장소의 BSD-3-Clause 원문
    cat <<'LICENSE'
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
LICENSE
fi
echo
# 실제로 빌드에 쓰이는 모듈만 (테스트 전용 제외)
for m in $(go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}}@{{.Version}}{{end}}{{end}}' ./cmd/douve-agent | sort -u); do
    dir=$(go mod download -json "$m" | sed -n 's/.*"Dir": "\(.*\)".*/\1/p')
    lic=$(ls "$dir" | grep -iE '^(LICENSE|LICENCE|COPYING)' | head -1)
    echo "================================================================"
    echo "$m"
    echo
    cat "$dir/$lic"
    echo
done
