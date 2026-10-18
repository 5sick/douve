#!/bin/bash
# 퍼징: Hub(libFuzzer + AddressSanitizer/UBSan)와 Agent(Go 퍼징)의 모든 대상을 FUZZTIME초씩 돌린다.
#   scripts/fuzz.sh [hub|agent|all] (FUZZTIME=60 기본)
# 찾은 입력은 hub/fuzz/corpus/<대상>/ 로 옮겨 회귀 시험 씨앗으로 남긴다 (Go는 testdata/fuzz/에 자동 저장).
set -euo pipefail
cd "$(dirname "$0")/.."
T=${FUZZTIME:-60}
WHAT=${1:-all}
fail=0

if [ "$WHAT" != agent ]; then
    cmake -S hub -B build/fuzz -G Ninja -DDOUVE_FUZZ=ON -DDOUVE_BUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_CXX_COMPILER=clang++ \
        -DCMAKE_CXX_FLAGS="-fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=undefined -g -O1" >/dev/null
    cmake --build build/fuzz >/dev/null
    mkdir -p build/fuzz/work build/fuzz/artifacts
    mkdir -p build/fuzz/work/fuzz_webauthn && build/fuzz/fuzz_seedgen build/fuzz/work/fuzz_webauthn >/dev/null
    for bin in build/fuzz/fuzz_*; do
        name=$(basename "$bin")
        [ -f "$bin" ] && [ -x "$bin" ] || continue
        case "$name" in fuzz_seedgen | *.*) continue ;; esac
        mkdir -p "build/fuzz/work/$name"
        [ -d "hub/fuzz/corpus/$name" ] && cp -n hub/fuzz/corpus/"$name"/* "build/fuzz/work/$name/" 2>/dev/null || true
        if "$bin" "build/fuzz/work/$name" -max_total_time="$T" -rss_limit_mb=2048 -print_final_stats=1 \
            -artifact_prefix=build/fuzz/artifacts/"$name"- >"build/fuzz/$name.log" 2>&1; then
            echo "ok   $name ($(grep -o 'stat::number_of_executed_units: [0-9]*' "build/fuzz/$name.log" | awk '{print $2}')회)"
        else
            echo "FAIL $name — build/fuzz/$name.log, 입력: build/fuzz/artifacts/"; fail=1
        fi
    done
fi

if [ "$WHAT" != hub ]; then
    for target in $(cd agent && grep -rl '^func Fuzz' --include=*_test.go internal); do
        pkg=./$(dirname "$target")
        for fn in $(grep -o '^func Fuzz[A-Za-z0-9]*' "agent/$target" | awk '{print $2}'); do
            if (cd agent && go test "$pkg" -run '^$' -fuzz "^$fn\$" -fuzztime "${T}s" >/dev/null 2>&1); then
                echo "ok   $pkg $fn"
            else
                echo "FAIL $pkg $fn — 재현: cd agent && go test $pkg -run '^$' -fuzz '^$fn\$'"; fail=1
            fi
        done
    done
fi
exit $fail
