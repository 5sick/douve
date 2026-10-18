# Douve 빌드 진입점. `make help` 참고.
ifeq ($(origin VERSION), undefined)
VERSION := $(shell scripts/version.sh)
endif
SIGNING_KEY ?= $(HOME)/.config/douve/dev-signing.key
GO_LDFLAGS := -s -w -X github.com/5sick/douve/agent/internal/version.Version=$(VERSION)

.PHONY: help all hub hub-static agent test test-hub test-agent e2e fuzz fmt lint clean

help:
	@echo "make hub         - douve-hub 빌드 (build/hub/douve-hub)"
	@echo "make agent       - douve-agent 빌드 (dist/douve-agent-linux-{amd64,arm64})"
	@echo "make test        - 전체 테스트"
	@echo "make e2e         - E2E 테스트: 가짜 Google 서버 + Chromium 가상 인증기 패스키 흐름"
	@echo "                   (필요: python3-jwt, npx playwright install chromium-headless-shell)"
	@echo "make fmt         - 코드 포맷 (clang-format, gofmt)"
	@echo "make lint        - 정적 검사 (go vet, shellcheck)"
	@echo "make clean       - 빌드 산출물 삭제"

all: hub agent

hub:
	cmake -S hub -B build/hub -G Ninja -DDOUVE_VERSION=$(VERSION)
	cmake --build build/hub

hub-static:  ## 배포용 정적 douve-hub (Docker 필요, 현재 아키텍처) → dist/static/
	docker build -f packaging/hub-static/Dockerfile --build-arg VERSION=$(VERSION) -o type=local,dest=dist/static .

agent:
	@for arch in amd64 arm64; do \
		echo "build douve-agent linux/$$arch"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go -C agent build -trimpath \
			-ldflags "$(GO_LDFLAGS)" -o ../dist/douve-agent-linux-$$arch ./cmd/douve-agent || exit 1; \
	done
	cd dist && sha256sum douve-agent-linux-amd64 douve-agent-linux-arm64 > SHA256SUMS
	scripts/agent-licenses.sh > dist/THIRD_PARTY_LICENSES-agent.txt
	echo "$(VERSION)" > dist/VERSION
	CGO_ENABLED=0 go -C agent build -trimpath -o ../dist/douve-sign ./cmd/douve-sign
	@# 서명 키가 있으면 SHA256SUMS에 서명 (Agent는 서명 없는 업데이트를 받지 않는다)
	@if [ -f "$(SIGNING_KEY)" ]; then dist/douve-sign sign "$(SIGNING_KEY)" dist/SHA256SUMS "$(VERSION)"; \
	else echo "서명 키 없음($(SIGNING_KEY)) — 서명하지 않음"; rm -f dist/SHA256SUMS.minisig; fi

test: test-hub test-agent

test-hub: hub
	ctest --test-dir build/hub --output-on-failure

test-agent:
	go -C agent vet ./...
	go -C agent test ./...

e2e: hub agent
	tests/e2e/google_flow.sh build/hub/douve-hub
	tests/e2e/agent_flow.sh build/hub/douve-hub dist
	tests/e2e/edge_flow.sh build/hub/douve-hub dist
	tests/e2e/devnet_flow.sh build/hub/douve-hub dist
	tests/e2e/checkup_flow.sh build/hub/douve-hub dist
	tests/e2e/reach_flow.sh build/hub/douve-hub dist
	tests/e2e/settings_flow.sh build/hub/douve-hub
	tests/e2e/recovery_flow.sh build/hub/douve-hub
	tests/e2e/tailscale_flow.sh build/hub/douve-hub
	tests/e2e/rbac_flow.sh build/hub/douve-hub
	tests/e2e/security_flow.sh build/hub/douve-hub dist
	cd tests/e2e/browser && npm ci --no-audit --no-fund >/dev/null && node passkey_flow.mjs ../../../build/hub/douve-hub
	tests/e2e/terminal_flow.sh build/hub/douve-hub dist
	cd tests/e2e/browser && node invite_flow.mjs ../../../build/hub/douve-hub

fuzz:  ## 퍼징 (FUZZTIME=60초씩, clang·libclang-rt 필요)
	scripts/fuzz.sh all

fmt:
	find hub -name '*.cc' -o -name '*.h' | xargs clang-format -i
	gofmt -w agent

lint:
	go -C agent vet ./...
	@if ls deploy/*.sh >/dev/null 2>&1; then shellcheck deploy/*.sh; fi

clean:
	rm -rf build dist
