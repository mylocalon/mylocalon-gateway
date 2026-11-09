.PHONY: run build build-linux test test-redis vet gen-keys token

VERSION ?= 0.1.0-dev
LDFLAGS := -X github.com/mylocalon/mylocalon-gateway/internal/server.Version=$(VERSION)

run:
	set -a; [ -f .env ] && . ./.env; set +a; go run -ldflags "$(LDFLAGS)" ./cmd/gateway

build:
	go build -ldflags "$(LDFLAGS)" -o bin/gateway ./cmd/gateway

# Static Linux binary for the server (cross-compiles from macOS).
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(or $(ARCH),amd64) go build -trimpath -ldflags "$(LDFLAGS) -s -w" -o bin/gateway-linux ./cmd/gateway

test:
	go test -race ./...

# Also runs the Redis store contract tests against a local redis (db 15).
test-redis:
	ML_TEST_REDIS_URL=redis://localhost:6379/15 go test -race ./...

vet:
	gofmt -l . && go vet ./...

# Dev only: stands in for the Platform until mylocalon-platform exists.
gen-keys:
	go run ./cmd/devtoken -gen-keys -out keys

# make token SUB=usr_dev SUBDOMAINS=myapp
token:
	@go run ./cmd/devtoken -key keys/ed25519.key -sub $(or $(SUB),usr_dev) -subdomains "$(SUBDOMAINS)"
