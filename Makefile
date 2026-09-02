.PHONY: build lint sec test test-race dev fmt check

# Build every package.
build:
	go build ./...

# Vet.
lint:
	go vet ./...

# Unit tests. This repository deliberately has no test that needs a network,
# a database, or a Cloudflare account: the safety properties it claims are
# meant to be checkable by anyone who clones it.
test:
	go test ./...

test-race:
	go test -race -count=1 ./...

fmt:
	gofmt -w .

# Security analysis (gosec, through golangci-lint so //nolint:gosec is honoured).
# Same linter and same version CI pins; see .golangci.yml for what is excluded.
# It fails rather than skips when the tool is absent: a security check that
# quietly does nothing is the failure this gate exists to prevent.
sec:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint not found. Install v2.13.2 to match CI:"; \
		echo "  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2"; \
		exit 1; }
	golangci-lint run ./...

# What CI runs, in the order CI runs it.
check: lint sec build test-race
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./...

# Local HTTP transport on :8093. MS_INTERNAL_SECRET gates every route except
# /healthz and /consent — the consent page is gated on its sealed reference, so
# a browser can open it. There is no database to point at — see README.
dev:
	cd cmd/dns-delegate-api && go run .
