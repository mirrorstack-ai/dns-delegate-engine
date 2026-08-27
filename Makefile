.PHONY: build lint test test-race dev fmt check

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

# What CI runs, in the order CI runs it.
check: lint build test-race
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./...

# Local HTTP transport on :8093. MS_INTERNAL_SECRET gates every route except
# /healthz. There is no database to point at — see README.
dev:
	cd cmd/dns-delegate-api && go run .
