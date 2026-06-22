.PHONY: help generate build test test-integration lint run up down key tidy

help:
	@echo "Targets:"
	@echo "  generate          - regenerate sqlc code from queries.sql"
	@echo "  build             - build the binary"
	@echo "  test              - unit tests (race detector)"
	@echo "  test-integration  - integration tests (needs Docker)"
	@echo "  lint              - golangci-lint"
	@echo "  up / down         - docker compose up / down"
	@echo "  key               - print a fresh base64 MASTER_KEY"
	@echo "  tidy              - go mod tidy"

generate:
	sqlc generate

build:
	go build -o bin/cryptoguard ./cmd/cryptoguard

test:
	go test -race ./...

test-integration:
	go test -tags=integration ./...

lint:
	golangci-lint run

run:
	go run ./cmd/cryptoguard

up:
	docker compose up --build

down:
	docker compose down -v

key:
	@openssl rand -base64 32

tidy:
	go mod tidy
