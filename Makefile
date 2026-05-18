## EMC Auth Server — Developer Makefile
## Usage: make <target>

BINARY     := emc-auth-server
CMD        := ./cmd/server
DOCKER_TAG := emc-auth-server:dev

# Default: build + run locally
.PHONY: all
all: build

# ─── Dev ────────────────────────────────────────────────────────────────────

## Start Postgres + Redis only (for native Go development)
.PHONY: deps
deps:
	docker-compose up -d postgres redis

## Start all services (app + deps) via Docker Compose
.PHONY: up
up:
	docker-compose up --build

## Start all services in background
.PHONY: up-d
up-d:
	docker-compose up --build -d

## Stop all services
.PHONY: down
down:
	docker-compose down

## Tail application logs
.PHONY: logs
logs:
	docker-compose logs -f app

## Open a psql shell to the dev database
.PHONY: psql
psql:
	docker-compose exec postgres psql -U emc_auth -d emc_auth

## Open a Redis CLI session
.PHONY: redis-cli
redis-cli:
	docker-compose exec redis redis-cli

# ─── Build ──────────────────────────────────────────────────────────────────

## Build the server binary
.PHONY: build
build:
	go build -o $(BINARY) $(CMD)

## Build with version + commit embedded
.PHONY: build-release
build-release:
	CGO_ENABLED=0 go build \
	  -ldflags="-s -w -X main.Version=$$(git describe --tags --always) -X main.Commit=$$(git rev-parse --short HEAD)" \
	  -o $(BINARY) $(CMD)

## Build Docker image
.PHONY: docker-build
docker-build:
	docker build -t $(DOCKER_TAG) .

## Run the binary (requires deps to be up)
.PHONY: run
run: build
	./$(BINARY)

# ─── Quality Gates ──────────────────────────────────────────────────────────

## Run all tests
.PHONY: test
test:
	go test ./... -timeout 120s

## Run tests with coverage report
.PHONY: test-cover
test-cover:
	go test ./... -coverprofile=coverage.out -covermode=atomic -timeout 120s
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"
	go tool cover -func=coverage.out | grep total

## Run tests with race detector
.PHONY: test-race
test-race:
	go test -race ./... -timeout 120s

## Run golangci-lint
.PHONY: lint
lint:
	golangci-lint run ./...

## Run gosec security scanner
.PHONY: gosec
gosec:
	gosec -exclude=G401,G501 ./...

## Run govulncheck (CVE scan)
.PHONY: vuln
vuln:
	govulncheck ./...

## Run all quality gates (lint + gosec + vuln + test)
.PHONY: check
check: lint gosec vuln test

# ─── Database ───────────────────────────────────────────────────────────────

## Apply all pending migrations (requires DATABASE_URL set or .env loaded)
.PHONY: migrate
migrate:
	go run ./cmd/server/ -migrate-only 2>&1 | head -30

## Reset database: drop + recreate + migrate + seed
.PHONY: db-reset
db-reset:
	docker-compose exec postgres psql -U emc_auth -c "DROP DATABASE IF EXISTS emc_auth; CREATE DATABASE emc_auth;"
	@echo "Database reset. Run 'make run' to migrate and seed."

# ─── Swagger ────────────────────────────────────────────────────────────────

## Regenerate Swagger docs from handler annotations
.PHONY: swagger
swagger:
	swag init -g cmd/server/main.go --output docs

# ─── Clean ──────────────────────────────────────────────────────────────────

## Remove build artifacts
.PHONY: clean
clean:
	rm -f $(BINARY) coverage.out coverage.html gosec.sarif

## Remove build artifacts + Docker resources
.PHONY: clean-all
clean-all: clean
	docker-compose down -v --remove-orphans
	docker rmi $(DOCKER_TAG) 2>/dev/null || true

# ─── Install dev tools ──────────────────────────────────────────────────────

## Install all required dev tools
.PHONY: tools
tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/swaggo/swag/cmd/swag@latest

# ─── Help ────────────────────────────────────────────────────────────────────

.PHONY: help
help:
	@grep -E '^## ' Makefile | sed 's/## //' | column -t -s '—'
