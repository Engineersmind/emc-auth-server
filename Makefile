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
#
# TEST_FLAGS is shared by every target below so the two settings that the suite
# genuinely depends on cannot drift between them.
#
#   -p 1       Packages must run one at a time. They share a single database and
#              several truncate it between tests, so running two packages at once
#              has one wiping the other's fixtures mid-run. The symptom is a
#              different test failing on each run, which reads as flakiness rather
#              than as the configuration problem it is.
#
#   -timeout   20 minutes, not the 300s this used to be and not Go's 600s default.
#              internal/auth alone takes around 490s on a developer machine — every
#              test in it stands up a pool, runs migrations, and seeds a tenant — so
#              300s could never pass and 600s crosses over under any contention
#              (an app container sharing the database is enough). A timeout that
#              fires mid-suite panics the whole package, which looks like a code
#              failure and is not one.
#
# If this package's runtime keeps growing, the fix is faster fixtures — a shared
# migrated template database rather than migrating per test — not a larger number
# here.
TEST_FLAGS := -p 1 -timeout 20m

## Run all tests
.PHONY: test
test:
	go test ./... $(TEST_FLAGS)

## Run tests with coverage report
.PHONY: test-cover
test-cover:
	go test ./... -coverprofile=coverage.out -covermode=atomic $(TEST_FLAGS)
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"
	go tool cover -func=coverage.out | grep total

## Run tests with race detector
.PHONY: test-race
test-race:
	go test -race ./... $(TEST_FLAGS)

# LINT_VERSION and the two commands below must stay byte-identical to the
# "Lint + SAST" job in .github/workflows/ci.yml. They drifted once — the Makefile
# installed golangci-lint v1 (@latest) while CI pinned v2.10.1, and gosec ran a
# shorter exclude list here than there — so a clean `make check` said nothing
# about whether CI would pass. PR #111 failed on a staticcheck rule (SA4000) that
# the local linter never ran. If you change a flag in one place, change it in
# both.
LINT_VERSION := v2.10.1
GOSEC_EXCLUDE := G101,G117,G124,G401,G501

## Run golangci-lint (same version + flags as CI)
.PHONY: lint
lint:
	golangci-lint run --timeout=5m

## Run gosec security scanner (same exclude list as CI)
.PHONY: gosec
gosec:
	gosec -exclude=$(GOSEC_EXCLUDE) ./...

## Run govulncheck (CVE scan)
.PHONY: vuln
vuln:
	govulncheck ./...

## Run all quality gates (lint + gosec + vuln + test)
.PHONY: check
check: lint gosec vuln test

## Everything CI blocks on, in CI's own order, minus the Docker smoke test.
## Run this before every push: it is the only local target that can be trusted
## to predict the "Lint + SAST" and "Test" jobs.
.PHONY: ci-local
ci-local: lint gosec test
	@echo "ci-local: lint + gosec + tests passed"

## Run k6 load test (requires k6 installed and server running on localhost:9090)
.PHONY: load-test
load-test:
	k6 run scripts/load-test.js

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
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(LINT_VERSION)
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/swaggo/swag/cmd/swag@latest

# ─── Help ────────────────────────────────────────────────────────────────────

.PHONY: help
help:
	@grep -E '^## ' Makefile | sed 's/## //' | column -t -s '—'
