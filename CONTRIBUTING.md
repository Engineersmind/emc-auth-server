# Contributing to EMC Auth Server

Thank you for contributing to EMC Auth Server. This guide covers the branch strategy, PR process, and code standards.

---

## Development Setup

```bash
# 1. Clone and install dependencies
git clone https://github.com/Engineersmind/emc-auth-server.git
cd emc-auth-server

# 2. Copy environment config
cp .env.example .env
# Edit .env with your local Postgres and Redis details

# 3. Start infrastructure
docker-compose up -d postgres redis

# 4. Build and run
go build -o emc-auth-server.exe ./cmd/server
./emc-auth-server.exe

# 5. Start UI dev server (separate terminal)
cd ui && npm install && npm run dev
```

---

## Branch Strategy

| Prefix | Purpose | Example |
|--------|---------|---------|
| `feat/` | New feature or phase | `feat/phase-9-oauth` |
| `fix/` | Bug fix | `fix/ui-auth-login-hydration` |
| `docs/` | Documentation only | `docs/update-api-reference` |
| `infra/` | CI/CD, Docker, workflows | `infra/add-arm64-build` |
| `refactor/` | Code restructure, no behavior change | `refactor/store-interface` |

**Rules:**
- Branch from `main`
- One concern per branch — no bundling unrelated fixes
- Merge via merge commit (no squash, no rebase) — preserves phase history
- Delete branch after merge

---

## Commit Message Format

```
type(scope): short description

Optional body — why, not what.
```

**Types:** `feat`, `fix`, `docs`, `infra`, `refactor`, `test`, `chore`

**Scope:** phase number or area — `(02)`, `(ui)`, `(auth)`, `(admin)`, `(ci)`

Examples:
```
feat(03): add TOTP enrollment with AES-256-GCM secret encryption
fix(ui): hydrate user state after cookie-based login
docs: update API reference with cross-tenant endpoints
```

---

## Pull Request Process

1. Open a PR against `main` using the [PR template](.github/PULL_REQUEST_TEMPLATE.md)
2. Fill in: summary, phase reference, changes checklist, security checklist, test plan
3. All CI checks must pass: tests, golangci-lint, gosec, govulncheck, Docker build
4. Review required from CODEOWNERS:
   - Auth/middleware/audit paths → `@EM-ShreyashGondane`
   - Migration files → `@dmisra`
5. No force-push to `main`
6. Squash is disabled — preserve commit history

---

## Code Standards

### Go
- Follow `gofmt` and `golangci-lint` rules (`.golangci.yml` in root)
- All SQL queries use pgx v5 positional parameters — never string interpolation
- All new handlers must emit an audit event via `AuditLogger`
- Error responses use the shared `echo.HTTPError` pattern — no raw `c.String()`
- Run before PR: `make test && make lint`

### TypeScript / React
- Strict TypeScript — no `any` types
- API calls go through `ui/src/api/` client modules — never fetch directly in components
- Permission checks use `useAuth()` context — never check `user.role` directly
- Run before PR: `cd ui && npm run build` (catches type errors)

### Migrations
- Goose SQL format — files in `migrations/`
- Naming: `NNNN_description.sql` (sequential number)
- Always include both `-- +goose Up` and `-- +goose Down` sections
- Never modify an existing migration — add a new one

### Security
- No secrets or credentials in code or comments
- No raw SQL string concatenation
- Rate limiting required on any public auth endpoint
- Audit log required on any state-changing admin endpoint

---

## Running Tests

```bash
# All tests
make test
# or
go test ./... -timeout 60s

# With coverage report
go test ./... -coverprofile=coverage.out && go tool cover -html=coverage.out

# Lint
make lint
# or
golangci-lint run ./...

# Security scan
gosec ./...
govulncheck ./...
```

---

## Regenerating Swagger Docs

After modifying handler annotations:

```bash
swag init -g cmd/server/main.go --output docs
```

Commit the updated `docs/` directory with your PR.

---

## Release Process

Releases are automated via `.github/workflows/release.yml`:

1. Merge all PRs for the release into `main`
2. Tag with semantic version: `git tag v1.x.0 && git push origin v1.x.0`
3. GitHub Actions publishes:
   - Docker image to GHCR (`ghcr.io/engineersmind/emc-auth-server:v1.x.0`)
   - Linux binaries (amd64 + arm64) attached to GitHub Release
4. Update `CHANGELOG.md` with the new version section before tagging

---

## Questions

Open a [GitHub Discussion](https://github.com/Engineersmind/emc-auth-server/discussions) or file an [Issue](https://github.com/Engineersmind/emc-auth-server/issues).
