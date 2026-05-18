# EMC Auth Server

A standalone, self-hosted, multi-tenant Identity Provider — EMC's drop-in replacement for Auth0.

Built with Go + Echo + PostgreSQL + Redis. Ships as a **single binary** that boots, migrates, seeds, and serves in under a second.

---

## Features

| Capability | Details |
|------------|---------|
| Multi-tenant | Tenant-scoped users, roles, permissions, and JWT secrets |
| JWT auth | HS256, per-tenant secret, 1-hour access + 30-day refresh |
| Refresh rotation | Atomic — old token revoked before new one issued; replay returns 401 |
| Password reset | SHA-256 hashed token, 15-min TTL, revokes all sessions on use |
| Rate limiting | 5 req/min/IP + 10 req/min/tenant on login |
| Admin API | Full tenant, user pool, role, and permission management |
| Audit logs | Every auth and admin event logged; tenant-scoped and system-wide views |
| Security headers | HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy |
| Swagger UI | Interactive docs at `/swagger/index.html` |
| Single binary | Migrations + seed embedded via `embed.FS` — no external tools needed |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Go 1.23 |
| HTTP framework | Echo v4 |
| Database | PostgreSQL 16 (pgx v5 driver, pgxpool) |
| Cache / sessions | Redis 7 |
| Migrations | Goose v3 (embedded SQL) |
| Logging | Zerolog (structured JSON) |
| API docs | Swaggo / echo-swagger |
| Passwords | bcrypt cost 12 |
| Tokens | JWT HS256 (golang-jwt/jwt v5) |

---

## Architecture

### Request Flow

```
Client
  │
  ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Echo HTTP Server                           │
│                                                                 │
│  ┌──────────────┐  ┌────────────────┐  ┌────────────────────┐  │
│  │  Request ID  │─►│Security Headers│─►│  HTTPS Redirect    │  │
│  │  (per-req)   │  │ HSTS/CSP/etc.  │  │  (production only) │  │
│  └──────────────┘  └────────────────┘  └─────────┬──────────┘  │
│                                                   │             │
│  ┌────────────────────────────────────────────────▼──────────┐  │
│  │              Request Logger (zerolog JSON)                │  │
│  └──────────────────────────┬─────────────────────────────┬─┘  │
│                             │                             │     │
│              ┌──────────────▼──────┐   ┌─────────────────▼──┐  │
│              │   Public Endpoints  │   │ Protected Endpoints │  │
│              │   /auth/*  /health  │   │ /admin/*  /auth/me  │  │
│              │                     │   │                     │  │
│              │  Rate Limiter       │   │  JWT Middleware      │  │
│              │  (login: 5/min/IP   │   │  (verify HS256,     │  │
│              │   10/min/tenant)    │   │   extract claims)   │  │
│              │                     │   │                     │  │
│              │  Tenant Resolution  │   │  Permission Guard   │  │
│              │  X-Tenant-Slug hdr  │   │  (tenant:manage or  │  │
│              │  → DB lookup → UUID │   │   admin:access)     │  │
│              └──────────┬──────────┘   └──────────┬──────────┘  │
│                         └──────────────┬───────────┘             │
│                                        │                         │
│                              ┌─────────▼──────────┐             │
│                              │      Handler        │             │
│                              │  (auth / admin)     │             │
│                              └───────┬─────┬───────┘             │
│                                      │     │                     │
│                         ┌────────────▼──┐ ┌▼────────────┐       │
│                         │  PostgreSQL   │ │    Redis    │       │
│                         │  pgxpool(25)  │ │  (sessions, │       │
│                         │  Users/Roles/ │ │   rate lim) │       │
│                         │  Audit/Tokens │ │             │       │
│                         └───────────────┘ └─────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

### JWT Token Flow

```
POST /auth/login
  │
  ├─► Resolve tenant (X-Tenant-Slug → tenants table)
  ├─► Verify bcrypt hash (cost 12)
  ├─► Load user roles + permissions from DB
  ├─► Sign JWT (HS256, per-tenant secret, 1-hour TTL)
  │     Payload: { user_id, tenant_id, email, role, permissions[], iss, aud, exp }
  ├─► Generate refresh token (32-byte crypto/rand → SHA-256 hash stored in Redis)
  └─► Return { access_token, refresh_token, token_type, expires_in }

POST /auth/refresh
  ├─► Hash incoming token → lookup in Redis
  ├─► Atomically: delete old token, store new token
  └─► Return new token pair (old token is immediately dead — replay → 401)
```

---

## Two-Tier Access Model

Every request resolves to one of three access tiers based on JWT claims:

```
┌──────────────────────────────────────────────────────────────────┐
│  Tier 1 — System Level (super_admin / tenant:manage)             │
│                                                                  │
│  • Create / update / deactivate any tenant                       │
│  • View system-wide audit log (all tenants)                      │
│  • Assign super_admin role                                       │
│  Scope: cross-tenant, system-wide                                │
├──────────────────────────────────────────────────────────────────┤
│  Tier 2 — Tenant Admin Level (admin:access)                      │
│                                                                  │
│  • Manage users within own tenant (create, update, delete)       │
│  • Create / manage roles and permissions within own tenant       │
│  • View tenant-scoped audit log (own tenant only)                │
│  • Force password reset for any user in tenant                   │
│  Scope: tenant-isolated, never cross-tenant                      │
├──────────────────────────────────────────────────────────────────┤
│  Tier 3 — Authenticated User                                     │
│                                                                  │
│  • Authenticate (login, refresh, logout)                         │
│  • View own profile (GET /auth/me)                               │
│  • Reset own password                                            │
│  Scope: own user record only                                     │
└──────────────────────────────────────────────────────────────────┘
```

Tier is determined from JWT claims at runtime — never from the request body. A token from tenant A cannot access tenant B's resources regardless of what the request contains.

---

## Role and Permission Model

```
Role (tenant-scoped)
  └── has many Permissions (tenant-scoped, UNIQUE per tenant)

User
  └── assigned one Role per tenant

JWT payload carries:
  { role: "super_admin", permissions: ["tenant:manage", "admin:access"] }

Seeded system permissions (emc tenant only):
  tenant:manage  →  Tier 1 guard — super_admin operations
  admin:access   →  Tier 2 guard — tenant admin operations

Tenant-created permissions (examples):
  invoice:read, invoice:write, report:export, user:impersonate
  (each tenant defines its own; names are isolated by tenant_id)
```

Permissions flow: tenant admin creates permissions → assigns to roles → assigns roles to users → JWT contains permission list → `RequirePermission()` middleware enforces at the route level.

---

## Quick Start — Docker (recommended)

**Prerequisites:** Docker Desktop running.

```bash
git clone https://github.com/Engineersmind/emc-auth-server.git
cd emc-auth-server

cp .env.example .env          # review and adjust if needed
docker-compose up --build
```

The server starts on **port 8080**. On first boot it automatically:
1. Runs all database migrations
2. Seeds the default `emc` tenant, `super_admin` role, and `admin@emc.local` user

Verify:
```bash
curl http://localhost:8080/health
# {"status":"ok","service":"emc-auth-server"}
```

Open the interactive API docs: [http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html)

---

## Quick Start — Native Go

**Prerequisites:** Go 1.23+, PostgreSQL 16, Redis 7.

```bash
git clone https://github.com/Engineersmind/emc-auth-server.git
cd emc-auth-server

# Start only the dependencies (Postgres + Redis)
docker-compose up -d postgres redis

# Copy and configure environment
cp .env.example .env

# Download dependencies
go mod download

# Build
go build -o emc-auth-server ./cmd/server/

# Run
./emc-auth-server
```

---

## Environment Variables

Copy `.env.example` to `.env` and adjust as needed:

```env
# Server
PORT=8080
ENV=development          # set to "production" to enable HTTPS redirect
LOG_LEVEL=info

# PostgreSQL
DATABASE_URL=postgres://emc_auth:password@localhost:5432/emc_auth?sslmode=disable

# Redis
REDIS_URL=redis://localhost:6379/0

# JWT
JWT_ISSUER=https://auth.emc.local

# Password reset link base (prepended to /api/v1/auth/reset-password?token=...)
APP_BASE_URL=http://localhost:8080

# Seed admin password (change this in production!)
SEED_ADMIN_PASSWORD=ChangeMe123!

# SMTP — optional. In development the reset link is logged to console instead.
SMTP_HOST=
SMTP_PORT=587
SMTP_FROM=noreply@emc.local
SMTP_USERNAME=
SMTP_PASSWORD=
```

---

## Default Credentials

After first boot the seed creates:

| Field | Value |
|-------|-------|
| Tenant slug | `emc` |
| Admin email | `admin@emc.local` |
| Admin password | value of `SEED_ADMIN_PASSWORD` (default: `ChangeMe123!`) |
| Admin role | `super_admin` |
| Admin permissions | `tenant:manage`, `admin:access` |

**Change the default password before exposing the server to any network.**

---

## Database Connection

Connect any SQL client (DBeaver, pgAdmin, TablePlus) to the local dev database:

```
Host:     localhost
Port:     5432
Database: emc_auth
Username: emc_auth
Password: password
```

---

## API Reference

### Authentication
> All public auth endpoints require the `X-Tenant-Slug` header (e.g. `X-Tenant-Slug: emc`)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/v1/auth/register` | — | Register a new user |
| POST | `/api/v1/auth/login` | — | Login — returns JWT + refresh token |
| POST | `/api/v1/auth/refresh` | — | Rotate refresh token |
| POST | `/api/v1/auth/logout` | — | Revoke refresh token |
| GET | `/api/v1/auth/me` | Bearer JWT | Get current user profile |
| POST | `/api/v1/auth/forgot-password` | — | Request password reset link |
| POST | `/api/v1/auth/reset-password` | — | Set new password with reset token |

### Admin — Tenant Management
> Requires `tenant:manage` permission (super_admin only)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/admin/tenants` | Create tenant |
| GET | `/api/v1/admin/tenants` | List all tenants |
| PUT | `/api/v1/admin/tenants/:id` | Update tenant name |
| DELETE | `/api/v1/admin/tenants/:id` | Soft-deactivate tenant |

### Admin — Roles & Permissions
> Requires `admin:access` permission

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/admin/permissions` | Create permission (tenant-scoped) |
| GET | `/api/v1/admin/permissions` | List permissions |
| DELETE | `/api/v1/admin/permissions/:id` | Delete permission |
| POST | `/api/v1/admin/roles` | Create role with permission assignments |
| GET | `/api/v1/admin/roles` | List roles (with embedded permissions) |
| PUT | `/api/v1/admin/roles/:id/permissions` | Replace role's permission set |
| DELETE | `/api/v1/admin/roles/:id` | Delete role |

### Admin — User Pool
> Requires `admin:access` permission

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/admin/users` | List users (`?search=&page=&limit=`) |
| POST | `/api/v1/admin/users` | Create user with optional role |
| GET | `/api/v1/admin/users/:id` | Get user details |
| PUT | `/api/v1/admin/users/:id` | Update user profile |
| PUT | `/api/v1/admin/users/:id/role` | Reassign role |
| DELETE | `/api/v1/admin/users/:id` | Soft-delete user |
| POST | `/api/v1/admin/users/:id/force-password-reset` | Send password reset email |

### Admin — Audit Logs

| Method | Endpoint | Guard | Description |
|--------|----------|-------|-------------|
| GET | `/api/v1/admin/audit-logs` | `admin:access` | Tenant-scoped event log |
| GET | `/api/v1/admin/audit-logs/system` | `tenant:manage` | System-wide log (all tenants) |

**Filters:** `?action=auth.login_failed&user_id=<uuid>&from=2026-01-01T00:00:00Z&to=...&page=1&limit=50`

---

## Using Swagger UI

1. Open [http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html)
2. Call `POST /api/v1/auth/login` with `X-Tenant-Slug: emc` and admin credentials
3. Copy the `access_token` from the response
4. Click **Authorize** (padlock icon, top right)
5. Enter `Bearer <your_access_token>` — **include the word Bearer**
6. All protected endpoints are now unlocked

---

## Multi-Tenant Architecture

Each tenant is fully isolated:

- **JWT secret** — per-tenant; tokens from tenant A cannot validate against tenant B
- **User pool** — `UNIQUE(tenant_id, email)`; same email can exist in different tenants
- **Roles and permissions** — per-tenant; two tenants can both define `invoice:read` independently
- **Audit log** — events are tagged with `tenant_id`; admins only see their own tenant's events

Tenant resolution on public endpoints: `X-Tenant-Slug` header → DB lookup → tenant UUID.
Tenant on protected endpoints: `tenant_id` claim inside the verified JWT — never from request body.

---

## Audit Events

Every security-relevant action is persisted to the `audit_logs` table:

| Action | Trigger |
|--------|---------|
| `auth.login` | Successful login |
| `auth.login_failed` | Wrong credentials |
| `auth.register` | New user registered |
| `auth.logout` | Logout |
| `auth.token_refresh` | Refresh token rotated |
| `auth.password_reset_requested` | Forgot-password called |
| `auth.password_reset_completed` | Password reset completed |
| `admin.tenant_created/updated/deactivated` | Tenant lifecycle |
| `admin.permission_created/deleted` | Permission management |
| `admin.role_created/permissions_updated/deleted` | Role management |
| `admin.user_created/updated/deleted` | User pool management |
| `admin.user_role_assigned` | Role reassigned |
| `admin.force_password_reset` | Admin-triggered reset |

Query the audit log via API (JSON) or directly in SQL:

```sql
-- Last 50 failed logins across all tenants
SELECT actor_email, ip_address, created_at
FROM audit_logs
WHERE action = 'auth.login_failed'
ORDER BY created_at DESC
LIMIT 50;

-- All admin actions on a specific user
SELECT action, actor_email, created_at
FROM audit_logs
WHERE resource_type = 'user'
  AND resource_id = '<user-uuid>'
ORDER BY created_at DESC;
```

---

## Architecture Decisions (ADR Index)

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| ADR-01 | JWT signing algorithm | HS256 per-tenant secret | Simpler key management for self-hosted deployments; RS256 (asymmetric) deferred to v2 when external verifiers need public keys |
| ADR-02 | Multi-tenancy strategy | `tenant_id` column (row-level) | Schema-per-tenant adds migration complexity and doesn't scale past ~100 tenants; row-level isolation is simpler and proven at scale |
| ADR-03 | Migration tool | Goose v3 (embedded SQL) | Plain SQL files version-controlled alongside code; embedded via `embed.FS` — zero external tooling at runtime |
| ADR-04 | ORM vs raw SQL | Raw SQL (pgx v5) | Auth queries are security-critical and latency-sensitive; full control over parameterization, no magic, no N+1 surprises |
| ADR-05 | Tenant resolution | `X-Tenant-Slug` header | Human-readable slug over UUID; slug is stable and meaningful in logs and URLs |
| ADR-06 | Rate limiter storage | In-memory (sync.Map + `x/time/rate`) | Sufficient for single-instance deployments; Redis-backed distributed limiting hooked in Phase 7 with explicit code comment |
| ADR-07 | Refresh token storage | SHA-256 hash in Redis | Raw token never stored; Redis TTL handles expiry automatically; hash prevents token extraction if cache is compromised |
| ADR-08 | Password hashing | bcrypt cost 12 | Industry standard; cost 12 gives ~300ms on modern hardware — strong against GPU brute-force while acceptable for login latency |
| ADR-09 | Audit log failure mode | Fire-and-forget | Audit failure must never block authentication; errors are logged via zerolog but never returned to caller |
| ADR-10 | Permission scope | Tenant-scoped (not system-global) | Permissions are business concepts owned by each tenant; system-global permissions would create cross-tenant coupling |
| ADR-11 | Admin UI delivery | React SPA embedded via `embed.FS` | Single deployable artifact — no separate static file server or CDN required for self-hosted deployment (Phase 6) |
| ADR-12 | Email enumeration prevention | `forgot-password` always returns HTTP 200 | Identical response body for registered and unregistered emails prevents user enumeration via timing or response diff |

---

## Security & Code Quality

### Implemented Controls

| Control | Implementation |
|---------|---------------|
| Password storage | bcrypt cost 12 — plaintext never persisted |
| SQL injection | Parameterized queries via pgx v5 positional args (`$1, $2, ...`) throughout |
| Token storage | Refresh and reset tokens stored as SHA-256 hashes — raw values never in DB |
| JWT integrity | HS256 signed with per-tenant secret; signature verified on every protected request |
| Session revocation | Logout and password reset atomically delete all Redis session keys for the user |
| Rate limiting | 5 req/min/IP + 10 req/min/tenant on `/auth/login` — returns `429 Too Many Requests` |
| Security headers | HSTS (1 year), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin` |
| Replay protection | Refresh token rotation is atomic — consumed token is deleted before new token is issued |
| Soft delete | Users marked `is_deleted=true` — IDs preserved for audit trail integrity |
| Enumeration prevention | `forgot-password` returns identical HTTP 200 for both registered and unregistered emails |
| Tenant isolation | JWT `tenant_id` claim is authoritative — never trust request body for tenant resolution on protected routes |

### Planned — Phase 7

```bash
# Static analysis (SAST)
gosec ./...                        # security-focused Go linter
govulncheck ./...                  # known CVE scan for dependencies
golangci-lint run                  # multi-linter: errcheck, staticcheck, unused, shadow

# Dependency audit
go list -m -json all | nancy sleuth   # OSS vulnerability database check

# Security test scenarios
# - Replay attack: re-submit consumed refresh token → assert 401
# - Brute-force: 6th login attempt in 1 min → assert 429
# - Email enumeration: diff forgot-password response for known vs unknown email → assert identical
# - TOTP bypass: submit expired/wrong OTP → assert 401 (Phase 3)
# - SQL injection probes on search and filter params

# Load test
k6 run --vus 500 --duration 60s load/login.js   # p99 ≤ 200ms target
```

### CI/CD Pipeline (Phase 7 — GitHub Actions)

```yaml
# .github/workflows/ci.yml (planned)
on: [push, pull_request]
jobs:
  quality:
    steps:
      - go test ./... -coverprofile=coverage.out   # ≥80% gate
      - gosec ./...
      - govulncheck ./...
      - golangci-lint run
  build:
    steps:
      - docker build --target prod .               # distroless final image
      - docker-compose up -d && sleep 5
      - curl -f http://localhost:8080/health
```

---

## Monitoring & Observability

### Currently Instrumented

| Signal | Implementation | Where to look |
|--------|---------------|---------------|
| Structured request logs | Zerolog JSON — method, path, status, latency, request_id | stdout / log aggregator |
| Health check | `GET /health` → `{"status":"ok","service":"emc-auth-server"}` | Uptime monitors |
| Audit trail | `audit_logs` table — 21 event types with tenant_id, user_id, IP | PostgreSQL / API |
| Error logging | Zerolog `Error()` on all DB/Redis failures with context fields | stdout |

### Observability Metrics (Planned — Phase 7)

`GET /metrics` — Prometheus-compatible endpoint:

```
# Authentication
emc_auth_login_total{tenant, result="success|failure"}
emc_auth_register_total{tenant}
emc_auth_token_refresh_total{tenant}
emc_auth_rate_limit_hits_total{tenant, type="ip|tenant"}

# Performance
emc_auth_request_duration_seconds{method, route, status}   histogram
emc_auth_db_query_duration_seconds{query}                  histogram
emc_auth_redis_op_duration_seconds{op}                     histogram

# System
emc_auth_active_sessions{tenant}
emc_auth_db_pool_acquired
emc_auth_db_pool_idle
```

### Grafana Dashboard (Planned — Phase 7)

```
Row 1 — Traffic Overview
  ├── Requests/sec (by endpoint)
  ├── Login success rate (success / total)
  └── Rate limit hit rate

Row 2 — Auth Health
  ├── Failed logins by tenant (bar chart — spike = brute-force attempt)
  ├── Token refresh volume
  └── Password reset requests

Row 3 — Performance
  ├── p50/p95/p99 request latency (heatmap)
  ├── DB query latency
  └── Redis operation latency

Row 4 — Infrastructure
  ├── DB connection pool utilization
  ├── Go runtime memory (heap in use)
  └── Goroutine count
```

### Alerting Rules (Planned — Phase 7)

| Alert | Condition | Severity |
|-------|-----------|----------|
| Auth spike | Login failures > 50/min/tenant | Warning |
| Brute-force | Rate limit hits > 100/min/IP | Critical |
| DB saturation | Pool acquired > 90% for 5 min | Warning |
| High latency | p99 login > 500ms for 2 min | Warning |
| Server down | `/health` fails 3 consecutive checks | Critical |

---

## Admin Dashboard — Phase 6

A React SPA embedded directly in the Go binary via `embed.FS` — no separate web server or CDN needed.

**Planned screens:**

| Screen | Capabilities |
|--------|-------------|
| Login | Email/password + TOTP (if enabled); establishes admin session |
| Dashboard | Active user count, recent login events, auth success rate tile |
| User Pool | Paginated + searchable table; create, edit, assign role, soft-delete, force reset |
| Roles & Permissions | Create/edit roles with permission assignments; create custom permissions |
| Tenant Management | Super-admin only — create, rename, deactivate tenants (cross-tenant view) |
| API Keys | Create (one-time reveal), list with last_used, revoke |
| SAML Config | Per-tenant IdP entity ID, SSO URL, X.509 cert |
| Audit Log Viewer | Filterable table — action type, date range, user, IP |

**Build pipeline:** Vite + React + TypeScript → `go generate` embeds the `ui/dist/` output into the binary → served at `/` by Echo static middleware.

---

## Enhancements — Planned Outside Main Roadmap

Items tracked for v2 (post-Phase 7):

| Enhancement | Description | Priority |
|-------------|-------------|----------|
| OAuth2 / OIDC server | Expose authorization_code + client_credentials flows so third-party apps can use EMC-Auth as a full OAuth2 provider | High |
| Social login | Google, GitHub, Microsoft OAuth2 login with account linking | Medium |
| Passwordless / magic link | Email-based one-click login for low-friction onboarding | Medium |
| RS256 JWT | Asymmetric signing — public key endpoint so external services can verify tokens without calling EMC-Auth | Medium |
| Webhooks | POST to a configured URL on user lifecycle events: `user.created`, `user.deleted`, `auth.login_failed` | Medium |
| SDK libraries | Node.js and Python client libraries for JWT verification and token introspection | Medium |
| White-label login page | Per-tenant custom logo, colors, and domain on the hosted login UI | Low |
| Audit log retention | Configurable retention window + archive to S3/GCS after N days | Low |
| Login anomaly detection | Flag logins from new country/device; alert admin or require MFA step-up | Low |
| CORS per tenant | Tenant-configurable allowed origins stored in DB; enforced by middleware | Low |
| Distributed rate limiting | Replace in-memory rate limiter with Redis-backed solution for multi-instance deployments | Phase 7 |
| Token introspection endpoint | `POST /oauth/introspect` — RFC 7662 token introspection for resource servers | v2 |

---

## Project Structure

```
emc-auth-server/
├── cmd/server/main.go       # entrypoint — wires everything and starts HTTP server
├── internal/
│   ├── admin/               # Admin service: tenant CRUD, user pool, role/permission CRUD
│   ├── api/
│   │   ├── handlers/        # HTTP handlers: auth.go, admin.go, health.go
│   │   └── middleware/      # jwt.go, permission.go, ratelimit.go, logger.go
│   ├── audit/               # Audit logger (write + paginated query)
│   ├── auth/                # JWT service, auth service, reset service, token utils
│   ├── config/              # Environment variable loader
│   ├── mailer/              # DevMailer (console) + SMTPMailer
│   └── store/               # DB pool, Redis client, migration runner, seed
├── migrations/              # Goose SQL files (00001–00016), embedded via embed.FS
├── docs/                    # Swagger-generated files (auto-generated, do not edit)
├── .env.example             # Template for local configuration
└── docker-compose.yml       # Postgres 16 + Redis 7 + app service
```

---

## Regenerating Swagger Docs

After adding or modifying handler annotations:

```bash
# Install swag if not already installed
go install github.com/swaggo/swag/cmd/swag@latest

swag init -g cmd/server/main.go --output docs
```

---

## Phase Tracking

### Progress Overview

```
Phase 1  Foundation            ████████████████████  COMPLETE  ✓  (3/3 plans)
Phase 2  Auth Engine           ████████████████████  COMPLETE  ✓  (4/4 plans)
Phase 3  TOTP + API Keys       ░░░░░░░░░░░░░░░░░░░░  PLANNED      (0/3 plans)
Phase 4  SAML 2.0              ░░░░░░░░░░░░░░░░░░░░  PLANNED      (0/2 plans)
Phase 5  Admin API             ████████████████████  COMPLETE  ✓  (3/3 plans)
Phase 6  Admin UI              ░░░░░░░░░░░░░░░░░░░░  PLANNED      (0/4 plans)
Phase 7  Testing & Hardening   ░░░░░░░░░░░░░░░░░░░░  PLANNED      (0/5 plans)
Phase 8  AI/Agent Security     ░░░░░░░░░░░░░░░░░░░░  PLANNED      (0/4 plans)
─────────────────────────────────────────────────────────────────
         3 of 8 phases complete  ·  10/21 sub-plans done  ·  37%
```

### Sub-plan Detail

<details>
<summary>Phase 1 — Foundation (COMPLETE)</summary>

| Plan | Description | Status |
|------|-------------|--------|
| 01-01 | Go module, Echo skeleton, logging, health, Dockerfile, docker-compose | ✓ Done |
| 01-02 | Goose migration files — all schema tables, FKs, indexes | ✓ Done |
| 01-03 | PostgreSQL + Redis pool, idempotent seed (tenant + super-admin) | ✓ Done |

</details>

<details>
<summary>Phase 2 — Auth Engine (COMPLETE)</summary>

| Plan | Description | Status |
|------|-------------|--------|
| 02-01 | Register, login, bcrypt cost 12, JWT HS256, `GET /auth/me` | ✓ Done |
| 02-02 | Refresh rotation (Redis), logout, JWTRequired, RequirePermission middleware | ✓ Done |
| 02-03 | Rate limiting (5/min/IP, 10/min/tenant), HTTPS enforcement, HSTS headers | ✓ Done |
| 02-04 | Password reset — forgot-password, SHA-256 token, email dispatch, session revocation | ✓ Done |

</details>

<details>
<summary>Phase 3 — TOTP + API Keys (branch: feat/phase-3-totp-api-keys)</summary>

| Plan | Description | Status |
|------|-------------|--------|
| 03-01 | TOTP enroll/verify/disable, AES-256 secret encryption, backup codes | Planned |
| 03-02 | TOTP step injected into login flow when TOTP is active | Planned |
| 03-03 | API key CRUD (create/list/revoke) + `APIKeyAuth` middleware + `last_used` | Planned |

</details>

<details>
<summary>Phase 4 — SAML 2.0 (branch: feat/phase-4-saml)</summary>

| Plan | Description | Status |
|------|-------------|--------|
| 04-01 | Per-tenant SAML config model, `GET /saml/metadata` using crewjam/saml | Planned |
| 04-02 | SP-initiated login, ACS handler, assertion validation, JIT provisioning | Planned |

</details>

<details>
<summary>Phase 5 — Admin API (COMPLETE)</summary>

| Plan | Description | Status |
|------|-------------|--------|
| 05-01 | Tenant management endpoints with tenant:manage guard | ✓ Done |
| 05-02 | AdminService — user pool, RBAC, role/permission CRUD | ✓ Done |
| 05-03 | AdminHandler — all admin REST endpoints + audit query handlers | ✓ Done |

</details>

<details>
<summary>Phase 6 — Admin UI (branch: feat/phase-6-admin-ui)</summary>

| Plan | Description | Status |
|------|-------------|--------|
| 06-01 | Vite + React + TypeScript scaffold, auth context, login page, protected routes | Planned |
| 06-02 | Tenant management views (super-admin) + user pool table (search, filter, paginate) | Planned |
| 06-03 | User detail page (edit, role assign, force reset) + roles/permissions management | Planned |
| 06-04 | API keys page, SAML config, dashboard metrics tile, `embed.FS` static serving | Planned |

</details>

<details>
<summary>Phase 7 — Testing & Hardening (branch: feat/phase-7-hardening)</summary>

| Plan | Description | Status |
|------|-------------|--------|
| 07-01 | Unit + integration tests for `internal/auth/` and `internal/store/` (≥80% coverage) | Planned |
| 07-02 | Security test suite — replay, rate limit, enumeration, TOTP bypass, SQL injection | Planned |
| 07-03 | Load test (k6, 500 VUs), production Dockerfile (distroless), deployment runbook | Planned |
| 07-04 | CI/CD — GitHub Actions: test + coverage gate, gosec, govulncheck, golangci-lint | Planned |
| 07-05 | Observability — Prometheus `/metrics`, Grafana dashboard JSON, alerting rules | Planned |

</details>

<details>
<summary>Phase 8 — AI/Agent Security (branch: feat/phase-8-ai-agent-security)</summary>

| Plan | Description | Status |
|------|-------------|--------|
| 08-01 | Agent registration (`agent_registrations` table), authenticate endpoint, agent JWT variant | Planned |
| 08-02 | Per-application rate limiting — configurable limits per `app_id`, DB-backed, Redis-cached | Planned |
| 08-03 | Agent audit trail — `agent_id` in audit_logs, `?agent_id=` filter, `GET /admin/agents` list | Planned |
| 08-04 | Security analysis engine — `GET /admin/agents/analysis` risk scoring, anomaly flags | Planned |

</details>

---

## Branch Strategy

```
master
  ├── feat/phase-3-totp-api-keys      ← TOTP 2FA + API key auth
  ├── feat/phase-4-saml               ← SAML 2.0 enterprise SSO
  ├── feat/phase-6-admin-ui           ← React admin dashboard
  ├── feat/phase-7-hardening          ← tests, CI/CD, Prometheus
  └── feat/phase-8-ai-agent-security  ← AI/agent identity + rate limits
```

**Rules:**
- All feature work happens on its phase branch — never directly on `master`
- Each branch maps to exactly one phase; sub-plans are tracked as commits on that branch
- A phase branch merges to `master` only when **all** its sub-plans are complete and validated
- Each merge to `master` is tagged with a semantic version: `v1.3.0`, `v1.4.0`, etc.

**Completion gate before merge:**
```
□ All sub-plans committed and self-tested
□ go build ./... succeeds with zero warnings
□ go test ./... passes (≥80% coverage on auth core — Phase 7+)
□ gosec ./... clean (Phase 7+)
□ swag init updated if handlers changed
□ README roadmap and ROADMAP.md updated
□ PR created, reviewed, and approved
```

---

## AI/Agent Security — Phase 8

EMC-Auth treats AI agents as first-class authenticated identities — not anonymous API consumers. Any LLM, orchestrator, or automated service can register, authenticate, and be governed by the same tenant-scoped permission and audit model as human users.

### Agent Identity Model

```
agent_registrations
  ├── id            UUID PRIMARY KEY
  ├── tenant_id     UUID  (tenant-scoped — agent A cannot cross into tenant B)
  ├── name          TEXT  (human-readable label, e.g. "invoice-classifier-v2")
  ├── agent_type    TEXT  (llm | tool | orchestrator | service)
  ├── capabilities  TEXT[] (declared scopes: ["invoice:read", "report:export"])
  ├── api_key_hash  TEXT  (SHA-256 of raw key — raw key shown once at registration)
  ├── is_active     BOOL
  └── created_at    TIMESTAMPTZ

Agent JWT payload (same middleware, different claims):
  {
    "agent_id":    "uuid",
    "agent_type":  "llm",
    "tenant_id":   "uuid",
    "capabilities": ["invoice:read"],
    "iss": "https://auth.emc.local",
    "exp": 1234567890
  }
```

### Per-Application Rate Limiting

Rate limits are configurable per `app_id` (header `X-App-ID`) without a server restart:

```
app_rate_limits table
  ├── app_id          TEXT PRIMARY KEY
  ├── tenant_id       UUID
  ├── requests_per_minute  INT  (default: 60)
  ├── burst           INT  (default: 10)
  └── updated_at      TIMESTAMPTZ

Enforcement:
  1. Middleware reads limit from Redis (key: rate:app:{app_id})
  2. Cache miss → query DB → write to Redis with 60s TTL
  3. Admin updates limit → next DB read (within 60s) picks up change
  4. Exceeds limit → 429 with Retry-After header

Admin API:
  POST   /api/v1/admin/apps              Create app rate config
  GET    /api/v1/admin/apps              List all app configs (tenant-scoped)
  PUT    /api/v1/admin/apps/:app_id      Update limit (effective within 60s)
  DELETE /api/v1/admin/apps/:app_id      Remove custom limit (falls back to default)
```

### Security Analysis

`GET /api/v1/admin/agents/analysis` — requires `admin:access`

```json
{
  "window": "24h",
  "agents": [
    {
      "agent_id": "uuid",
      "name": "invoice-classifier-v2",
      "agent_type": "llm",
      "total_requests": 4821,
      "rate_limit_hits": 12,
      "unique_ips": 3,
      "off_hours_access": false,
      "risk_score": 14,
      "flags": []
    },
    {
      "agent_id": "uuid",
      "name": "data-scraper-unknown",
      "agent_type": "service",
      "total_requests": 98200,
      "rate_limit_hits": 447,
      "unique_ips": 31,
      "off_hours_access": true,
      "risk_score": 87,
      "flags": ["high_volume", "many_ips", "off_hours", "rate_limit_abuse"]
    }
  ]
}
```

**Risk score signals (weighted):**

| Signal | Weight | Threshold |
|--------|--------|-----------|
| Rate limit hit rate > 1% | 20 | hits/total > 0.01 |
| Unique IPs > 5 in 24h | 25 | unusual for a single agent |
| Off-hours access (outside 06–22 UTC) | 15 | any request in window |
| Request volume > 10k/24h | 20 | high automated load |
| New agent (< 7 days old) | 10 | elevated caution period |
| Capability mismatch (accessing non-declared routes) | 30 | critical |

---

## Enhancements — Planned Outside Main Roadmap

Items tracked for v2 (post-Phase 8):

| Enhancement | Description | Priority |
|-------------|-------------|----------|
| OAuth2 / OIDC server | Expose authorization_code + client_credentials flows so third-party apps can use EMC-Auth as a full OAuth2 provider | High |
| Social login | Google, GitHub, Microsoft OAuth2 login with account linking | Medium |
| Passwordless / magic link | Email-based one-click login for low-friction onboarding | Medium |
| RS256 JWT | Asymmetric signing — public key endpoint so external services can verify tokens without calling EMC-Auth | Medium |
| Webhooks | POST to a configured URL on user lifecycle events: `user.created`, `user.deleted`, `auth.login_failed` | Medium |
| SDK libraries | Node.js and Python client libraries for JWT verification and token introspection | Medium |
| White-label login page | Per-tenant custom logo, colors, and domain on the hosted login UI | Low |
| Audit log retention | Configurable retention window + archive to S3/GCS after N days | Low |
| Login anomaly detection | Flag logins from new country/device; alert admin or require MFA step-up | Low |
| CORS per tenant | Tenant-configurable allowed origins stored in DB; enforced by middleware | Low |
| Distributed rate limiting | Replace in-memory rate limiter with Redis-backed solution for multi-instance deployments | Phase 7 |
| Token introspection endpoint | `POST /oauth/introspect` — RFC 7662 token introspection for resource servers | v2 |
| Agent federation | Allow agents registered in tenant A to present credentials to tenant B with explicit trust grant | v2 |
| Agent behavior baseline | ML-based normal behavior model per agent; alert on deviation from baseline | v2 |

---

## Project Structure

```
emc-auth-server/
├── cmd/server/main.go       # entrypoint — wires everything and starts HTTP server
├── internal/
│   ├── admin/               # Admin service: tenant CRUD, user pool, role/permission CRUD
│   ├── api/
│   │   ├── handlers/        # HTTP handlers: auth.go, admin.go, health.go
│   │   └── middleware/      # jwt.go, permission.go, ratelimit.go, logger.go
│   ├── audit/               # Audit logger (write + paginated query)
│   ├── auth/                # JWT service, auth service, reset service, token utils
│   ├── config/              # Environment variable loader
│   ├── mailer/              # DevMailer (console) + SMTPMailer
│   └── store/               # DB pool, Redis client, migration runner, seed
├── migrations/              # Goose SQL files (00001–00016), embedded via embed.FS
├── docs/                    # Swagger-generated files (auto-generated, do not edit)
├── .env.example             # Template for local configuration
└── docker-compose.yml       # Postgres 16 + Redis 7 + app service
```

---

## Regenerating Swagger Docs

After adding or modifying handler annotations:

```bash
# Install swag if not already installed
go install github.com/swaggo/swag/cmd/swag@latest

swag init -g cmd/server/main.go --output docs
```

---

## License

MIT
