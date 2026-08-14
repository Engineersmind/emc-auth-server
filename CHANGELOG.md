# Changelog

All notable changes to **EMC Auth Server** are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Fixed
- **`POST /api/v1/auth/refresh` returned no tokens to application-scoped clients** (#108)
  — the rotated pair was delivered only through `setAuthCookies`, which deliberately
  writes nothing for an identity carrying an `app_id` claim ("cookies are for the portal,
  headers are for applications"), and the JSON body carried no tokens either. The client
  received a `200` with nothing usable, retried with the old refresh token, and that
  forced retry was correctly classified as a **replay** — revoking the whole token family
  and ending every session for the user. App-scoped callers now receive the full pair in
  the body (`access_token`, `refresh_token`, `token_type`, `expires_in`, `expires_at`),
  the same shape `POST /api/v1/auth/apps/login` already returns, and still no cookies.
  - **First-party callers are unchanged**: cookies plus a body of
    `{message, expires_in, expires_at}`. A refresh token is deliberately never placed
    where portal JavaScript can read it, and `/auth/session/refresh` still returns none.
  - Purely additive for app-scoped clients; no migration, no config, no service-layer
    change. Replay detection and the `409 concurrent_refresh` grace path are untouched.
  - Reported by the EMC Insurance Platform integrator, 2026-08-11.

### In Progress
- Phase 7: Full unit test suite (≥80% coverage gate)
- Phase 7: Security test suite (auth bypass, injection, privilege escalation)
- Phase 7: Load testing + k6 benchmarks
- Phase 8: Agent registration + M2M auth (`POST /api/v1/admin/agents`)
- Phase 8: Agent activity audit trail
- Phase 8: AI risk scoring engine
- Phase 9: OAuth 2.0 Authorization Server + OIDC Provider

---

## [1.5.0] — 2026-05-18

### Added
- **Admin UI** — React 18 + TypeScript SPA embedded in Go binary via `embed.FS`
  - Login page with TOTP 2FA second-step flow
  - Dashboard with tenant/role/permission overview
  - Users: full CRUD — list, create, edit role, force-password-reset, delete
  - Roles: create, assign/replace permissions, delete
  - API Keys: generate, list, revoke
  - SAML: configure IdP metadata
  - Tenants: list all tenants, drill-down detail view (permissions / roles / users tabs)
  - Tenant Detail: cross-tenant management via `/api/v1/admin/tenants/:tid/*` endpoints
- **Permission-based UI routing** — `admin:access` gates admin pages; non-admins redirected to `/account` self-service portal
- **Cross-tenant management API** — super-admin endpoints to manage permissions, roles, and users in any tenant
- **Cookie session auth fix** — POST `/auth/session` now hydrates user state via GET `/auth/me` after login
- **AdminRoute guard** — React component redirecting non-admins cleanly to `/account`
- **AccountPage** — self-service portal for tenant users (profile, role, permissions display)

### Fixed
- UI type mismatches in roles and API keys API clients
- X-Tenant-Slug header missing from API client base config
- Vite dev server proxy port corrected to 9090

---

## [1.4.0] — 2026-05-18

### Added
- **SAML 2.0 SP** — full service-provider implementation
  - SAML config storage per tenant (`saml_configs` table)
  - SP metadata endpoint: `GET /saml/metadata`
  - SP-initiated SSO: `GET /saml/login`
  - Assertion Consumer Service: `POST /saml/acs`
  - JIT user provisioning — auto-create user on first SAML login
  - Admin config endpoints: `GET/PUT /api/v1/admin/saml-config`

---

## [1.3.0] — 2026-05-18

### Added
- **CI/CD pipeline** — GitHub Actions: test (≥50% coverage soft gate), golangci-lint, gosec SAST, govulncheck, Docker build, release on tag
- **Release automation** — `release.yml` publishes Docker image to GHCR + Linux binaries (amd64/arm64) on `v*.*.*` tag
- **Prometheus metrics** — `GET /metrics`: HTTP latency histogram, in-flight gauge, operation counters
- **Grafana dashboard** — JSON dashboard + alerting rules for latency, error rate, in-flight
- **Per-tenant CORS** — `cors_origins[]` column on tenants table, Redis-cached 60s TTL, OPTIONS preflight
- **Cookie sessions** — `POST /api/v1/auth/session`, `POST /api/v1/auth/session/refresh`, `POST /api/v1/auth/session/logout` — HttpOnly + SameSite=Lax cookies for browser/SPA
- **AI/Agent security** — Per-app rate limiting via `X-App-ID` header, `app_rate_limits` table, Redis-cached limits, `429 + Retry-After`
- **Makefile** — `make test`, `make lint`, `make build`, `make docker`, `make swagger`
- **Security headers** — Content-Security-Policy added (HIGH-03 fix)
- **SPA fallback guard** — `/api/*` paths return 404, never fall through to `index.html` (CRIT-02 fix)

### Fixed
- 401 interceptor infinite redirect loop on `/login` (CRIT-01)
- API key modal state hygiene on dismiss (HIGH-02)

---

## [1.2.0] — 2026-05-18

### Added
- **Admin API — Tenant Management** (requires `tenant:manage`)
  - `POST/GET /api/v1/admin/tenants` — create and list tenants
  - `PUT /api/v1/admin/tenants/:id` — update tenant name
  - `DELETE /api/v1/admin/tenants/:id` — soft-deactivate
  - `PUT /api/v1/admin/tenants/:id/cors-origins` — replace CORS origin whitelist
- **Admin API — RBAC** (requires `admin:access`)
  - Permissions: `POST/GET /api/v1/admin/permissions`, `DELETE /api/v1/admin/permissions/:id`
  - Roles: `POST/GET /api/v1/admin/roles`, `PUT /api/v1/admin/roles/:id/permissions`, `DELETE /api/v1/admin/roles/:id`
- **Admin API — User Pool** (requires `admin:access`)
  - `GET/POST /api/v1/admin/users`, `GET/PUT/DELETE /api/v1/admin/users/:id`
  - `PUT /api/v1/admin/users/:id/role` — reassign role
  - `POST /api/v1/admin/users/:id/force-password-reset`
- **Admin API — API Key Management**
  - `POST/GET /api/v1/admin/api-keys`, `DELETE /api/v1/admin/api-keys/:id`
- **Audit Logs**
  - `GET /api/v1/admin/audit-logs` — tenant-scoped (21 event types, filterable)
  - `GET /api/v1/admin/audit-logs/system` — system-wide (requires `tenant:manage`)
- **CODEOWNERS** — path-based review enforcement for auth, middleware, and audit paths

---

## [1.1.0] — 2026-05-18

### Added
- **TOTP 2FA** — full enroll / activate / disable lifecycle
  - `POST /api/v1/auth/otp/enroll` — returns `otpauth://` URI + 8 single-use backup codes
  - `POST /api/v1/auth/otp/activate` — validates first code, marks TOTP active
  - `DELETE /api/v1/auth/otp` — disables TOTP (requires valid TOTP or backup code)
  - Two-step login: `POST /auth/login` returns `totp_session_id`; `POST /auth/login/otp` completes auth
  - Secrets encrypted at rest with AES-256-GCM; backup codes SHA-256 hashed, single-use
- **API Keys** — machine-to-machine auth
  - `POST /api/v1/admin/api-keys` — create key (`emck_` prefix, 32-byte random, raw shown once)
  - `GET /api/v1/admin/api-keys` — list keys (name, created_at, last_used — raw never returned)
  - `DELETE /api/v1/admin/api-keys/:id` — revoke key
  - Middleware: `X-API-Key` or `Authorization: ApiKey <key>` header; permission check via key's role

---

## [1.0.0] — 2026-05-18

### Added
- **Foundation** — Go 1.23 + Echo v4, PostgreSQL 16 (pgx v5 + pgxpool), Redis 7, Goose migrations, Zerolog structured logging
- **User registration** — `POST /api/v1/auth/register` — bcrypt cost-12, tenant-scoped, duplicate detection
- **Login** — `POST /api/v1/auth/login` — rate-limited (5/min/IP, 10/min/tenant), returns JWT access + refresh token
- **JWT auth** — HS256, per-tenant secret, 1-hour access token, 30-day refresh token
- **Refresh rotation** — `POST /api/v1/auth/refresh` — atomic: old token revoked before new issued; replay returns 401
- **Logout** — `POST /api/v1/auth/logout` — revokes refresh token
- **Password reset** — `POST /api/v1/auth/forgot-password` + `POST /api/v1/auth/reset-password` — SHA-256 token, 15-min TTL, enumeration-safe responses
- **Current user** — `GET /api/v1/auth/me` — returns profile with permissions array
- **Health check** — `GET /health`
- **Swagger UI** — `GET /swagger/index.html` — interactive API explorer
- **Docker** — 3-stage Dockerfile (Node UI builder → Go builder → distroless/static ~5MB), `docker-compose.yml` with Postgres + Redis
- **Single binary** — migrations + seed embedded via `embed.FS`; boots and migrates in <1s
- **Security headers** — HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy
- **SQL injection protection** — all queries use pgx v5 positional parameters (`$1, $2, ...`)
- **Seed data** — default `super_admin` role with `admin:access` + `tenant:manage` permissions

---

[Unreleased]: https://github.com/Engineersmind/emc-auth-server/compare/v1.5.0...HEAD
[1.5.0]: https://github.com/Engineersmind/emc-auth-server/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/Engineersmind/emc-auth-server/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/Engineersmind/emc-auth-server/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Engineersmind/emc-auth-server/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Engineersmind/emc-auth-server/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Engineersmind/emc-auth-server/releases/tag/v1.0.0
