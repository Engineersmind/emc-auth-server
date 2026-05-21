# EMC Auth Server — Human Review Checklist

All implemented functionality requiring human review before production deployment.
Reviewer should verify correctness, security assumptions, and operational readiness for each item.

---

## Phase 1 — Foundation

### 1.1 Database Migrations (goose v3, embedded)
- **Files:** `migrations/000{01-18}_*.sql`, `migrations/migrations.go`
- **Review:** Schema design, FK constraints, index coverage, goose embed path. Migrations run automatically on server boot — verify rollback safety.

### 1.2 Multi-Tenant Architecture
- **Files:** `internal/auth/service.go`, `migrations/00001_create_tenants.sql`
- **Review:** Every DB query scoped by `tenant_id`. `X-Tenant-Slug` header resolves tenant. Verify no cross-tenant data leakage in any query.
- **Risk:** Missing `tenant_id` filter on any query would be a critical data exposure.

### 1.3 JWT Service (HS256 per-tenant secret)
- **Files:** `internal/auth/jwt.go`
- **Review:** Per-tenant `jwt_secret` stored in DB. Token lifetime: access=1h, refresh=30d. Claims struct fields. `Verify()` fetches tenant secret each call — confirm pgxpool handles connection pressure.

### 1.4 User Registration & Login
- **Files:** `internal/auth/service.go` (Register, Login), `internal/api/handlers/auth.go`
- **Review:** bcrypt cost factor (should be ≥12). Password minimum length enforcement. Email uniqueness per-tenant (not global).

---

## Phase 2 — Core Auth

### 2.1 Token Refresh & Logout
- **Files:** `internal/auth/service.go` (Refresh, Logout), `migrations/00004_create_refresh_tokens.sql`
- **Review:** Refresh token rotation — old token invalidated atomically on rotation. Replay attack: verify second use of same refresh token returns 401. `revoked_at` vs `expires_at` expiry logic.

### 2.2 JWT Middleware (Bearer + Cookie)
- **Files:** `internal/api/middleware/jwt.go`
- **Review:** Bearer token extraction. Cookie fallback (`emc_access_token`). Verify the fallback does NOT skip signature verification — both paths call `jwtSvc.Verify()`.
- **Risk:** A cookie-only path that skips Verify would be a critical auth bypass.

### 2.3 Permission System (RBAC)
- **Files:** `internal/auth/service.go`, `migrations/00008-00015_*.sql`
- **Review:** `RequirePermission` middleware extracts claims from context. Permissions injected into JWT at login time — stale if role changes. Confirm tokens are invalidated or short enough that stale permissions are acceptable.

### 2.4 Login Rate Limiter (per-IP + per-tenant)
- **Files:** `internal/api/middleware/ratelimit.go`
- **Review:** Default 5 req/min per IP, 10 req/min per tenant. In-memory rate limiters — state lost on restart, not shared across instances. Suitable for single-node; review for multi-node deployment.

### 2.5 Security Headers
- **Files:** `internal/api/routes.go` (`securityHeaders`)
- **Review:** HSTS max-age=31536000, X-Content-Type-Options, X-Frame-Options: DENY, Referrer-Policy. Confirm HSTS is appropriate before enabling (requires HTTPS enforced).

### 2.6 Password Reset (SMTP + dev console)
- **Files:** `internal/auth/reset.go`, `internal/mailer/`
- **Review:** Reset token is a cryptographically random 32-byte value stored as SHA-256 hash. Token TTL (check migration). Email enumeration prevention — POST /forgot-password always returns 200. SMTP credentials via env vars (not committed).

---

## Phase 3 — TOTP 2FA + API Keys

### 3.1 TOTP Service (AES-256-GCM encrypted secrets)
- **Files:** `internal/auth/totp.go`
- **Review:**
  - `TOTP_ENCRYPTION_KEY` — 32-byte AES key, hex-encoded. Dev zero-key fallback logs a warning; **must** be set in production.
  - AES-256-GCM encryption: nonce prepended to ciphertext, base64-encoded at rest. Confirm nonce is unique per encryption call (`rand.Read`).
  - Key rotation: no mechanism exists. Adding key rotation is a future requirement.
  - Backup codes: 8 × 8-char from unambiguous charset, SHA-256 hashed, single-use. Verify the consume logic is atomic (race condition: two concurrent uses of the same backup code).

### 3.2 TOTP Login Flow (OTP Session in Redis)
- **Files:** `internal/auth/service.go` (Login, LoginOTP, createOTPSession, loadOTPSession), `internal/auth/totp.go` (OTPSession)
- **Review:** Pre-auth state stored in Redis with 5-minute TTL under `otp:session:{token}`. Token is 32-byte random base64url. Session is single-use — deleted after `LoginOTP` consumes it. Verify the `DEL` is atomic with the `GET` (or that a second call returns an error before issuing tokens).

### 3.3 API Key Authentication
- **Files:** `internal/auth/apikey.go`, `internal/api/middleware/apikey.go`, `migrations/00010_create_api_keys.sql`
- **Review:**
  - Key format: `emck_` prefix + 32 random bytes base64url. Raw key returned ONCE at creation — never stored.
  - Key stored as SHA-256 hash only. `AuthenticateAPIKey` hashes the incoming key and compares.
  - `last_used_at` updated with fire-and-forget (no error handling) — confirm this is acceptable.
  - `revoked_at` soft-delete; physically deleted rows are not possible via API (no hard delete).
  - Permissions on API keys: stored as TEXT[] column — confirm permission enforcement in `APIKeyRequirePermission` middleware.

---

## Phase 5 — Admin API

### 5.1 Admin Service (Tenant + RBAC + User Pool)
- **Files:** `internal/admin/service.go`, `internal/api/handlers/admin.go`
- **Review:** All admin operations are tenant-scoped via JWT claims. `tenant:manage` vs `admin:access` permission distinction. Soft-delete for users (`is_deleted=true, is_active=false`) — confirm deleted users cannot log in.

### 5.2 Audit Logging
- **Files:** `internal/audit/logger.go`, `migrations/00016_create_audit_logs.sql`
- **Review:** Fire-and-forget logging — audit failures do NOT block requests. Verify audit records include `tenant_id` on all admin operations. System-wide audit endpoint (`tenant:manage` only) returns all tenants — confirm super_admin access control is solid.

---

## Phase 7 — Hardening & Observability

### 7.1 CI/CD Pipeline
- **Files:** `.github/workflows/ci.yml`, `.github/workflows/release.yml`
- **Review:**
  - CI: test (postgres+redis services), lint (golangci-lint), gosec SARIF upload, govulncheck, docker smoke test.
  - Coverage gate: warns below 50% — should be raised to 80% before production.
  - Release: builds linux/amd64+arm64 binaries, pushes to ghcr.io, creates GitHub Release.
  - Secrets: `GITHUB_TOKEN` used for GHCR push — confirm repository permissions.

### 7.2 Prometheus Metrics
- **Files:** `internal/metrics/metrics.go`, `internal/api/middleware/prometheus.go`, `internal/api/routes.go`
- **Review:**
  - `GET /metrics` is unauthenticated — intended for Prometheus scraping. **Must** be network-restricted in production (e.g., bind to localhost, reverse proxy, or add a scrape secret).
  - Route template used as label (not raw URL) — avoids cardinality explosion. Verify Echo's `c.Path()` returns the matched template for all route patterns.
  - `emc_auth_operations_total` counter defined but not yet wired into handler call sites — only the middleware-level HTTP counters are active. Auth-specific counters (`login`, `register`, etc.) need wiring.

### 7.3 Golangci-lint Configuration
- **Files:** `.golangci.yml`
- **Review:** Enabled linters and excluded rules (G401, G501 for bcrypt/AES intentionally). Confirm `noctx` and `bodyclose` linters pass on current codebase.

---

## Phase 8 — AI/Agent Security

### 8.1 Per-App Rate Limiting
- **Files:** `internal/auth/applimit.go`, `internal/api/middleware/applimit.go`, `migrations/00017_create_app_rate_limits.sql`
- **Review:**
  - In-memory `rate.Limiter` map per `app_id` — NOT shared across server instances. Multi-node deployments need Redis-backed rate limiting (e.g., redis-cell / lua script).
  - Rate limit config fetched from Redis cache (60s TTL), falls back to DB, falls back to default (60 RPM / 10 burst).
  - Stale limiter cleanup: goroutine runs every 5 minutes, removes limiters unseen for 10+ minutes. Verify goroutine has no leak (it runs for the lifetime of the process — no cancellation mechanism).
  - `getLimiter` does NOT update the rate limiter when RPM/burst config changes — only new app sessions pick up the new limit. Existing in-memory limiters use the rate at creation time until evicted.

### 8.2 Cookie-Based Session
- **Files:** `internal/api/handlers/auth.go` (SessionLogin, SessionRefresh, SessionLogout), `internal/api/middleware/jwt.go`
- **Review:**
  - `Secure` flag auto-detected from `TLS != nil` or `X-Forwarded-Proto: https` header. **Verify** the proxy header cannot be spoofed by clients in your infrastructure.
  - `emc_refresh_token` cookie path is `/api/v1/auth/session/refresh` — restricts scope but verify the browser respects path scoping.
  - `clearAuthCookies` uses `MaxAge=-1` with `Path=/api/v1` — the refresh token cookie was set with a more specific path (`/api/v1/auth/session/refresh`). A logout may not clear the refresh cookie if the path in the `Set-Cookie` expiry doesn't match the original. **Verify and fix** if needed.
  - TOTP + cookie login: returns OTP challenge (JSON), not cookies. Client must complete `/auth/login/otp` and then separately call `/auth/session` — document this two-step flow for FE integration.

### 8.3 Per-Tenant CORS Middleware
- **Files:** `internal/api/middleware/cors.go`, `internal/admin/service.go`, `migrations/00018_add_cors_origins_to_tenants.sql`
- **Review:**
  - Origin comparison is exact string match — no wildcard/regex support. Wildcards (e.g., `*.example.com`) require explicit implementation if needed.
  - `InvalidateCache` is best-effort — accepts optional `slug` query param on the admin update. If slug is not provided, the cached stale origins will be used until TTL expires (60s).
  - CORS middleware runs globally, before JWT auth — preflight OPTIONS will succeed for valid origins even without a token. This is standard CORS behaviour but confirm it aligns with your security model.

---

## Infrastructure & Operational

### Infra.1 Docker Compose (Production)
- **Files:** `infra/docker-compose.prod.yml`
- **Review:** Resource limits (app 256M, postgres 512M, redis 192M). Prometheus + Grafana bound to 127.0.0.1. All secrets via environment variables — confirm `.env` is in `.gitignore`.

### Infra.2 Prometheus + Grafana Provisioning
- **Files:** `infra/prometheus/`, `infra/grafana/`
- **Review:** Scrape target for `emc-auth-server:8080/metrics` — must match container network name. Confirm dashboards provisioned with correct data source name.

---

## Critical Security Items (Must Fix Before Production)

| # | Item | Risk |
|---|------|------|
| S1 | `GET /metrics` is unauthenticated | Exposes operational data; restrict by network policy or add secret |
| S2 | In-memory rate limiters not shared across instances | Multi-node deployments bypass rate limits |
| S3 | `clearAuthCookies` path mismatch may not expire refresh cookie | Session not fully terminated on logout |
| S4 | `emc_auth_operations_total` counter not wired to handlers | Auth event metrics will show zero |
| S5 | No TOTP encryption key rotation mechanism | Long-term key compromise risk |
| S6 | `getLimiter` doesn't update in-memory limiter on config change | Rate limit changes take up to 10 min to propagate |

---

## Testing Coverage Gaps

- No integration tests for TOTP enrollment → activation → verify flow
- No integration test for refresh token replay attack prevention
- No tests for API key hash verification across key formats
- No tests for cookie session logout (path mismatch risk above)
- No tests for per-app rate limiting across app_id boundaries
- No tests for CORS preflight handling with valid/invalid origins
- CI coverage gate at 50% — should target ≥80%

---

_Generated: 2026-05-15 | Branch: feat/phase-8-ai-agent-security_
