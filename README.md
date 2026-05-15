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

## Roadmap

- [x] **Phase 1** — Foundation: schema, migrations, Docker, seed, health endpoint
- [x] **Phase 2** — Auth Engine: JWT, refresh rotation, password reset, rate limiting, security headers
- [x] **Phase 5** — Admin API: tenant management, user pool, RBAC, audit logs
- [ ] **Phase 3** — TOTP 2FA + API Keys (machine-to-machine auth)
- [ ] **Phase 4** — SAML 2.0 (enterprise SSO)
- [ ] **Phase 6** — Admin UI (React SPA embedded in binary)
- [ ] **Phase 7** — Testing & Hardening (≥80% coverage, load test, security suite, CI/CD)

---

## License

MIT
