# EMC Auth Server — Architecture Guide for Team

**Date:** 2026-06-09  
**Status:** ✅ VERIFIED against codebase (v1.0)

---

## Overview

EMC Auth Server is a **multi-tenant Identity Provider** that replaces Auth0 for internal use. It handles:
- User authentication (email/password + optional TOTP 2FA)
- Role & permission management  
- JWT token issuance & refresh rotation
- Machine-to-machine API key authentication
- Per-app rate limiting
- Audit logging of all auth events

---

## ✅ Your Understanding — CORRECT with Clarifications

### Demo Seed Data (SEED_DEMO_DATA=true)

**You're correct.** The system seeds 3 demo tenants with recognizable credentials:

| Tenant | Email | Password | Role |
|--------|-------|----------|------|
| outreach | admin@outreach.local | Demo1234! | admin |
| outreach | alice@outreach.local | Demo1234! | member |
| outreach | bob@outreach.local | Demo1234! | member |
| senie | admin@senie.local | Demo1234! | admin |
| senie | carol@senie.local | Demo1234! | member |
| senie | david@senie.local | Demo1234! | member |
| acme | admin@acme.local | Demo1234! | admin |
| acme | frank@acme.local | Demo1234! | member |
| acme | grace@acme.local | Demo1234! | member |
| **emc** | **admin@emc.local** | **$SEED_ADMIN_PASSWORD** | **super_admin** |

**Key detail:** The EMC tenant admin uses `$SEED_ADMIN_PASSWORD` (from env), not Demo1234!. This is the only super-admin in the system.

---

## Authentication Flow — Corrected Diagram

Your diagram was close but needed refinement. Here's the actual flow:

### 1. **User Authentication (Browser/SPA)**

```
┌─────────────────────────────────────────────────────────────┐
│  User Login Flow                                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Client submits: POST /auth/login                        │
│     Payload: { tenant_slug: "outreach",                     │
│                email: "admin@outreach.local",               │
│                password: "Demo1234!" }                      │
│                                                             │
│  2. EMC Auth Server:                                        │
│     ├─► Resolve tenant (outreach → UUID)                   │
│     ├─► Fetch user from DB → verify bcrypt hash           │
│     ├─► Load user's role + permissions                     │
│     ├─► Sign JWT (RS256, kid header, 15-min TTL)            │
│     ├─► Generate refresh token (32-byte random)            │
│     └─► Store refresh token hash in Redis                  │
│                                                             │
│  3. Return to client:                                       │
│     {                                                       │
│       "access_token": "eyJ...", (1 hour)                    │
│       "refresh_token": "emck_...", (30 days)               │
│       "token_type": "Bearer",                               │
│       "expires_in": 3600                                    │
│     }                                                       │
│                                                             │
│  4. Client stores tokens in:                               │
│     ├─► HttpOnly cookies: emc_access_token, emc_refresh    │
│     └─► Or: localStorage / sessionStorage (less secure)    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 2. **Machine-to-Machine (App Integration)**

```
┌─────────────────────────────────────────────────────────────┐
│  App-to-Auth Server Flow (Integration Key)                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Scenario: Insurance App needs to verify user claims       │
│                                                             │
│  1. Insurance Admin creates API key in EMC Auth UI:        │
│     Name: "insurance-service-prod"                         │
│     Permissions: ["auth:verify"]                           │
│                                                             │
│  2. EMC Auth returns (ONCE ONLY):                          │
│     Raw key: "emck_M7x3q9p2Z8vL1kJ4nO5bY..."              │
│     ⚠️  Copy & store securely — never shown again         │
│                                                             │
│  3. Insurance App stores key in secure vault:              │
│     (HashiCorp Vault, AWS Secrets Manager, etc.)          │
│                                                             │
│  4. On user action, Insurance App calls:                  │
│                                                             │
│     POST /api/v1/auth/verify                               │
│     Headers: {                                              │
│       "X-API-Key": "emck_M7x3q9p2Z8vL1kJ4nO5bY...",       │
│       "X-App-ID": "insurance-prod"  (for rate limiting)   │
│     }                                                       │
│     Body: { "token": "<user_access_token>" }               │
│                                                             │
│  5. EMC Auth Server:                                        │
│     ├─► Hash incoming key → lookup in api_keys table      │
│     ├─► Verify key belongs to insurance app               │
│     ├─► Check X-App-ID rate limit (Redis, 60s TTL)        │
│     ├─► Decode JWT & return claims:                       │
│     │   { user_id, email, role, permissions[] }           │
│     └─► Log audit event                                   │
│                                                             │
│  6. Insurance App uses claims for:                         │
│     ├─► Authorization (check role ∈ claims.permissions)   │
│     ├─► Logging (who performed action)                    │
│     └─► Feature gating (admin-only features)              │
│                                                             │
│  Note: API Key NEVER expires — must be revoked manually   │
│        Or: rotate by creating new key + deleting old one  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 3. **Multi-Tenant Isolation**

```
┌─────────────────────────────────────────────────────────────┐
│  Tenant Isolation Guarantees                                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Every JWT includes tenant_id in claims                    │
│  Every API endpoint extracts tenant from:                  │
│    1. JWT claims (if authenticated)                        │
│    2. X-Tenant-Slug header (for public endpoints)         │
│                                                             │
│  ✅ A user from outreach can NEVER:                        │
│     • Access another tenant's users / roles               │
│     • See another tenant's audit logs                     │
│     • Use another tenant's refresh token                  │
│                                                             │
│  ✅ Even if somehow a JWT claim is forged:                │
│     • Database queries are tenant_id-scoped              │
│     • Permission checks verify tenant ownership          │
│     • Audit logs record all access attempts              │
│                                                             │
│  Database schema enforces this at the SQL level:          │
│    • users has tenant_id FK                              │
│    • roles has tenant_id FK                              │
│    • permissions has tenant_id FK                        │
│    • All queries include WHERE tenant_id = <verified>    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Three Access Tiers

### Tier 1: System Admin (super_admin)

**Who:** admin@emc.local (SEED_ADMIN_PASSWORD)

**Permissions:**
- Create / update / deactivate tenants
- View system-wide audit log
- Assign super_admin role
- **Scope:** Cross-tenant, system-wide

### Tier 2: Tenant Admin (admin:access)

**Who:** admin@{tenant}.local (e.g., admin@outreach.local)

**Permissions:**
- Manage users within own tenant (create, update, delete)
- Create / manage roles and permissions
- View tenant-scoped audit log
- Force password reset for any user

**Scope:** Tenant-isolated, never cross-tenant

### Tier 3: Authenticated User

**Who:** Any logged-in user (alice@outreach.local, bob@outreach.local, etc.)

**Permissions:**
- Authenticate (login, refresh, logout)
- View own profile (GET /auth/me)
- Reset own password

**Scope:** Own user record only

---

## API Key vs. JWT

| Aspect | JWT (User) | API Key (App) |
|--------|-----------|--------------|
| **Format** | `Bearer eyJ...` | `Authorization: ApiKey emck_...` or `X-API-Key: emck_...` |
| **TTL** | 1 hour (access), 30 days (refresh) | No expiration (manual revocation only) |
| **Created by** | System (on login) | Tenant admin via API |
| **Use case** | Browser/SPA user sessions | Machine-to-machine app auth |
| **Header** | `Authorization: Bearer ...` | `X-API-Key: ...` or `Authorization: ApiKey ...` |
| **Rate limit** | Per-IP + per-tenant | Per `X-App-ID` header |
| **Audit logged** | ✅ Yes (all auth events) | ✅ Yes (API key usage events) |

---

## Example: Insurance App Setup

### Step 1: Insurance Admin Creates API Key

```bash
# POST /api/v1/admin/api-keys
curl -X POST https://auth.emc.local/api/v1/admin/api-keys \
  -H "Authorization: Bearer <admin_token>" \
  -H "X-Tenant-Slug: insurance" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "insurance-service-prod",
    "permissions": ["auth:verify", "user:read"]
  }'

# Returns:
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "insurance-service-prod",
  "key": "emck_M7x3q9p2Z8vL1kJ4nO5bY...",
  "permissions": ["auth:verify", "user:read"],
  "created_at": "2026-06-09T10:00:00Z"
}
```

### Step 2: Insurance App Stores Key Securely

```bash
# In production: HashiCorp Vault, AWS Secrets Manager, etc.
export INSURANCE_API_KEY="emck_M7x3q9p2Z8vL1kJ4nO5bY..."
```

### Step 3: Insurance App Uses Key to Verify User Tokens

```bash
# User submits JWT from browser login
USER_TOKEN=$(curl https://insurance.local/api/user-profile -H "Authorization: Bearer <token>")

# Insurance app verifies the token:
curl -X POST https://auth.emc.local/api/v1/auth/verify \
  -H "X-API-Key: emck_M7x3q9p2Z8vL1kJ4nO5bY..." \
  -H "X-App-ID: insurance-prod" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "<user_access_token>"
  }'

# Returns:
{
  "user_id": "550e8400-e29b-41d4-a716-446655440001",
  "tenant_id": "550e8400-e29b-41d4-a716-446655440002",
  "email": "alice@insurance.local",
  "role": "admin",
  "permissions": ["admin:access", "claims:read"]
}
```

### Step 4: Insurance App Makes Authorization Decision

```go
// Insurance app receives claims from EMC Auth
claims := VerifyToken(userToken, apiKey)

// Check if user has required permission
if !contains(claims.Permissions, "claims:read") {
    return 403 Forbidden // User cannot access claims
}

// User can proceed
return showClaimData(claims.UserID)
```

---

## Roles Explained

Roles are **tenant-scoped** and contain a set of permissions:

### Default Roles (seeded):

- **admin** → `[admin:access]` (tenant admin)
- **member** → `[]` (empty — base authenticated user)

### Custom Roles:

Each tenant can create custom roles:

```sql
-- Example: Insurance company roles
admin      → [admin:access, claims:read, claims:write, policy:read]
claims_mgr → [claims:read, claims:write]
csr        → [claims:read, policy:read]
```

---

## Permissions Explained

Permissions are **tenant-scoped** identifiers checked at runtime:

### System Permissions (reserved):

- `admin:access` — Tenant admin capability
- `tenant:manage` — System-wide tenant management

### Application-Defined Permissions:

Each app defines its own permission namespace:

```
Insurance:          claims:read, claims:write, policy:read, policy:write, ...
PDF AuthFiller:     document:create, document:sign, document:download, ...
Outreach CRM:       contact:read, contact:write, campaign:manage, ...
```

**Who defines them?** Tenant admin (via API or UI) for their tenant.

---

## Audit Logging

Every authentication event is logged:

```sql
SELECT 
  event_type,     -- login, logout, token_refresh, api_key_used, password_reset
  user_id,
  tenant_id,
  email,
  success,        -- true/false
  reason,         -- "password mismatch", "TOTP failed", "rate limited", etc.
  ip_address,
  user_agent,
  created_at
FROM audit_logs
WHERE tenant_id = '...'
ORDER BY created_at DESC;
```

**Retention:** Depends on your database/compliance policy (not enforced by EMC Auth).

---

## Security Summary

| Layer | Mechanism |
|-------|-----------|
| **Password Storage** | bcrypt (cost 12) — ~100ms per hash |
| **Token Signing** | RS256 (per-tenant RSA key pair) — private key stays on the server; public keys published as JWKS |
| **Token Storage** | JWT stored in HttpOnly cookies (browser-side) |
| **API Key Storage** | SHA-256 hash only (raw key shown once at creation) |
| **Refresh Rotation** | Atomic: old token revoked before new issued; replay returns 401 |
| **Rate Limiting** | 5 req/min/IP + 10 req/min/tenant on login; per-app limits on API keys |
| **2FA** | TOTP (Time-based One-Time Password) with 8 backup codes |
| **Tenant Isolation** | Database-level: every table has tenant_id FK, all queries scoped |
| **HTTPS** | Enforced in production; redirect from HTTP |
| **CORS** | Per-tenant whitelist (configurable origins) |
| **Audit Trail** | All auth events logged with user, tenant, IP, timestamp |

---

## Environment Variables

```bash
# Database
DATABASE_URL="postgres://user:pass@localhost:5432/emc_auth"

# Redis (sessions, rate limiting, cache)
REDIS_URL="redis://localhost:6379"

# JWT Issuer (appears in "iss" claim)
JWT_ISSUER="https://auth.emc.local"

# Base URL for reset links in emails
APP_BASE_URL="https://auth.emc.local"

# TOTP (2FA) — 64-char hex key for AES-256-GCM
TOTP_ENCRYPTION_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# Email (SMTP)
SMTP_HOST="smtp.sendgrid.net"
SMTP_PORT="587"
SMTP_FROM="noreply@emc.local"
SMTP_USERNAME="apikey"
SMTP_PASSWORD="SG.xxxx..."

# Admin password for super_admin seed
SEED_ADMIN_PASSWORD="YourSecurePassword123!"

# Demo seed toggle
SEED_DEMO_DATA="true"  # Only in dev/staging

# Environment
ENVIRONMENT="development"  # or "production"

# Prometheus metrics
METRICS_ENABLED="true"
```

---

## Deployment Checklist

- [ ] PostgreSQL 16 running, migrations applied
- [ ] Redis 7 running and accessible
- [ ] `SEED_ADMIN_PASSWORD` set to a strong value
- [ ] `TOTP_ENCRYPTION_KEY` generated (64-char hex)
- [ ] `JWT_ISSUER` matches your domain (e.g., `https://auth.emc.local`)
- [ ] SMTP configured (or disabled in dev)
- [ ] HTTPS enabled (production only)
- [ ] `SEED_DEMO_DATA=false` in production
- [ ] Database backups configured
- [ ] Firewall allows only necessary ports (5432, 6379, 3000)
- [ ] Audit log retention policy set
- [ ] Monitoring/alerting on failed login attempts

---

## Common Workflows

### 1. Create a New Tenant

```bash
POST /api/v1/admin/tenants
Authorization: Bearer <super_admin_token>
X-Tenant-Slug: system

{
  "name": "NewCorp",
  "slug": "newcorp",
  "cors_origins": ["https://app.newcorp.local"]
}
```

### 2. Create a Tenant Admin User

```bash
POST /api/v1/admin/users
Authorization: Bearer <super_admin_token>
X-Tenant-Slug: newcorp

{
  "email": "admin@newcorp.local",
  "password": "SecurePass123!",
  "first_name": "Admin",
  "last_name": "User",
  "role": "admin"
}
```

### 3. Create Custom Role

```bash
POST /api/v1/admin/roles
Authorization: Bearer <tenant_admin_token>
X-Tenant-Slug: insurance

{
  "name": "claims_manager",
  "permissions": ["claims:read", "claims:write"]
}
```

### 4. Assign User to Role

```bash
POST /api/v1/admin/users/{user_id}/roles
Authorization: Bearer <tenant_admin_token>
X-Tenant-Slug: insurance

{
  "role_id": "550e8400-e29b-41d4-a716-446655440003"
}
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `401 Unauthorized` | JWT expired? Refresh token invalid? Check `Authorization` header format |
| `403 Forbidden` | Missing permission? Check user's role → permissions in JWT claims |
| `429 Too Many Requests` | Rate limited. Check `Retry-After` header. For app: verify `X-App-ID` header |
| `Cannot authenticate` | User in wrong tenant? Verify `X-Tenant-Slug` matches user's tenant |
| `TOTP not working` | TOTP secret encrypted? `TOTP_ENCRYPTION_KEY` must be 64-char hex |
| `Redis connection failed` | Check `REDIS_URL`, firewall, Redis is running |
| `Audit logs are empty` | Audit logging is always on — check database for `audit_logs` table |

---

## Next Steps

1. **Read the Swagger Docs:** `http://localhost:3000/swagger/index.html`
2. **Explore the API:** Use Postman collection in `emc-auth-postman.json`
3. **Deploy to staging** with `SEED_DEMO_DATA=true` for testing
4. **Create first app API key** and test machine-to-machine flow
5. **Enable audit monitoring** — set up log aggregation (ELK, Datadog, etc.)
6. **Implement app-side permission checks** — EMC Auth returns claims, apps enforce rules

---

## Questions?

- **Architecture:** See `docs/PLATFORM_DESIGN.html`
- **Deployment:** See `docs/DEPLOYMENT.md`
- **Database schema:** See `migrations/` folder
- **Security:** See `SECURITY.md`

---

**Document verified against:** EMC Auth Server v1.0 (June 2026)  
**Next review:** After next major version release
