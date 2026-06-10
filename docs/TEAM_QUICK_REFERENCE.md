# EMC Auth Server — Quick Team Overview

**TL;DR** — What you need to know in 5 minutes

---

## What is EMC Auth?

✅ **Self-hosted replacement for Auth0**
- Handles user login, password reset, 2FA (TOTP)
- Manages roles and permissions
- Issues JWT tokens for your apps
- Logs every auth event for security

❌ **NOT** another library or framework — it's a standalone server you deploy

---

## How It Works

### For Users (Browser/Mobile App)

1. User enters email + password
2. EMC Auth verifies and returns a token
3. User's app stores token in browser
4. On each request: app sends token to your service
5. Your service verifies token with EMC Auth and checks permissions

### For Apps (Backend Service)

1. Your app gets an **API key** from EMC Auth (created once by admin)
2. Your app calls EMC Auth to verify user tokens
3. EMC Auth returns user info + permissions
4. Your app decides what the user can do

---

## Demo Credentials (Dev Only)

| Tenant | Email | Password | Role |
|--------|-------|----------|------|
| outreach | admin@outreach.local | Demo1234! | admin |
| outreach | alice@outreach.local | Demo1234! | member |
| senie | admin@senie.local | Demo1234! | admin |
| acme | admin@acme.local | Demo1234! | admin |
| **emc** | **admin@emc.local** | **$SEED_ADMIN_PASSWORD** | **super_admin** |

Set `SEED_DEMO_DATA=true` to activate.

---

## Key Concepts

### **Tenants** 
Separate companies/orgs. Complete isolation — a user in tenant A can never see tenant B's data.

**Examples:** outreach, senie, acme, insurance, etc.

### **Users**
Belong to exactly one tenant. Email + password + role.

**Examples:** admin@outreach.local, alice@outreach.local

### **Roles**
Define what permissions a user has within a tenant.

**Built-in roles:**
- `admin` — can manage users, roles, permissions in their tenant
- `member` — basic authenticated user

**Custom roles:** Each tenant can create their own (e.g., `claims_manager`, `csr`)

### **Permissions**
Specific capabilities defined by your app.

**Examples:**
- Insurance app: `claims:read`, `claims:write`, `policy:read`
- PDF app: `document:create`, `document:sign`

### **API Keys**
For app-to-app authentication (machine-to-machine).

Format: `emck_...` (shown once, never recoverable — store securely!)

### **Tokens**
- **Access Token** (JWT): 1 hour — used for API requests
- **Refresh Token**: 30 days — used to get a new access token

---

## Three Levels of Access

| Level | Who | Can Do |
|-------|-----|--------|
| **System Admin** | admin@emc.local | Create tenants, see all audit logs, assign super_admin |
| **Tenant Admin** | admin@{tenant}.local | Manage users in their tenant, create roles/permissions |
| **Authenticated User** | Any user | Log in, view own profile, reset own password |

---

## Security

✅ Passwords hashed with bcrypt (cost 12 — ~100ms per login)  
✅ Tokens signed with cryptographic key (HS256)  
✅ Refresh tokens atomic (old revoked before new issued)  
✅ Rate limiting (5 login attempts/min per IP)  
✅ Tenant isolation guaranteed at database level  
✅ All actions logged for audit trail  
✅ Optional 2FA (TOTP)  
✅ HTTPS enforced in production  

---

## Example: Insurance App

### Setup (One-time)

1. Insurance admin logs in to EMC Auth
2. Admin creates API key: `emck_M7x3q9p2Z8vL1kJ4nO5bY...`
3. Insurance app stores key in secure vault (Vault, AWS Secrets Manager)

### At Runtime

1. User logs into insurance app → gets JWT from browser
2. Insurance app calls EMC Auth: *"Verify this token"*
3. EMC Auth returns: `{ user_id, email, role, permissions: [claims:read, policy:read] }`
4. Insurance app checks: *"Does this user have `claims:read`?"*
5. If yes → show claims; if no → 403 Forbidden

---

## Deployment

| Component | Tech | Notes |
|-----------|------|-------|
| Auth Server | Go (single binary) | Boots in <1 second |
| Database | PostgreSQL 16 | Migrations embedded |
| Cache | Redis 7 | Sessions, rate limiting |
| Logs | JSON (Zerolog) | Stdout → ELK/Datadog/etc. |
| Metrics | Prometheus | `/metrics` endpoint |

---

## Environment Variables

```bash
DATABASE_URL="postgres://user:pass@localhost:5432/emc_auth"
REDIS_URL="redis://localhost:6379"
JWT_ISSUER="https://auth.emc.local"
TOTP_ENCRYPTION_KEY="0123456789abcdef0123456789abcdef..."
SMTP_HOST="smtp.sendgrid.net"
SEED_ADMIN_PASSWORD="YourSecurePassword!"
SEED_DEMO_DATA="true"  # Only in dev
ENVIRONMENT="production"
```

---

## Common Tasks

### Create a New Tenant
```bash
POST /api/v1/admin/tenants
Authorization: Bearer <super_admin_token>

{
  "name": "Insurance Corp",
  "slug": "insurance",
  "cors_origins": ["https://insurance.local"]
}
```

### Create an API Key for an App
```bash
POST /api/v1/admin/api-keys
Authorization: Bearer <tenant_admin_token>
X-Tenant-Slug: insurance

{
  "name": "insurance-service-prod",
  "permissions": ["auth:verify", "user:read"]
}
```

### Create a Custom Role
```bash
POST /api/v1/admin/roles
Authorization: Bearer <tenant_admin_token>
X-Tenant-Slug: insurance

{
  "name": "claims_manager",
  "permissions": ["claims:read", "claims:write"]
}
```

---

## Where to Learn More

📖 **Full Architecture Guide:** `docs/ARCHITECTURE_GUIDE.md` (in this repo)  
🔗 **Swagger UI:** `http://localhost:3000/swagger/index.html`  
📋 **API Postman Collection:** `emc-auth-postman.json`  
🚀 **Deployment Guide:** `docs/DEPLOYMENT.md`  
🔒 **Security Policy:** `SECURITY.md`  

---

## Questions?

**What does EMC Auth NOT do?**
- Social login (Google, GitHub, etc.) — no OIDC provider role
- Token introspection endpoint — but we have `/auth/verify` and `/auth/me`
- Password history enforcement — apps must enforce if needed
- Custom password policies — set validation rules in your app

**What if my app needs different permissions per tenant?**
Each tenant defines their own permission set independently. Insurance app permissions ≠ PDF app permissions.

**Can users belong to multiple tenants?**
No — one user = one tenant. Cross-tenant access must go through separate logins.

**How do I revoke an API key?**
Delete it via API or UI. Revocation is immediate (Redis cache TTL = 60s).

---

**Last Updated:** 2026-06-09  
**EMC Auth Server Version:** 1.0
