# Application Integration Guide — End-User Auth with Application-Scoped MFA

How a consuming application (your dummy backend + frontend) integrates end-user
authentication against the EMC Auth Server, including TOTP + email MFA,
backup codes, forced enrollment, and admin management (issue #63).

Base URL below: `http://localhost:9090` (dev). All bodies are JSON
(`Content-Type: application/json`). Interactive reference: `/swagger/index.html`.

---

## 0. Local test environment

```bash
# 1. Postgres + Redis (dev containers)
docker start emc-mfa-test-pg emc-mfa-test-redis   # or create:
# docker run -d --name emc-mfa-test-pg -e POSTGRES_DB=emc_auth -e POSTGRES_USER=emc_auth \
#   -e POSTGRES_PASSWORD=local-dev-only -p 55432:5432 postgres:16-alpine
# docker run -d --name emc-mfa-test-redis -p 56379:6379 redis:7-alpine

# 2. Server (migrations + seed run automatically)
DATABASE_URL='postgres://emc_auth:local-dev-only@127.0.0.1:55432/emc_auth?sslmode=disable' \
REDIS_URL='redis://127.0.0.1:56379/0' ENV=development PORT=9090 go run ./cmd/server
```

- Seeded super_admin: `admin@emc.local` / `ChangeMe123!` (tenant slug `emc`).
- `ENV=development` → **no real email is sent**; every MFA code email is
  printed in the server log as a JSON line containing `"code"`, `"to"`,
  `"from"`, `"app"`. Your test harness reads codes from there.

## 1. Credential model

| Credential | Used by | How |
|---|---|---|
| **Application credentials** (`client_id` + `client_secret`) | your app's **backend** | header `Authorization: Basic base64(client_id:client_secret)` on `/auth/apps/*` and the public MFA endpoints need no auth at all |
| **Admin JWT** | owner / super_admin console | `Authorization: Bearer <token>` from `POST /auth/login` |
| **End-user JWT** | your app after login | `Authorization: Bearer <access_token>` on `/auth/otp/*`, `/auth/me` |
| **Pre-auth tokens** (`otp_session_token`, `enrollment_token`) | mid-login state | opaque strings carried in JSON bodies; short-lived, single-purpose |

⚠️ `client_secret` must live only in your app's backend. The browser/frontend
never sees it — your backend proxies `/auth/apps/*` calls.

---

## 2. One-time setup (admin persona)

### 2.1 Admin login
```
POST /api/v1/auth/login
{ "email": "admin@emc.local", "password": "ChangeMe123!" }
→ 200 { "access_token", "refresh_token", "token_type", "expires_in", "expires_at" }
```

### 2.2 Create the application
```
POST /api/v1/applications                       Bearer <admin>
{ "name": "Acme CRM", "app_type": "web" }
→ 201 { "id": "149", "name", "app_type", "client_id", "client_secret", "scopes", "created_at" }
```
`client_secret` is shown **exactly once** — store it now.

### 2.3 Set the application's MFA policy
```
PUT /api/v1/applications/{appID}/mfa            Bearer <admin>
{ "mode": "required", "allowed_methods": ["totp","email"] }
→ 200 (policy incl. stats, see 2.4)
```
- `mode`: `disabled` | `optional` (default) | `required`
- `allowed_methods`: non-empty subset of `["totp","email"]`; omit to keep
  current (default `["totp"]`)
- Canonical alternative for super_admin cross-tenant:
  `PUT /api/v1/tenants/{tid}/applications/{appID}/mfa`
- The whole PUT (switch, mode/methods, magic-link fields) is applied in **one
  transaction**: a 400 on any part leaves every setting as it was.

### 2.3a MFA master switch (`mfa_enabled`)
```
PUT /api/v1/applications/{appID}/mfa            Bearer <admin>
{ "mfa_enabled": false }                         # mode may be omitted
→ 200 (policy incl. "mfa_enabled": false)
```
The switch sits **above** `mode`. It is the one setting that means "run this
application without MFA".

| | `mfa_enabled: true` (default) | `mfa_enabled: false` |
|---|---|---|
| Enrolled user logs in | challenged (per `mode`/`allowed_methods`) | **not challenged** — tokens directly |
| Unenrolled user, `mode: required` | forced enrolment | **not forced** |
| New enrolment (TOTP / email) | per `mode`/`allowed_methods` | **403 `mfa_switched_off`** |
| Removing the last factor under `required` | refused (last-factor guard) | allowed (nothing is required) |
| Stored mode, methods, factors, backup codes | — | **kept**, all apply again when switched back on |

Compare `mode: "disabled"`, which only blocks *new* enrolment and still
challenges users who already enrolled.

An application with no settings row is `mfa_enabled: true`. Administrator
(console) MFA is never affected by any application's switch.

**Turning it OFF is protected** (turning it on is not):

| Caller | Off | On |
|---|---|---|
| Management / API-key token, client-credentials token | **403 `mfa_switch_off_service_token`** | allowed |
| Human session not established with MFA, or MFA sign-in older than **10 minutes** | **403 `mfa_switch_off_stale_session`** — sign in again with MFA and retry | allowed |
| Human session signed in with MFA in the last 10 minutes | allowed | allowed |

Every real change (old ≠ new) writes an `admin.mfa_switch_changed` audit event
(`old_mfa_enabled`, `new_mfa_enabled`) and emails the application's
administrators (tenant owners + co-owners of that app). Re-sending the current
value is a no-op: no audit, no email.

**Changes apply at the next login.** Existing sessions are not re-checked:
a session issued while MFA was off stays valid until its refresh token expires
(up to 30 days), and turning MFA off does not end sessions that did MFA.
App-wide session revoke is tracked in #196.

**Known gap — social and passkey sign-ins.** Google (and other social) and
passkey sign-ins do not go through the application MFA gate at all, whatever
`mfa_enabled` and `mode` say. This predates the switch and is fixed by the
opt-in `federated_mfa = enforce` setting (#194).

### 2.4 Read policy + enrollment stats (dashboard)
```
GET /api/v1/applications/{appID}/mfa            Bearer <admin>
→ 200 {
  "application_id": "149", "mfa_enabled": true, "mode": "required",
  "allowed_methods": ["totp","email"],
  "enrolled_users": 1,          // active TOTP
  "pending_enrollments": 0,     // TOTP enrolled, never activated
  "email_enrolled_users": 1,    // active email MFA
  "total_users": 2,
  "updated_at": "…"
}
```

### 2.5 (Optional) White-label email sender
Codes resolve their sender **application → tenant → global** (`SMTP_FROM` env).
```
PUT /api/v1/email-settings                                  # tenant-level
PUT /api/v1/applications/{appID}/email-settings             # per-app override
{ "from_address": "no-reply@acme.com", "smtp_host": "smtp.acme.com",
  "smtp_port": 587, "smtp_username": "acme", "smtp_password": "…" }
→ 200 { …, "has_password": true }        # password is write-only, never returned
GET / DELETE on the same paths.          # DELETE falls back to the next level
```
A failing tenant relay automatically falls back to the global sender.

### 2.6 Rescue a locked-out user (lost phone + backup codes + inbox)
```
DELETE /api/v1/applications/{appID}/users/{uid}/mfa         Bearer <admin>
→ 200   # wipes TOTP AND email MFA; 'required' app re-forces enrollment at next login
```
User ids come from `GET /api/v1/applications/{appID}/users` (paginated
`{users,total,page,total_pages}`).

---

## 3. End-user flows (your app's backend calls these)

### 3.1 Register
```
POST /api/v1/auth/apps/register                 Basic <app credentials>
{ "email": "jane@x.com", "password": "Secret123!", "first_name": "", "last_name": "" }
→ 201 token pair | 400 | 401 invalid client credentials | 409 email already registered in this application
```
Users are **isolated per application** — the same email registers independently
in each app. Registration is never MFA-gated.

### 3.2 Login — THE branching call
```
POST /api/v1/auth/apps/login                    Basic <app credentials>
{ "email": "jane@x.com", "password": "Secret123!" }
```
**Your frontend must branch on the response:**

| Status | Body contains | Meaning → next step |
|---|---|---|
| 200 | `access_token` | logged in, done |
| 200 | `requires_otp: true, otp_session_token, methods[], expires_in: 300` | second factor needed → §3.3. If `methods` includes `"email"`, a code was already emailed |
| 403 | `mfa_enrollment_required: true, enrollment_token, allowed_methods[], expires_in: 600` | `required` app + not enrolled → §3.4 |
| 401 | `error` | bad user or app credentials |
| 429 | `error, retry_after` | rate limited (5/min/IP, 10/min/client) |

### 3.3 Complete the OTP challenge (enrolled user)
```
POST /api/v1/auth/login/otp                     (no auth header)
{ "otp_session_token": "…", "code": "123456" }
→ 200 full token pair (+ auth cookies)
```
- `code` may be a **TOTP code**, a **backup code**, or the **emailed code** —
  one endpoint accepts whichever methods the challenge listed.
- 401 wrong/expired code · **429 after 5 wrong codes → session destroyed,
  restart from password** · also 429 from the endpoint rate limiter.

Re-send the email code (only when `methods` includes `email`):
```
POST /api/v1/auth/login/otp/resend
{ "otp_session_token": "…" }
→ 200 | 429 after 3 re-sends per challenge     # each re-send invalidates the previous code
```

### 3.4 Forced enrollment (`required` app, user not enrolled)
Show a method picker from `allowed_methods`, then:

**TOTP path** (authenticator app):
```
POST /api/v1/auth/login/mfa/enroll
{ "enrollment_token": "…" }
→ 200 { "otp_uri": "otpauth://totp/AcmeCRM:jane@x.com?secret=…&issuer=Acme+CRM",
        "backup_codes": ["ABCD2345", ×8] }     # render otp_uri as QR; show codes ONCE
```

**Email path**:
```
POST /api/v1/auth/login/mfa/email
{ "enrollment_token": "…" }
→ 200 "code sent"                              # 6-digit code to the account email; max 3 sends
```

**Both paths finish the same way — activation completes the login:**
```
POST /api/v1/auth/login/mfa/activate
{ "enrollment_token": "…", "code": "123456" }
→ 200 full token pair                          # MFA active + logged in, one step
```
Errors: 401 bad code/expired token · 403 method not allowed for this app ·
429 attempt budget (5) exhausted.

### 3.5 Token lifecycle (unchanged by MFA)
```
POST /api/v1/auth/refresh   { "refresh_token" }   → 200 new pair in the body (rotation; replay revokes the whole session family)
                                                    409 concurrent_refresh — a sibling request already rotated the family; no pair returned, use its response
GET  /api/v1/auth/me                                Bearer <user>   → profile from claims (user_id, tenant_id, email, role, permissions)
POST /api/v1/auth/logout    { "refresh_token" }   → 200
```
Access token TTL 15 min; refresh 30 days. The JWT carries `app_id` — verify it
matches your application.

---

## 4. Self-service MFA management (Bearer <user JWT>)

| Purpose | Endpoint | Notes |
|---|---|---|
| My MFA state | `GET /api/v1/auth/otp/status` | `{ enrolled, active, backup_codes_remaining, email_active, mfa_enabled }` — warn user when codes run low; hide MFA settings when `mfa_enabled` is false |
| Which methods I may use | `GET /api/v1/auth/me/mfa` | `{ mfa_required, mfa_enabled, mode, methods: [{ method, allowed, available, active }] }`. For an app user `allowed` = `mfa_enabled` **and** `mode != "disabled"` **and** method in the app's `allowed_methods` — only offer methods with `allowed: true` |
| Enroll TOTP | `POST /api/v1/auth/otp/enroll` body `{}` or `{ "code" }` | 403 `mfa_switched_off` if the app's switch is off; 403 if app mode `disabled` or `totp` not allowed. **Re-enroll while active (new phone) requires current TOTP/backup code in `code`** |
| Activate TOTP | `POST /api/v1/auth/otp/activate` `{ "code" }` | first authenticator code |
| Regenerate backup codes | `POST /api/v1/auth/otp/backup-codes` `{ "code" }` | → `{ "backup_codes": [×8] }`; TOTP secret unchanged; all old codes die |
| Disable TOTP | `DELETE /api/v1/auth/otp` `{ "code" }` | 403 under `required` unless email MFA remains active (last-factor guard; lifted while the switch is off) |
| Enroll email MFA | `POST /api/v1/auth/otp/email/enroll` | sends verification code; 403 `mfa_switched_off` if the switch is off; 403 if `disabled`/method not allowed |
| Activate email MFA | `POST /api/v1/auth/otp/email/activate` `{ "code" }` | inbox proven before it becomes a factor |
| Send proof code | `POST /api/v1/auth/otp/email/send` | fresh code for the disable action below |
| Disable email MFA | `DELETE /api/v1/auth/otp/email` `{ "code" }` | same last-factor guard mirrored |

Common error shape everywhere: `{ "error": "human-readable message" }`.
Newer codes use the coded shape `{ "error": "<stable_code>", "message": "<prose>" }` —
switch on `error`, never parse `message`. MFA switch codes:

| Code | Status | When |
|---|---|---|
| `mfa_switched_off` | 403 | enrolment attempted while the app's MFA switch is off |
| `mfa_switch_off_service_token` | 403 | a service/API-key token tried to turn MFA off |
| `mfa_switch_off_stale_session` | 403 | turning MFA off without an MFA sign-in in the last 10 minutes |

---

## 5. Guardrails your tests should hit

| Limit | Value | Behaviour on breach |
|---|---|---|
| Wrong codes per challenge/enrollment session | **5** | session destroyed → 429, restart from password |
| Email re-sends per challenge | **3** | 429 |
| OTP endpoints per IP | 10/min | 429 + `Retry-After: 60` |
| OTP endpoints per session token | 10/min | 429 |
| Login/register per IP (app routes) | 5/min | 429 |
| Login per client_id | 10/min | 429 |
| OTP challenge TTL | 5 min | token expires → 401 |
| Enrollment session TTL | 10 min | token expires → 401 |
| Pre-auth tokens | single-use | reuse → 401 |

---

## 6. Suggested test matrix for the dummy app

1. **optional + unenrolled** → login returns tokens directly.
2. **Voluntary TOTP setup** → status shows `active`, next login = two-step.
3. **required + new user, TOTP path** → 403 → enroll → activate → tokens; JWT `app_id` correct.
4. **required + new user, email path** → 403 → `/login/mfa/email` → code from server log → activate → tokens.
5. **Both factors active** → challenge `methods: ["totp","email"]`; each code type works; backup code works and decrements `backup_codes_remaining`.
6. **Brute force** → 5 wrong codes → 429; correct code then refused; fresh login works.
7. **Resend** → 3 ok (each rotates the code), 4th → 429; stale code refused.
8. **Isolation** → same email registered in a second app logs in without MFA there.
9. **Policy flips** → `disabled` blocks new enrollments but still challenges enrolled users; `required` blocks disabling the last factor.
9a. **Master switch** → `mfa_enabled: false`: enrolled user gets tokens with no challenge, `required` stops forcing enrolment, enrolment returns 403 `mfa_switched_off`, `/auth/me/mfa` shows every method `allowed: false`. Switch on → challenge returns at the next login. A management token gets 403 `mfa_switch_off_service_token` turning it off but may turn it on.
10. **Admin reset** → both factors wiped, next login re-enrolls.
11. **Sender chain** → configure tenant sender then app override; check `from` in the dev-mailer log; delete each level and watch the fallback.
