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
  current (default `["totp"]`). Only accepted together with `mode`; sent
  without it → 400 `allowed_methods requires mode`
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
To apply a tightened policy now, revoke the application's sessions (§2.3d).

Social and passkey sign-ins follow the switch and `mode` only when the
application opts in with `federated_mfa: "enforce"` (§2.3b).

### 2.3b Social and passkey sign-ins (`federated_mfa`)
```
PUT /api/v1/applications/{appID}/mfa            Bearer <admin>
{ "federated_mfa": "enforce" }                   # mode may be omitted
→ 200 (policy incl. "federated_mfa": "enforce")
```

| | `federated_mfa: "trust"` (default) | `federated_mfa: "enforce"` |
|---|---|---|
| Social sign-in (Google, GitHub) | tokens at `/auth/oauth/exchange`, no app MFA step — unchanged | the **same app MFA gate as password login** runs at `/auth/oauth/exchange` |
| Passkey **with** user verification (biometric / PIN) | tokens | tokens — a user-verified passkey is already two factors and **satisfies** app MFA |
| Passkey **without** user verification | tokens, no app MFA step | the same app MFA gate as password login runs at `/auth/passkey/login/complete` |

`enforce` changes the response contract of those two endpoints **for this
application only**. Where a second factor is due they answer exactly like
`/auth/apps/login` (§3.2):

| Status | Body | Next step |
|---|---|---|
| 200 | `access_token` … | done (nothing due) |
| 200 | `requires_otp: true, otp_session_token, methods[], expires_in` | §3.3 (`POST /auth/login/otp`) |
| 403 | `mfa_enrollment_required: true, enrollment_token, allowed_methods[], expires_in` | §3.4 (`/auth/login/mfa/*`) |
| 503 | `error: "app_mfa_unavailable"` | the server cannot run the challenge; no tokens |

The `login_code` is spent at the exchange either way; the challenge token
replaces it. The finished session keeps the original grant (`gty: "social"` /
`"passkey"`) and its `amr` records the extra factor (`fed`/`hwk` + `otp`,
`mfa`). Everything else — switch off, `mode`, `allowed_methods`, role rules (§2.3c) —
applies to these sign-ins exactly as to password login. Tenant-level (console)
social and passkey sign-ins are not affected.

Every real change writes an `admin.mfa_federated_changed` audit event
(`old_federated_mfa`, `new_federated_mfa`). Turn `enforce` on only once your
social-callback and passkey code handles the challenge responses above — a
client that only knows the token shape will treat them as a failure.

### 2.3c Role-based MFA rules (`/mfa/role-rules`)
Require MFA only of users holding certain roles, on an otherwise `optional`
application.
```
GET /api/v1/applications/{appID}/mfa/role-rules            Bearer <admin>
→ 200 { "application_id": "149",
        "rules": [ { "role_id": "12", "role_name": "finance", "created_at": "…", "created_by": "7" } ] }

PUT /api/v1/applications/{appID}/mfa/role-rules            Bearer <admin>
{ "role_ids": ["12", "15"] }                                # the WHOLE new list; [] clears
→ 200 (same shape as GET)
```
Also under `/api/v1/tenants/{tid}/applications/{appID}/mfa/role-rules`, with
the same permissions as the `/mfa` routes.

- A user holding **any** listed role — as their primary role or any
  additional grant — is treated as `required`: challenged if enrolled, forced
  to enrol otherwise, and unable to remove their last factor. Roles are read
  from the database at each login, never from the token.
- Rules apply only while `mfa_enabled` is true and `mode` is not `disabled`.
  Under `required` they add nothing (everyone is already covered).
- **Rules cover social and passkey sign-ins only when `federated_mfa` is
  `enforce`** (§2.3b). With `trust`, a covered user signing in with Google or
  a passkey is not challenged.
- Only the application's own live roles are accepted → otherwise
  **400 `mfa_role_rule_invalid_role`**. At most 100 roles → **400
  `mfa_role_rules_too_many`**.
- A non-empty list while the switch is off or the mode is `disabled` →
  **409 `mfa_role_rules_inactive`**. Clearing (`[]`) is always accepted.
- A non-empty list while `email` is the only allowed method and passwordless
  email-code sign-in is on for the application → **409
  `mfa_role_rules_passwordless_conflict`** (covered users could no longer sign
  in by email code). Conversely, while rules exist, turning email codes on or
  narrowing the methods to `email` only is refused with
  `passwordless_mfa_conflict` — rules count as `required` for that check.
- A role listed by a rule cannot be deleted → `DELETE /roles/{id}` answers
  **409 `role_in_mfa_rule`**; remove the rule first.
- Forced enrolment offers only allowed methods this server can run; if none
  can run, sign-in is refused with **503 `app_mfa_unavailable`**.
- Every real change writes `admin.mfa_role_rules_set` (`old_role_ids`,
  `new_role_ids`, `old_role_names`, `new_role_names`). Changes apply at the
  next login.
- `GET /auth/me/mfa` for a covered user reports
  `"mfa_required_by": "role:<name>"`.

### 2.3d Revoke every session of the application (#196)
Policy changes never end sessions by themselves. After turning MFA on or
tightening it, an administrator can sign every user of the application out so
each one meets the new policy at their next login:
```
POST /api/v1/applications/{appID}/sessions/revoke          Bearer <admin>
POST /api/v1/tenants/{tid}/applications/{appID}/sessions/revoke
→ 200 { "application_id": "149", "revoked": 42, "failed": 0 }
```
- Same permission as `PUT .../mfa` (`apps:write`).
- Ends every live session bound to the application in this tenant (its own
  users and tenant-level users who signed in through it). Refresh tokens are
  revoked (`revoked_reason = admin_app_revoke_all`) and outstanding access
  tokens are denied immediately.
- Idempotent; `failed > 0` (logged server-side) is worth a retry. 503
  `service_unavailable` when the server cannot deny access tokens.
- Audited as `admin.application_sessions_revoked` with `revoked` / `failed`.

### 2.3e Step-up at refresh (`refresh_step_up`, #197)
Off by default. With it off, refresh is never re-checked against the MFA
policy (exactly the pre-#197 behaviour). Turn it on per application:
```
PUT /api/v1/applications/{appID}/mfa                         Bearer <admin>
{ "refresh_step_up": true }        → 200 { …, "refresh_step_up": true }
```
While on, every refresh (`POST /auth/refresh`, `POST /auth/session/refresh`,
the cookie renewal middleware, and `POST /oauth/token` with
`grant_type=refresh_token`) of a session whose `amr` lacks `mfa` is refused when
the application now requires MFA of the user:
- the switch is on and the mode is `required`, or a role rule (§2.3c) covers
  the user;
- social (`fed`) and passkey (`hwk`) sessions only when `federated_mfa` is
  `enforce` — under `trust` they are not forced, as at login.
```
→ 401 { "error": "step_up_required", "message": "…" }
```
Nothing is revoked and the refresh token is not rotated: your app sends the
user through sign-in again, where the login gate challenges or enrols them.
Sessions that did MFA, tenant-level users (no application), administrators and
`client_credentials` tokens are never affected. The renewal middleware leaves
the cookies in place on this refusal.

Cost: the flag is read in the refresh-token lookup the rotation already does,
so an application with it off pays nothing. With it on, a session without
`mfa` costs one extra indexed read per refresh.

A real change is audited as `admin.mfa_refresh_step_up_changed`
(`old_refresh_step_up`, `new_refresh_step_up`).

### 2.4 Read policy + enrollment stats (dashboard)
```
GET /api/v1/applications/{appID}/mfa            Bearer <admin>
→ 200 {
  "application_id": "149", "mfa_enabled": true, "mode": "required", "federated_mfa": "trust",
  "refresh_step_up": false,
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
| 503 | `error: "app_mfa_unavailable"` | a second factor is due (user has an active permitted factor, or the app is `required`) but this server cannot run the challenge (no Redis / TOTP service, or none of the user's methods is configured). **No tokens.** Not a credential failure — do not tell the user their password is wrong |
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
                                                    401 step_up_required — only when the app has refresh_step_up on (§2.3e): sign in again
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
| Which methods I may use | `GET /api/v1/auth/me/mfa` | `{ mfa_required, mfa_enabled, mode, mfa_required_by?, methods: [{ method, allowed, available, active }] }`. `mfa_required_by` is `"role:<name>"` when an MFA role rule covers the user (§2.3c). For an app user `allowed` = `mfa_enabled` **and** `mode != "disabled"` **and** method in the app's `allowed_methods` — only offer methods with `allowed: true` |
| Enroll TOTP | `POST /api/v1/auth/otp/enroll` body `{}` or `{ "code" }` | 403 `mfa_switched_off` if the app's switch is off; 403 if app mode `disabled` or `totp` not allowed. **Re-enroll while active (new phone) requires current TOTP/backup code in `code`** |
| Activate TOTP | `POST /api/v1/auth/otp/activate` `{ "code" }` | first authenticator code |
| Regenerate backup codes | `POST /api/v1/auth/otp/backup-codes` `{ "code" }` | → `{ "backup_codes": [×8] }`; TOTP secret unchanged; all old codes die |
| Disable TOTP | `DELETE /api/v1/auth/otp` `{ "code" }` | 403 under `required` or an MFA role rule unless email MFA remains active (last-factor guard; lifted while the switch is off) |
| Enroll email MFA | `POST /api/v1/auth/otp/email/enroll` | sends verification code; 403 `mfa_switched_off` if the switch is off; 403 if `disabled`/method not allowed |
| Activate email MFA | `POST /api/v1/auth/otp/email/activate` `{ "code" }` | inbox proven before it becomes a factor |
| Send proof code | `POST /api/v1/auth/otp/email/send` | fresh code for the disable action below |
| Disable email MFA | `DELETE /api/v1/auth/otp/email` `{ "code" }` | same last-factor guard mirrored |

Common error shape everywhere: `{ "error": "human-readable message" }`.
Newer codes use the coded shape `{ "error": "<stable_code>", "message": "<prose>" }` —
switch on `error`, never parse `message`. MFA switch codes:

| Code | Status | When |
|---|---|---|
| `mfa_switched_off` | 403 | enrolment attempted while the app's MFA switch is off — self-service enrolment, or a forced-enrolment token (`/auth/login/mfa/enroll`, `/email`, `/activate`) minted before the switch was turned off. The enrolment token is invalidated; sign in again |
| `mfa_switch_off_service_token` | 403 | a service/API-key token tried to turn MFA off |
| `mfa_switch_off_stale_session` | 403 | turning MFA off without an MFA sign-in in the last 10 minutes |
| `app_mfa_unavailable` | 503 | sign-in refused: the application requires a second factor at this login and the server cannot run it. Returned by every first factor that goes through the app MFA gate (password, magic link, email code, and social / unverified-passkey sign-ins under `federated_mfa: "enforce"`). Fail-closed since #193: before it, such a server issued tokens without MFA |

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
