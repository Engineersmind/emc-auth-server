# Passwordless registration & login (email OTP) — implementation plan

| | |
|---|---|
| Status | **Proposed — for review** |
| Baseline | `master` @ `d63d51a` (PR #183 merged; no newer commits on `origin/master` at time of writing, 2026-11-11) |
| Scope | Application-scoped end users (`/auth/apps/*` API and the admin console; the auth server provides no end-user screens for this flow). Platform/console administrators are **out of scope** and stay password + mandatory MFA. |
| Principle | Passwordless is **additive**. Password flow is untouched and remains the default; each application chooses its own mix. |

---

## 0. Compatibility guarantee (overrides anything below that says otherwise)

**Everything that is live today keeps behaving exactly as it does now.** An application can run
the **password flow** (current, and the default), the **passwordless flow**, or **both side by
side**. An application with no passwordless policy is byte-for-byte what it is today.

1. **No behaviour change for applications that have not opted in.** Same requests, responses,
   status codes, timing and side effects on every existing endpoint.
2. **No refactor of live code.** `Login`, `VerifyMagicLink`, `Register`, password reset,
   invitation acceptance, social login, MFA enrollment and challenge stay as they are. The new
   flow is separate code that **calls the same existing building blocks** (token issue, MFA gate,
   organization selection, lock checks). Shared code changes only through additive options whose
   zero value is today's behaviour.
3. **Magic link and email MFA are untouched.** Gaps G1, G2 and G4 are recorded in §2 but are
   **not fixed by this plan**. Fixing them would change live behaviour, so any fix is an
   explicit, opt-in follow-up. The rule "email is not offered as a second factor after an
   inbox-based first factor" applies to the **new email-code flow only**.
4. **Per-application modes:** *password only* (default, today), *both*, *passwordless only*
   (optional). "Both" lets the user choose on each sign-in.
5. **Proof, not promise.** Before any feature code: characterisation tests that pin current
   behaviour of password login, magic link, register, reset, MFA, organization selection, social
   login and the hosted login page. They run on every PR. The existing test suite passes
   unchanged; existing tests are only ever added to. The generated API spec may only gain
   entries.
6. **Passwords are never deleted or changed by this feature.** A user's stored password stays exactly as it is, including when an application later moves to *passwordless only*. In that mode the password flow is **closed**: login, register, forgot/reset and change-password answer `password_auth_disabled` before any password is read or checked. Moving the application back makes the stored passwords work again. Mode changes never rewrite data (§4.11). Nothing changes for applications that have not opted in; the only new behaviour in an opted-in *passwordless only* application is that closure.
7. **Side effects of merely deploying:** new routes that answer 404 while the global switch is
   off, two new tables, and one more entry in the email template list. None of these changes
   behaviour.

---

## 1. Summary

A user types an email address. The server emails a 6-digit one-time code. Entering it
either signs the user in (account exists) or **creates the account and signs in**
(account does not exist and the application allows sign-up). No password is ever
requested, stored or reset for that user.

The same two calls (`start`, `verify`) cover registration **and** login, so a caller
never has to know whether the email is already registered — which is also what makes
the flow enumeration-safe.

Key decisions (details in the sections noted):

1. **Code, not link, is the primary mechanism** (§3, §4). Codes survive email-scanner
   prefetch, work across devices, and avoid login-CSRF. The existing magic link stays.
2. **Account is created at `verify`, never at `start`** (§4.3) — no unverified rows, no
   squatting, no cleanup job.
3. **Same MFA / org / session building blocks as password login** (§4.6) called from a new,
   separate path. Live login code is **not** refactored (§0); a parity test keeps the two paths
   from drifting.
4. **An emailed code never counts as the second factor of an emailed-code login** (§4.7).
5. **Pre-hijack safeguard that keeps passwords:** the first time an owner proves inbox control on an unverified, password-bearing account, existing sessions are revoked, the email is marked verified and the owner is told. The stored password is kept (§4.4, T3).
6. Everything is **opt-in per application** behind a global kill-switch (§4.8, §9).

---

## 2. Current platform — what exists (verified in code)

| Area | Where | Relevance |
|---|---|---|
| Magic-link login | `internal/auth/magic_link.go`, `POST /auth/apps/login/magic[/verify]` | Login-only (no sign-up), link not code, S2S only. Proves the model works: 256-bit token, SHA-256 in Redis, `GETDEL`, app-bound, then `mfaGate`. |
| Email OTP as **second** factor | `internal/auth/email_mfa.go` | 6-digit generator, Redis hash + TTL, attempt budget, resend cap (3), white-label sender fallback, template-suppression handling. Reusable pieces. |
| Credential-less users | `user_credentials` is a separate table; `Login` joins it; social users (`oauthflow.go:679`) have **no row** | A passwordless user is simply a user with no credential row. **No schema change to `users`.** |
| Registration | `AuthService.Register` (`service.go:1161`) | Default-role + `user_roles` transaction, welcome/verification mails, deliberately returns **no session**. Passwordless sign-up must reuse the user-creation block. |
| MFA gate | `mfaGate` (`service.go:1896`) | Enforces per-app mode/allowed methods; fails closed. |
| Org sessions | `orgSessionRequest`, `409 organization_selection_required` | Must work for OTP login. |
| Lockout / soft-lock | `blockSvc.SoftLockedFor`, `ExpireHardLock`, `ResetFailedLogins` | Run in password `Login`; **not** in magic link. |
| Rate limiting | `s2s.UserLimit` / `GuessLimit`, `RATE_LIMIT_APP_USER_*` | Per-recipient and per-IP patterns exist for magic link. |
| CAPTCHA | `captcha_gate.go`, per-scope policy (#145) | Reusable on `start`. |
| Mail | `mailer` + 13 templates, per-scope templates & white-label senders | New template needed (14). |
| Passkeys | `webauthn.go`, `docs/WEBAUTHN_MASTER_PLAN.md` | Complementary: OTP bootstraps, passkey is the durable passwordless credential. |
| Email normalisation | `emailaddr.Normalize`, DB `CHECK (email = lower(email))` | Use as-is. |

### Gaps found while reading (these shape the plan)

- **G1 — Magic-link is an enumeration oracle.** `RequestMagicLink` returns an error if the
  *send* fails, and only existing accounts reach the send. A mail outage (or a bad
  address) therefore distinguishes "account exists" from "doesn't". OTP must send
  asynchronously and always answer identically. (Fix the magic link in the same PR.)
- **G2 — Magic-link skips post-auth steps `Login` performs**: soft-lock check, hard-lock
  expiry, `ResetFailedLogins`, role-scoped sessions, org request. A new factor copy-pasting
  that shape would repeat the drift. → the new path repeats those steps in the same order and a parity test guards drift (§4.6); the live magic link is not edited (§0).
- **G3 — Weak code hashing.** `HashToken` is plain SHA-256. Fine for 256-bit tokens, **not**
  for a 10⁶ space: a Redis read leak recovers any code instantly. New flow uses
  HMAC-SHA-256 with a server key. (Retrofit `email_mfa` as a follow-up.)
- **G4 — Email MFA after email login is the same factor twice.** After a magic link,
  `mfaGate` can still offer the *email* method as "second factor". Ceremony, not security.
- **G5 — Password reset assumes a credential row** (`reset.go:397` is an `UPDATE`). For a user with no password it affects 0 rows. **Recorded, not fixed:** the flow stays as it is. It is closed in passwordless-only applications and, in *both* mode, such users sign in by code (§4.11).
- **G6 — Today's app endpoints require the client secret** (`Authorization: Basic`), i.e. a confidential backend. The integrating app calls them from its own backend and builds its own sign-in screens. The auth server provides no end-user screens for this flow, and the hosted `/oauth/authorize` page is not changed (no code option in v1).
- **G7 — Magic link is not bound to the initiating browser** → login-CSRF (attacker mails
  *their own* link to a victim; victim's browser ends up in the attacker's account). The OTP
  flow is immune because the code is typed into the session that started it. Noted, not
  fixed here.

---

## 3. Industry comparison

Based on vendors' public documentation; re-verify specifics before quoting externally.

| IdP | Passwordless email | Sign-up & login unified | Notes worth copying / avoiding |
|---|---|---|---|
| **Auth0** | `/passwordless/start` + OTP-grant token exchange (code or link) | Yes; "disable sign-ups" toggle per connection | Short-lived 6-digit code, attempt-limited. Same start/verify split we propose. |
| **Okta (OIE)** | Email authenticator usable as primary via authentication policy | No (user must exist / be provisioned) | Policy-driven, "password optional". Enterprise-grade assurance levels. |
| **AWS Cognito** | Email/SMS OTP + passkeys as first factor (choice-based sign-in, 2024+) | Sign-up separate | Earlier required custom Lambda challenges — high build cost. |
| **Clerk** | Email code / email link, password optional | Yes | Best-in-class UX: code autofill, per-instance toggle, verification baked into sign-up. |
| **Stytch** | Email OTP + magic link, `login_or_create` | Yes | Single call semantic; configurable expiry. |
| **Firebase Auth** | Email **link** only | Yes | Needs same-device email persistence or re-prompt; no code option → weaker cross-device UX. |
| **Microsoft Entra External ID** | Email OTP for customer sign-up/sign-in | Yes | Tenant-level user flows. |
| **Keycloak** | No native first-factor email OTP (extensions only) | n/a | Cautionary: pushing this to extensions fragments security review. |

**Takeaways adopted**

- Unified `start`/`verify` pair, sign-up as a per-application switch (Auth0, Stytch, Clerk).
- 6-digit code, short TTL, hard attempt cap, per-email and per-IP throttles (all).
- Policy-driven per-application control and ability to enforce stronger factors on top (Okta).
- Passkeys as the long-term passwordless credential; OTP as bootstrap/recovery (Cognito, Clerk direction).
- Code over link as primary (Firebase's link-only limitation is the counter-example).

**Where we deliberately go further**: enumeration-parity including timing and failure paths,
pre-hijack neutralisation, no same-factor MFA double-count, domain allow-lists for
enterprise tenants, and a parity test so the new path gets lockout, role, org and MFA handling identical to password login.

---

## 4. Design

### 4.1 Per-application authentication-methods policy

New table `passwordless_policies` (migration `00105`, additive; magic-link columns are **not**
moved). It copies the **platform → tenant → application** scope model of `captcha_policies`
(migration 00090) so inheritance, the resolved `source`, and the admin API shape are the ones
administrators already know. Every tunable column is nullable; `NULL` means "inherit".

```sql
CREATE TABLE passwordless_policies (
  id                    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id             BIGINT REFERENCES tenants(id) ON DELETE CASCADE,       -- NULL/NULL = platform
  application_id        BIGINT REFERENCES oauth_clients(id) ON DELETE CASCADE, -- set = application
  email_otp_enabled     BOOLEAN,           -- NULL = inherit
  signup_enabled        BOOLEAN,           -- create account on first verified code
  password_enabled      BOOLEAN,           -- false = password register/login/reset refused
  allowed_email_domains TEXT[],            -- empty/NULL = any; else sign-up restricted
  blocked_email_domains TEXT[],            -- disposable / abuse list (merged up the chain)
  code_ttl_seconds      INT CHECK (code_ttl_seconds BETWEEN 300 AND 900),
  max_attempts          INT CHECK (max_attempts BETWEEN 3 AND 5),
  max_resends           INT CHECK (max_resends BETWEEN 0 AND 5),
  resend_cooldown_secs  INT CHECK (resend_cooldown_secs BETWEEN 30 AND 300),
  starts_per_hour       INT CHECK (starts_per_hour BETWEEN 1 AND 10),   -- per email
  daily_email_budget    INT CHECK (daily_email_budget >= 0),            -- per scope; 0 = unlimited
  allow_persistent      BOOLEAN,           -- "remember me" on code sign-in
  welcome_email_enabled BOOLEAN,
  version               INT NOT NULL DEFAULT 1,        -- optimistic concurrency for the console
  updated_by            BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE NULLS NOT DISTINCT (tenant_id, application_id)
);
CREATE TABLE passwordless_policy_history (   -- append-only, powers "history & restore" in the console
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  policy_id BIGINT NOT NULL, tenant_id BIGINT, application_id BIGINT,
  changed_by BIGINT, change JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

Resolution is application → tenant → platform → built-in default, per field, and the API reports
`effective` values plus `source` per field. The "an app can never have zero first factors" rule
cannot be a table CHECK once values inherit, so it is enforced on the **resolved** policy at
write time (and re-checked at request time, failing safe to password). Platform rows are
**ceilings** as well as defaults: a tenant or application may tighten but not exceed them (§7.3).

No row anywhere ⇒ today's behaviour (password only). Resulting modes:

| `email_otp_enabled` | `password_enabled` | Mode |
|---|---|---|
| false | true | **Password only** (default, unchanged) |
| true | true | **Both** — user chooses |
| true | false | **Passwordless only** |

`signup_enabled=false` with OTP on gives "passwordless login for provisioned users" (invite-only
enterprise apps).

### 4.2 API (application-authenticated; same credential channel and limiter chain as `/apps/login`)

```
POST /api/v1/auth/apps/passwordless/start    { email, first_name?, last_name?, persistent?, captcha_id?, captcha_answer? }
 → 200 { challenge_id, expires_in, resend_after, code_length }          // ALWAYS, for any email

POST /api/v1/auth/apps/passwordless/resend   { challenge_id }
 → 200 { resend_after, resends_left }

POST /api/v1/auth/apps/passwordless/verify   { challenge_id, code, organization?, roles? }
 → 200 tokens | 200 mfa/otp challenge | 200 mfa enrollment | 409 organization_selection_required
 → 400 invalid_or_expired_code            // single uniform error
 → 429 …                                  // limiter, keyed by email/IP, never by existence
```

The auth server provides the API only. The sign-in and sign-up screens are built by the integrating application (§7.2).

Error vocabulary: `passwordless_disabled` (policy off — safe to reveal, it is per-app config),
`captcha_required` (428, existing contract), `invalid_or_expired_code`, `too_many_attempts`.

### 4.3 State machine (Redis; no new durable table)

```
start ──► challenge pwless:ch:{id}  (hash)
            email, tenant, app, code_mac, attempts=0, resends=0,
            persistent, name_hint, ip_hash, created_at, decoy(bool)
            TTL = code_ttl_seconds
          + counters: pwless:start:{app}:{sha(email)}  (hour/day), pwless:fail:{app}:{sha(email)}
verify ──► Lua (atomic): load → attempts++ → >MAX? delete : compare HMAC (const-time)
            match → DEL challenge, return payload
            ── then ──► resolve user (fresh DB read) → completePasswordlessLogin (§4.6)
```

- `challenge_id`: 256-bit random, opaque, **not** derived from the email.
- **Code**: 6 digits from `crypto/rand` (reuse `generateEmailOTP`), stored as
  `HMAC-SHA256(key=PASSWORDLESS_CODE_HMAC_KEY, challenge_id || code)`; never logged
  (DevMailer excepted, as today).
- **Max 5 wrong attempts** per challenge → challenge destroyed. Cross-challenge budget per
  `(app,email)`: 10 failures/hour → passwordless verify refused for that email for 15 min
  (does **not** affect password login). Closes "mint many challenges × 5 guesses".
- **Resend** rotates the code on the *same* challenge (old code dies — "use the latest"),
  30 s cooldown, max 3.
- **Latest start wins**: a new `start` for the same `(app,email)` supersedes the prior
  challenge.
- **Decoy challenges**: for unknown email with sign-up disabled, blocked/inactive accounts,
  domain-rejected addresses, and throttled senders, `start` stores a decoy with identical shape,
  sends nothing, and `verify` fails after the same attempt budget. Callers cannot tell.
- **Sending is asynchronous** (bounded in-process worker with retry/backoff, or the mailer's
  queue if one exists) so SMTP latency/failure never reaches the HTTP response (fixes G1).
  Response time is equalised with the existing `settleLoginTiming` mechanism.

### 4.4 Resolving the user at `verify` (after the code is proven)

| Situation | Action |
|---|---|
| User exists, active, verified | Login. |
| User exists, active, **unverified**, has a password | Keep the stored password. Revoke refresh tokens and bump `token_version` (ends any session an attacker opened), set `email_verified=true`, audit, and email the owner that a password exists on the account, with a link to the existing forgot-password page when passwords are enabled. Then log in. Residual risk in *both* mode is stated in T3. |
| User exists, unverified, no password (e.g. invited) | Set `email_verified=true`, login. |
| User exists but blocked / `is_active=false` / soft-locked / tenant inactive | Generic `invalid_or_expired_code` (hard lock expiry handled like password login). |
| No user, `signup_enabled`, domain permitted | **Create** user (new-path helper, `Register` untouched: default role + `user_roles` in one tx, `email_verified=true`, **no** `user_credentials`), send welcome mail, login. |
| No user, sign-up off / domain rejected | Generic `invalid_or_expired_code`. |
| Concurrent verifies racing to create | `INSERT … ON CONFLICT` on the per-app email unique index; loser re-reads and logs in. Idempotent. |

### 4.5 Sessions & tokens

- New `GrantEmailOTP = "email_otp"` (add to `HumanGrants`, `organization_mint.go` switch).
- `amr`: new `AMREmailOTP = "email_otp"` (no RFC 8176 value for email; same precedent as
  `AMRMagicLink = "link"`). After a TOTP step: `["email_otp","otp","mfa"]`.
- `persistent` only when the app's session policy permits it **and** the user ticked it at
  `start` (carried in the challenge). Default non-persistent.
- Session limits, device listing, refresh, revocation: unchanged (shared issuer).

### 4.6 Completing a sign-in on the new path (no refactor of live code)

`completePasswordlessLogin` lives in the new `passwordless.go` and performs the same steps as
password `Login` does after the password check, **in the same order**, by calling the same
existing helpers: soft-lock check → hard-lock expiry → `ResetFailedLogins` → role scoping →
permission load → organization request → `mfaGate` → `issueTokenPair` → audit.
`Login`, `VerifyMagicLink` and `Register` are not edited.

- **Parity test:** a table-driven test runs a password login and a code login against the same
  user states (active, soft-locked, hard-locked, role-scoped, multi-org, MFA optional and
  required) and asserts the same outcomes. This is what prevents drift.
- **User creation:** the new path has its own small helper for the default-role transaction.
  `Register` keeps its own copy.
- **Duplication is deliberate and tracked.** Converging the paths into one function is a later,
  separately approved change, made only after the new flow has run in production.

### 4.7 MFA interaction

- `mfaGate` becomes a thin wrapper over a variant that takes an options struct. The zero value
  is today's behaviour, so both existing callers are unchanged. The **new email-code flow**
  passes `inboxFirstFactor: true`, which removes the **email** second-factor method from the
  offered set. TOTP and passkeys remain. The magic link keeps its current behaviour (§0, rule 3).
- App `mode=required` + passwordless: user without TOTP gets the existing forced-enrollment
  challenge with `allowed_methods` minus `email`.
- **Validation at policy-write time**: reject `email_otp_enabled=true` with `mode=required`
  and `allowed_methods={email}` (would be unsatisfiable / fake MFA). Error
  `passwordless_mfa_conflict`.
- Administrators: `appRowID==0` never reaches this flow; admin MFA gate untouched.

### 4.8 Configuration & kill-switch

- `PASSWORDLESS_ENABLED` (default `false`) — global switch; routes answer `404` when off,
  mirroring `ORGANIZATIONS_ENABLED`.
- `PASSWORDLESS_CODE_HMAC_KEY` — required in production/staging (fail-fast like
  `TOTP_ENCRYPTION_KEY`).
- `RATE_LIMIT_APP_USER_PASSWORDLESS_START`, `…_VERIFY` (+ per-app daily e-mail budget).
- Per-app quota (`appClientRateLimit`) already applies.

### 4.9 Password coexistence

- **Stored passwords are never deleted.** Not by a mode change, not by a code sign-in, not by an admin action in this plan. There is no "remove password" action.
- **`password_enabled=false` closes the password flow, it does not erase it:** `/apps/register`, `/apps/login`, forgot/reset, reset-link redemption and change-password all answer `password_auth_disabled` before any lookup, hash or comparison. Hashes stay in `user_credentials`, unread. Setting `password_enabled=true` again makes them work.
- **Forgot-password is not needed for passwordless users.** The live flow is left as it is. In passwordless-only applications it is closed. In *both* mode a user who has no password signs in by code.
- **`/apps/login` for a user with no password** returns the normal `invalid credentials` (no hint).
- **Setting a password later** is not part of v1. If product wants it in *both* mode it is an optional Phase 3 item (`POST /auth/me/password/set`, confirmed by a fresh code to the inbox).

### 4.10 Email content (template `14_passwordless_code`)

One template, two copy variants (sign-in / verify-your-address, chosen at send time — only the
inbox owner sees it). Contents: app name, large code, TTL, approximate request origin
(IP-derived geo, existing enrichment), "didn't request this? ignore — no account change". The code is on its own line so mail apps can offer to copy or autofill it. Honours per-scope template overrides, suppression and white-label sender with global
fallback (same helpers as `email_mfa.mintAndSend`). Subject must not contain the code.

---

### 4.11 Switching an application's mode, including while it is live

**Rules**
1. A mode change never deletes or rewrites data. Stored password hashes stay in `user_credentials` exactly as they are.
2. A change applies to new requests only. Nothing already issued is rewritten.
3. It is reversible at any time, and switching back makes stored passwords work again.
4. Each request resolves the whole policy once, so no request sees a half-applied change. A change takes effect within the policy cache lifetime (target 30 s or less; confirm against the existing policy cache in Phase 2a).

**What happens when an admin switches an application from *password* or *both* to *passwordless only* while it is live**

| Item | Behaviour |
|---|---|
| Stored passwords | Kept, dormant. Not read, not verified, not re-hashed |
| New password sign-in attempts (`/apps/login`, tenant `/login` for that app) | Refused at once with `password_auth_disabled`, **before** any lookup or hash work. Not counted toward lockout. Counted in a metric and a rate-limited audit event so admins can see who still uses passwords |
| Existing sessions and refresh tokens | Keep working until normal expiry. Refresh does not depend on how the user signed in. A **Sign out everyone** checkbox in the confirmation dialog (off by default) uses the existing revoke-all |
| Sign-ins already in progress (password verified, MFA code pending) | May finish. Bounded by the OTP session lifetime (5 minutes). No new ones start |
| Forgot-password and reset links | Closed. New requests refused. Links issued earlier stop working when redeemed and show a generic "sign in with an email code" message |
| Change-password for signed-in users | Closed |
| Password self-registration (`/apps/register`) | Closed. Accounts come only from code sign-up (if `signup_enabled`), admin creation or import. If sign-up is off too, there is no self-registration. The impact preview says so |
| Invitations | Accepting an invitation normally sets a password. Here the link leads to the code sign-in; completing it activates the account and marks the invitation accepted |
| MFA | Unchanged. TOTP enrolments stay. A `required` app still enforces a second factor after the code. Users who only have email as a second factor are listed in the impact preview as "will be asked to enrol TOTP" |
| Users with an unverified email | The code sign-in proves the inbox and verifies it |
| Social login, passkeys, SAML | Unchanged |
| Integrator backends that call `/apps/login` with passwords | **These stop working at the moment of the switch.** This is the main reason for the staged path below |
| Console administrators | Unaffected (tenant-level) |
| Tokens already issued | Unchanged, including `amr = pwd` |

**Recommended path:** password only → **both** → passwordless only. In *both*, announce the change, let integrators move, and watch the "password sign-ins in the last 7 and 30 days" figure fall to about zero before closing the password flow.

**Switching back (to *both* or *password only*)**
- Stored passwords work again immediately.
- Users who signed up by code have **no password**. In *both* they keep using the code. In *password only* they could not sign in, so the console **blocks the switch to password only while active users without a password exist**, unless the admin explicitly overrides.
- In *both*, a user without a password who uses forgot-password hits the existing live behaviour (G5: the link is used up and no password is set). It is recorded, not fixed here. They can sign in by code.

**Guardrails on the switch**
- **Impact preview** shows: users with a stored password (kept), users without any password, active users with an unverified email, password sign-ins in the last 7 and 30 days (users and count), how many `/apps/login` calls came from integrations, users who would be asked to enrol TOTP, and whether self-registration will remain possible.
- Typed application name to confirm. Asking the admin for MFA again is deferred (§11).
- Optional **scheduled cutover** (effective at a chosen time) so integrators get notice.
- One-click revert from the settings history. Every change is audited with before and after.
- Two admins changing the policy at once: the second gets a 409 with the other change shown.
- A tenant default of *passwordless only* shows the per-application impact list before it is saved. Setting it at tenant level is discouraged.

**Global kill switch caution.** `PASSWORDLESS_ENABLED=false` hides the feature and stops code sign-in. Users who were created without a password then have **no way in** until it is turned back on, and applications set to passwordless only would have no first factor at all. For that reason an emergency rollback should first stop **new sign-ups** (`signup_enabled=false`) and keep code sign-in on for existing users. The full switch is a last resort, and while it is off the password flow is reopened for users who have a stored password.

## 5. Threat model & controls

| # | Threat | Control |
|---|---|---|
| T1 | Brute-forcing 6-digit code | 5 attempts/challenge; 10 fails/hour/email; per-IP limiter; HMAC'd code; atomic Lua verify; short TTL |
| T2 | Account enumeration (body, status, timing, **failure path**) | Identical 200 on `start`; decoy challenges; async send; timing settle; uniform verify error; limiter keyed on input not existence |
| T3 | **Pre-hijack** (attacker registers `victim@x` with a password; victim later signs in by code) | Keep the password; on first inbox proof revoke sessions, bump `token_version`, mark verified and notify the owner. In passwordless-only apps the password is closed and harmless. In *both* mode the attacker's password still works until the owner resets it through the existing forgot-password flow. **Residual risk, accepted;** the same risk exists today without this feature |
| T4 | Mail bombing a victim / SMTP cost abuse | Per-email 5/h & 20/day start cap, resend cap + cooldown, per-IP cap, per-app daily budget, CAPTCHA policy hook, no mail for decoys |
| T5 | Code interception (mailbox compromise) | Inherent to email factor; mitigated by risk signals, new-device notification, optional TOTP/passkey on top, passkey enrolment nudge |
| T6 | Phishing relay (real-time proxy of the code) | Origin-bound code line, anti-phishing copy, recommend passkeys; documented residual risk |
| T7 | Login-CSRF / session fixation | Code typed into the initiating session; `challenge_id` bound to the caller's app credentials |
| T8 | Cross-application replay | `challenge_id` stores app+tenant; verify rejects mismatch; user lookups app-scoped |
| T9 | Code reuse / race | `DEL` inside the same Lua script; account creation idempotent |
| T10 | Redis loss/failover | Fail **closed** (verify = invalid, start = 503 only when Redis is entirely unavailable and identical for all emails) |
| T11 | Sign-up spam / disposable domains | `signup_enabled` opt-in, allow/block domain lists, CAPTCHA on `start` when policy demands |
| T12 | Same-factor MFA theatre | §4.7 |
| T13 | Mixed-case / homograph emails | `emailaddr.Normalize` + DB CHECK; reject non-ASCII local parts / IDN domains unless explicitly enabled |
| T14 | Privilege escalation via sign-up | Only the app's default non-system role is assigned (reuse of `Register` logic); never owner/super_admin |
| T15 | Log/telemetry leakage | Never log code, `challenge_id` or full email at info level; audit stores email hash + domain |

---

## 6. Edge cases

| Case | Behaviour |
|---|---|
| Email delivered after code expired | `resend` or `start` again; copy states TTL |
| User requests several codes | Resend rotates on same challenge (old dies); new `start` supersedes. UI text: "use the newest code" |
| Wrong challenge/expired challenge | Uniform `invalid_or_expired_code`; UI restarts at email step |
| Mailbox is a forwarder / shared mailbox | Works (inbox control) — documented; domain allow-list available |
| Plus-addressing / dots | Distinct accounts (existing policy, `emailaddr` doc) |
| User has password **and** uses code | Allowed in "Both" mode; `amr` records which |
| User has TOTP + signs in by code | TOTP challenged (policy-dependent); email factor excluded |
| Account blocked/locked/deleted | Generic failure, no mail |
| Soft-deleted user's email re-registers | Treated as no user (existing partial-unique semantics); verify path creates fresh account |
| Tenant/app disabled mid-flow | Verify re-reads state; fails generic |
| Role changed mid-flow | Fresh load at verify (as magic link) |
| Multi-org user | `409 organization_selection_required` flow unchanged |
| Email provider down | `start` still 200 (async retry); delivery failure metric + alert; no oracle |
| Tenant white-label SMTP broken | Fall back to global sender (existing behaviour) |
| User changes email later | Reuse `email_change.go`: verify new address by code; notify old address; revoke sessions |
| User loses mailbox access | Tenant admin–assisted email change (audited); passkey/TOTP users recover via those; no SMS fallback in v1 |
| `challenge_id` guessed | 256-bit; useless without code |
| Clock skew / TTL | Redis TTL is authoritative |
| Double submit of `verify` | First wins; second gets uniform error |
| Integrating app is backgrounded or restarted | Challenge survives to its TTL |
| SSO-enforced email domain (SAML/OIDC) | Out of scope v1; hook point: `start` returns decoy when domain has enforced SSO |
| Bot sign-ups | CAPTCHA policy, domain lists, email budget |
| Passwordless-only app, user wants password | Not offered; document passkeys |
| Import/migration of users | Imported users without credentials can sign in by code once `email_otp_enabled` |

---

## 7. Platform integration

### 7.1 Backend
`internal/auth/passwordless.go` (service), the completion helper (§4.6),
`internal/api/handlers/passwordless.go`, routes in `routes.go` beside `/apps/login/magic`
(same `s2s.Resolve → appClientRateLimit → UserLimit/GuessLimit` chain), settings accessors
next to `SetAppMagicLink`, admin endpoints under the existing application-policy group,
`ActionAuth…` audit constants, `internal/metrics` counters.

### 7.2 No end-user screens
The auth server provides no sign-in or sign-up screens for this flow. The integrating application builds its own screens on the three API calls. The existing hosted `/oauth/authorize` login page is **not changed** and offers no email-code option in v1.

### 7.3 Admin console and management (`../emc-auth-frontend`)

Goal: an administrator can turn the feature on safely, see exactly what is in force and why,
manage individual users' sign-in methods, recover people who are locked out, and prove what
changed. Everything follows existing console conventions (react-hook-form + zod, TanStack
Query, "send only changed fields", `effective.source` shown first, one accent per surface).

**Surfaces**

| # | Where | What administrators get |
|---|---|---|
| C1 | Application → **Security** (new "Passwordless sign-in" card beside MFA / Passkey / CAPTCHA) | Master toggles: *Email codes*, *Allow sign-up with a code*, *Keep password sign-in*. Live "mode" chip (Password only / Both / Passwordless only). Sign-up domain **allow** list and **block** list (paste or CSV, validated, with an "add disposable-domain preset"). Code lifetime, max attempts, resends and cooldown, sends per hour per email, daily email budget, "remember me" allowed, welcome email on/off. Each field shows *Inherited from tenant/platform* with a per-field **Override** / **Reset to inherited**. Warnings inline (MFA conflict, template disabled, no sender). **Preview** of the email. **Send test email** to the admin's own address (never creates challenges for real accounts). |
| C2 | Tenant settings → **Authentication defaults** | Same form at tenant scope. Applications inherit unless they override. Shows how many applications override each field. |
| C3 | Platform admin → **Passwordless limits** | Platform default and **ceilings** (max daily emails per tenant, min cooldown, max TTL), server status ("available on this server: yes/no" from `PASSWORDLESS_ENABLED`), delivery-health summary across tenants. |
| C4 | Application → **Users** table | New **Sign-in methods** column (chips: Password, Email code, Passkey, Google…, MFA), new filters (*Passwordless only*, *No password*, *Unverified email*, *Never signed in*, *Created by email code*), bulk actions (*Revoke sessions*, *Send password-set email*). |
| C5 | User detail drawer → **Sign-in methods** card | Per-method rows with *added* and *last used*. Actions: **Mark email verified**, **Change email** (admin-assisted recovery, reason required, notifies old and new address, revokes sessions), **Clear code throttle** (lifts a 15-minute verify block), **Revoke sessions**, plus the existing Force password reset, Unlock, Reset MFA, Block. A **Recent activity** list shows the last 10 passwordless events for that user from the audit log. |
| C6 | User create / edit modal and **bulk import** | Password becomes optional: *"Create without password. The user signs in with an email code"* (requires email codes on) plus *Send welcome / invitation*. Import accepts rows with no password when the app allows codes; the dry-run report lists who will be passwordless. |
| C7 | Application → **Monitoring** | Passwordless panel: codes sent, verify success rate, sign-ups by code, throttled requests, send failures, median time-to-verify, top refused domains, plus a banner when failure ratio or send failures cross the alert thresholds. |
| C8 | Application → **Email templates** and **Email provider** | New template type **Sign-in code** with variables, preview and test send. Disabling it shows a blocking warning: *"Users cannot sign in with a code while this email is off."* Provider page shows sender health and whether the global fallback is being used. |
| C9 | **Audit log** | New actions with labels and tones (`actionMeta`), filter by *Sign-in method = email code*, deep link from a user drawer, export includes `auth_method`. |
| C10 | Application → **Settings history** | Timeline of policy changes with who, when, field-level before/after, and **Restore this version** (writes a new version, never rewrites history). |

**Guardrails (the part that prevents outages and lockouts)**

1. **Impact preview before saving** (`GET …/passwordless-policy/impact?proposed=…`): "This
   turns password sign-in off for 1,284 users. 1,201 already have an email code or passkey;
   83 have only a password and will sign in by code." Risky changes require a confirmation
   dialog; turning password off or sign-up on with no domain list needs the application name
   typed to confirm.
2. **No self-lockout:** the resolved policy must keep at least one first factor; the Save
   button explains why it is disabled. Enabling email codes is refused while the sign-in-code
   template is disabled or no sender resolves.
3. **Optimistic concurrency:** `version` is sent with every PUT; a conflict returns 409 and
   the form shows the other admin's change instead of overwriting it.
4. **Admin step-up is deferred.** Asking an admin for MFA again before a risky action does not exist in the platform today and is out of scope for v1. Risky changes rely on the impact preview, typed confirmation, audit and one-click revert. Admins already pass mandatory MFA at sign-in. To be revisited later.
5. **Reason + audit on every sensitive action,** with admin id, target user, before/after.
   Tenant owners are notified of policy changes through the existing admin-activity email
   (template 12).
6. **Settings export / import** as JSON, for promoting a configuration from a pilot tenant to
   production; import goes through the same impact preview.
7. **Kill switch visibility:** when the platform switch is off the cards render read-only
   with an explanatory banner instead of disappearing.

**Who can do what** (reuses existing scoped permissions: `apps:read/write` for settings,
`users:read/write` for people)

| Action | Platform admin | Tenant owner / super_admin | Application admin | Read-only / support |
|---|---|---|---|---|
| View policy, effective values, history, stats | ✔ | ✔ | ✔ (own app) | ✔ |
| Edit application policy | ✔ | ✔ | ✔ (own app, within ceilings) | ✖ |
| Edit tenant defaults | ✔ | ✔ | ✖ | ✖ |
| Edit platform defaults and ceilings | ✔ | ✖ | ✖ | ✖ |
| View a user's sign-in methods and activity | ✔ | ✔ | ✔ | ✔ |
| Mark verified, clear throttle, revoke sessions | ✔ | ✔ | ✔ | ✖ |
| Change email, enable sign-up, switch an application to passwordless only | ✔ | ✔ | tenant decides (setting) | ✖ |
| Export / import settings | ✔ | ✔ | ✖ | ✖ |

**Admin API** (same shape as the captcha / lockout / passkey policy routes; `source` and
`effective` in every GET)

```
GET|PUT|DELETE  /tenants/:tid/passwordless-policy
GET|PUT|DELETE  /tenants/:tid/applications/:appID/passwordless-policy
GET|PUT         /platform/passwordless-policy                       (defaults + ceilings)
POST            …/passwordless-policy/impact                        (dry run, no write)
POST            …/passwordless-policy/test-send                     (to the caller's own address)
GET             …/passwordless-policy/history      POST …/history/:id/restore
GET             …/passwordless/stats?window=24h|7d|30d
GET             /tenants/:tid/users/:uid/auth-methods
POST            /tenants/:tid/users/:uid/verify-email
POST            /tenants/:tid/users/:uid/clear-passwordless-throttle
PUT             /tenants/:tid/users/:uid/email                      (admin-assisted change, reason required)
```

Every route also exists under `/applications/:appID/users/:uid/…` for application-scoped
administrators, like the existing user routes.

**Frontend work map** (conventions from the console's CLAUDE.md): `types/passwordless-policy.ts`,
`lib/api/passwordless-policy.ts`, `queries/passwordless-policy.ts`;
`components/applications/PasswordlessPolicyForm.tsx` (changed-fields-only PUT, per-field
inheritance), `PasswordlessImpactDialog`, `PasswordlessHistoryPanel`, `UserAuthMethodsCard`,
`SignInMethodChips`; edits to `ApplicationSecurityPage`, `TenantSettingsPage`,
`UserTable` / `UserDetailDrawer` / `UserFormModal` / `UserImportModal`,
`ApplicationMonitoringPage`, email-template page, `lib/audit/actionMeta.ts`,
`api-contract/audit-actions.json` and a new `api-contract/flows/passwordless.md`;
docs page `src/docs/content/passwordless.mdx`. Frontend needs its own plan file in `.plans/`,
vitest + MSW tests (80% coverage gate), accessibility pass, and a PR to `dev` under the
frontend's branch and commit conventions.

### 7.4 Observability & audit
Audit: `auth.passwordless_started`, `_resent`, `_verified`, `_failed`, `_throttled`,
`user.created_passwordless`, `auth.preverification_neutralized`. Context fields reuse the
enrichment pipeline (UA/geo/risk, `auth_method="email_otp"`). Metrics:
`emc_auth_passwordless_{start,verify,created}_total{result}`, `…_email_send_failures_total`,
`…_throttled_total{scope}`. Prometheus alert: verify failure ratio spike; send failure rate.

### 7.5 Docs & contracts
Regenerate swagger; update Postman collection(s); new `docs/PASSWORDLESS_INTEGRATION.md`
(backend-proxy pattern, error table); CHANGELOG entry;
SECURITY.md residual-risk note (T5/T6).

---

## 8. Phasing

| Phase | Deliverable | Est. |
|---|---|---|
| **0 — Compatibility harness** | Characterisation tests pinning current password login, magic link, register, reset, MFA, org selection, social login and hosted login; parity-test scaffold; `mfaGate` options wrapper with zero value = today. **Tests and an additive wrapper only; no behaviour change** | 2–3 d |
| **1 — Core OTP (API)** | Migration `00105`; challenge store + Lua verify; `start/resend/verify`; sign-up + pre-hijack safeguards; template 14; limiters, audit, metrics; config & kill-switch | 6–8 d |
| **2a — Admin API** | Scoped policy endpoints (platform / tenant / app) with inheritance and ceilings, impact preview, test-send, history + restore, stats, per-user auth-methods / verify-email / change-email / clear-throttle; `password_enabled` enforcement on register/login/reset; domain lists; CAPTCHA wiring; audit actions | 5–6 d |
| **2b — Console** | C1–C10 in §7.3 (policy card, tenant defaults, platform limits, user table and drawer, create/import, monitoring, templates, audit, history); frontend plan file, tests, docs | 7–9 d |
| **3 — Lifecycle (optional)** | Email-change integration; passkey-enrolment nudge after code login; set-password only if product asks for it in *both* mode. **No change to reset, to email-MFA hashing, or to stored passwords** | 4–5 d |
| **4 — Optional** | Code+link hybrid with browser binding (also fixes G7); SSO-domain enforcement; SMS channel; adaptive step-up from risk score | later |

Each phase ships behind `PASSWORDLESS_ENABLED=false`; Phase 0 adds tests and an additive wrapper
only, and is mergeable alone.

### Test plan
- **Unit**: code generation/HMAC, Lua script (attempts, atomic consume), domain policy,
  decoy parity, email normalisation.
- **Integration** (`emc_auth_test`, `go test -p 1`): signup→login→refresh; both-mode user;
  passwordless-only app rejects password endpoints; MFA required + TOTP; org selection;
  blocked/locked/deleted users; pre-hijack neutralisation; cross-app replay; concurrent
  verify (create race, double redeem).
- **Security**: enumeration-parity test (status, body, headers, latency distribution for
  known/unknown/blocked/domain-rejected); throttle-by-email independent of existence; fuzz
  `email`/`code`; timing test using `LoginTimingBudget`.
- **Failure injection**: Redis down, SMTP down, white-label SMTP down.
- **Regression**: full existing auth suite unchanged (password, magic link, MFA, social).
- **Mode switching** (§4.11): password hashes byte-identical after switching to passwordless only and back; password login refused before any lookup and not counted toward lockout; existing sessions and refresh keep working; an in-progress OTP session completes within its lifetime; reset links issued earlier stop working; register closed; invitation leads to code sign-in; password login works again after switching back; switch to password only blocked while users without a password exist; concurrent policy edits return 409.

---

## 9. Rollout & compatibility

- Additive migration only; default row-less ⇒ identical behaviour.
- Global kill-switch default off; per-app opt-in; staged: internal app → pilot tenant → GA.
- Down-migration drops the table; no data in `users` changes.
- No token-contract break: new `grant`/`amr` values only (document for relying parties that
  validate `amr`/`grant` allow-lists).
- Rollback: first set `signup_enabled=false` and keep code sign-in on for existing users. Flipping `PASSWORDLESS_ENABLED=false` locks out users who have no password until it is turned back on (§4.11). No password is ever touched.

---

## 10. Out of scope (v1)

SMS/voice OTP, push/authenticator-app passwordless, passkey-only registration (separate
`WEBAUTHN_MASTER_PLAN.md` track), console/administrator passwordless, SSO-domain enforcement,
cross-application single account.

## 11. Decisions and defaults

**Nothing is open.** Each item below was either decided by product direction or takes the industry-standard default. A reviewer can change any of them.

**Decided by product direction (2026-11-12)**
- Forgot-password is closed in passwordless-only apps and untouched elsewhere.
- Email goes through the existing SMTP sender. No SendGrid work, no new queue, no SMS in v1.
- Stored passwords are never deleted. Moving an app to passwordless only closes the password check, not the password.
- Mode changes made while an app is live follow §4.11.
- Admin step-up (asking an admin for MFA again) is deferred.
- The auth server provides no end-user screens for this flow. Integrating apps build their own (§7.2).

**Defaults adopted**

| Topic | Default |
|---|---|
| Sign-up by code | Off until an owner turns it on |
| Code lifetime | 5 minutes, configurable 5–15 |
| Wrong attempts | 5 per code |
| Pre-hijack case | Keep the password, revoke sessions, notify the owner |
| Who can turn on sign-up or switch an app to passwordless only | Tenant owners. Application admins cannot |
| Invited users who have not accepted | May sign in by code, which counts as accepting |
| Magic link and its known gaps | Left exactly as they are |
| Domains that must use SSO | Ignored in v1 |
| Non-English email addresses | Rejected |
| Assurance | Documented as single factor, not NIST AAL2 |

---

## 12. Delivery strategy — one release at a time

**Recommendation: ship in three releases, in order, never as one deploy. None of them changes
anything for an existing application until an administrator opts that application in.**

| Release | Contents | Changes live behaviour? | Gate before the next | Rollback |
|---|---|---|---|---|
| **R1** | Phase 0 (test harness) + Phase 1 + Phase 2a (core OTP API, migration `00105`, admin API, enforcement hooks) | **No.** Tests and an additive wrapper, then new code shipped dark: `PASSWORDLESS_ENABLED=false`, routes answer 404 | Characterisation suite green and unchanged; enable in staging, then one internal application; enumeration-parity, parity and timing tests pass | Flag off. Migration is additive and can stay |
| **R2** | Phase 2b: admin console (frontend repo) | **No** for existing apps. The console only shows the feature where it is on | Pilot tenant for 1–2 weeks with alerts armed and the readiness checklist (§14) signed off | Policy off per application, then flag off; console cards hide themselves |
| **R3** | Phase 3 (optional): email-change integration, passkey nudge, set-password only if requested | No change to existing flows | Existing suites unchanged | Revert the release |

General availability follows R2's pilot and the §14 sign-off. R3 ships after that.

**Why not everything in one go**
- A 25–32 day diff cannot be reviewed well, and one regression cannot be bisected away from the
  rest, even though live login code is not being rewritten.
- The backend and the console are separate releases: the console lives in another repository with its own branch rules and tests.
- The console lives in a separate repository with its own branch rules, plan file, tests and
  `dev` branch cadence. It cannot deploy atomically with the backend anyway.
- Any approval is dismissed by later pushes (project convention), so very large PRs keep being
  re-reviewed from scratch.

**Why not finer than three**
- Phase 1 alone has no safe way to be enabled (no policy to turn it on or impact-preview it), so
  it ships with 2a.
- Phase 2a alone has nothing to administer. Together they are one coherent, dark release.

If a single deploy is unavoidable, the minimum acceptable shape is: R1 already in production
with the characterisation suite green, then R2 and R3 as stacked PRs deployed together with the
global flag off and the console cards hidden until the flag is turned on. Elapsed time for the
staged path is roughly 5–6 calendar weeks for about 24–31 working days of work.

---

## 13. Impact on functionality that is live today

Legend: **High** = could affect existing users if wrong · **Med** = visible change for some
integrators · **Low** = additive.

| # | Existing feature | Phase | Effect | Risk | What we do |
|---|---|---|---|---|---|
| I1 | Password login (`/login`, `/apps/login`, hosted `/oauth/authorize/login`) | none | **Not edited.** The new flow has its own code path | None | Characterisation tests pin it and run on every PR |
| I2 | Magic link | none | **Not edited**, including its known gaps G1 and G2 | None | Pinned by existing and new tests. Any fix is an opt-in follow-up |
| I3 | Email MFA after a magic-link sign-in | none | **Not edited** | None | Pinned by tests |
| I4 | TOTP, backup codes, forced enrollment, admin MFA | R1 | `mfaGate` becomes a thin wrapper over an options variant; zero value = today's behaviour; both callers unchanged. Administrator path (`appRowID == 0`) untouched | Low | Existing MFA suites pass unchanged |
| I5 | Registration (`/register`, `/apps/register`) | R1 | `Register` **not edited**. The new path has its own user-creation helper. With `password_enabled=false`, an application that chose *passwordless only* gets `password_auth_disabled` | Low | Applies only to an application that opts in; integrators notified first |
| I6 | Hosted login page and SSO session (`oauth_authorize.go`, `login.html`) | none | **Not edited.** It offers no code option in v1 | None | Out of scope: integrating apps build their own screens |
| I7 | Tokens, introspection, relying parties | R1 | New `gty` value `email_otp` and `amr` value `email_otp`. Relying parties with strict allow-lists of `gty` or `amr` would reject the tokens. The grant must be added to `HumanGrants` | Med | Documented in the integration guide; opt-in per application |
| I8 | Organizations (`organization_mint.go`) | R1 | Selection resume maps the stored grant through an allow-list. Without a new `case GrantEmailOTP` it returns `ErrOrganizationSelectionInvalid`, so users in multi-org apps could not finish a code sign-in | **High** if missed | Add the case with a test (this is a must-fix in Phase 1) |
| I9 | Rate limits (`appClientRateLimit`, `UserLimit`) | R1 | `start` shares the per-application quota with login. A mail-bomb on `start` could exhaust the quota and block real logins | **High** | Separate bucket for passwordless, or exempt it from the shared quota; new `RATE_LIMIT_APP_USER_PASSWORDLESS_*` variables (0 = built-in default, like the others) |
| I10 | Lockout and CAPTCHA | R1 | Code failures do **not** count toward password lockout, by design. CAPTCHA reused on `start` only | Low | Documented; separate failure counters |
| I11 | Email system | R1 | New template type appears in `AllTemplateTypes`, so it is listed for every tenant and application and may break tests that count 13 types. Added volume shares the global sender with verification, reset and MFA mail, so a code flood can delay them | Med | Update template tests; separate daily budget and send priority for transactional mail; DKIM/SPF checked for the sending domain |
| I12 | Social login and SAML users | R1 | These users have no credential row. When email codes are on, anyone with the inbox can sign in to an account created through Google or SAML. Applications that rely on "social only" or a restricted domain gain a second path | **Med** | Console warns when an application has social or SAML configured and codes are on; sign-up domain allow-list; policy opt-in |
| I13 | Invited, not-yet-accepted users | R1 | Invited app users are active and credential-less until they accept, so a code sign-in would skip the acceptance step | Med | Default: the code sign-in counts as accepting the invitation (§11) |
| I14 | Forgot-password / reset | R1 | **Not edited.** Closed only for applications that chose *passwordless only*. In other modes it behaves as today, including the 0-row case for users with no password (G5, recorded, not fixed) | Low | Pinned by tests; `password_auth_disabled` for opted-in apps only |
| I15 | Console users table, drawer, CSV export | R2 | New column and filters. A per-row sign-in-methods lookup would be an N+1 on large tenants | Med | One aggregated query (the existing `EXISTS (…user_credentials…)` pattern); new CSV columns appended at the end or behind an option |
| I16 | Audit log and the frontend audit contract | R1, R2 | New actions. `api-contract/audit-actions.json` and `actionMeta` must list them or the console shows raw strings | Low | Update both in the same release; SIEM export consumers informed |
| I17 | Redis | R1 | New `pwless:*` keys (no prefix collision with `otp:`, `mfa:`, `magic:`). More load; if Redis is down only passwordless degrades | Low | Capacity check; fail closed |
| I18 | Database | R1 | Migration `00105` creates two new tables only. No change to `users`, `user_credentials` or any hot table | Low | Additive; down-migration drops them |
| I19 | Sessions, refresh, device list | R1 | Unchanged logic. Sessions list will show the new `amr` value | Low | UI label |
| I20 | API docs, Swagger, Postman | all | Additive | Low | Regenerate |

**Not affected:** client-credentials and S2S tokens, API keys, refresh rotation and replay
detection, JWKS and signing keys, SAML assertion handling, organization membership rules, RBAC
permission resolution, passkey enrollment and login, TOTP enrollment, administrator MFA, session
reaper, and the schema of every existing table.

**Feature-flag layers** (each is an independent off switch): global `PASSWORDLESS_ENABLED` →
per-tenant default → per-application override → per-method (`email_otp_enabled`,
`signup_enabled`, `password_enabled`). Nothing reaches an end user until an administrator turns
on an application's policy.

---

## 14. Production readiness checklist (gate for general availability)

Nothing here exists yet. R2's pilot cannot become general availability until each line is done and
signed off.

| # | Area | Requirement | Phase |
|---|---|---|---|
| P1 | Email deliverability | Existing SMTP sender stays. SPF, DKIM and DMARC aligned on the sending domain. Bounce handling and a suppression list are added only if the provider changes later (the swap stays env-only). Inbox-placement test on Gmail, Outlook and Yahoo. Delivery target: p95 under 30 s | 1, pilot |
| P2 | Sending approach | Existing mailer. Asynchronous in-process send with bounded retry and backoff; idempotent per challenge and code version; queue-depth metric. A restart can lose a pending email and the user can resend. A durable outbox is deferred and revisited if loss shows up in metrics | 1 |
| P3 | Independent security review | External penetration test of start, resend and verify; internal threat-model review; `govulncheck` and dependency scan; fuzzing of email and code inputs | before GA |
| P4 | Load and soak | Targets set from current login traffic times three. Cases: Redis failover, SMTP slow (10 s) with no latency leak, throttle storms, sign-up bursts | before GA |
| P5 | Service targets and alerts | Start availability 99.9%; server-side verify p95 under 300 ms; alert when verify failure ratio exceeds 40% for 10 minutes, send failures exceed 5%, throttles spike, or challenge-store errors appear | 1, pilot |
| P6 | Runbooks | Mail-bomb response (lower budget, block domain or IP); mail-provider outage; suspected code interception; mass pre-hijack neutralisation; kill-switch use; HMAC key rotation with two keys active during the switch | before GA |
| P7 | Account recovery and support | Lost-mailbox procedure: tenant-admin identity check, reason recorded, optional 24–72 h cooling-off with notice to the old address, full audit; support playbook; user-facing help text | 2a, 2b |
| P8 | Data handling | Challenges live in Redis with TTL only; code and challenge id never logged; audit stores email hash and domain; retention follows `AUDIT_RETENTION_DAYS`; privacy export and delete include passwordless events; processing agreement with the email provider | 1 |
| P9 | Accessibility and language | WCAG 2.2 AA for the console; plain-text alternative and localised copy for the email | 2b |
| P10 | Email rendering | Rendering check in major email clients (Gmail, Outlook, Apple Mail) | 1 |
| P11 | Key management | `PASSWORDLESS_CODE_HMAC_KEY` stored like the TOTP key; two-key rotation supported | 1 |
| P12 | Availability assumptions | Redis HA behaviour and failover documented; single-region limits stated | 1 |
| P13 | Release controls | Characterisation suite green on every PR; canary then per-application staged enablement; rollback rehearsed in staging | all |
| P14 | Documentation | Integration guide, admin guide, support guide, changelog entry, residual-risk note in `SECURITY.md` | 2b |
| P15 | Compliance | New audit events mapped to existing control evidence; assurance disclaimer for regulated tenants (§15) | before GA |

---

## 15. Standards and assurance position

| Standard or practice | Position of this design |
|---|---|
| NIST SP 800-63B | Email is not a permitted channel for out-of-band authentication, so an email code **cannot be claimed as AAL2**. It is treated as a single factor (proof of inbox control). Higher assurance comes from TOTP or a passkey layered on top. Confirm exact clauses against the current standard text before quoting |
| OWASP ASVS and Authentication Cheat Sheet | Generic responses, rate limiting, attempt limits, single-use short-lived codes, no code in logs: all met |
| OpenID Connect `amr` | No registered value for an emailed code. This plan uses a custom `email_otp` (same precedent as `link`); relying parties must tolerate unknown values |
| Phishing resistance | Email codes can be relayed in real time. Passkeys are the phishing-resistant option; the plan nudges users toward them after a code sign-in |
| Industry practice | Code lifetimes of roughly 3–10 minutes, 6 digits, attempt-capped, unified start and verify. The plan sits inside that range. The default is 5 minutes |
