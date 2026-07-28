# Account Lockout — Implementation & Integration Guide

> **Issue:** [#72](https://github.com/Engineersmind/emc-auth-server/issues/72) — *feat(be): Account lockout after repeated failed login attempts*
> **Branch:** `feat/issue-72-account-lockout` (off `origin/master`@`554b099`)
> **Tracked in:** `PRODUCTION_READINESS.md` → **H5** (left OPEN — see [§12](#12-what-this-does-not-cover))

This document is the single reference for what was built, why each decision was
made, how the flow executes step by step, how consuming applications are
affected, and what operators and integrators have to do.

---

## Table of contents

1. [The problem and the threat model](#1-the-problem-and-the-threat-model)
2. [Design decisions — including three deliberate deviations from the issue](#2-design-decisions)
3. [Architecture](#3-architecture)
4. [The login flow, step by step](#4-the-login-flow-step-by-step)
5. [The Redis counter in detail](#5-the-redis-counter-in-detail)
6. [Database schema](#6-database-schema)
7. [Configuration reference](#7-configuration-reference)
8. [Admin API — the unlock endpoint](#8-admin-api--the-unlock-endpoint)
9. [Observability — audit events and metrics](#9-observability)
10. [Impact on consuming applications](#10-impact-on-consuming-applications)
11. [Operational runbook](#11-operational-runbook)
12. [What this does NOT cover](#12-what-this-does-not-cover)
13. [Failure modes](#13-failure-modes)
14. [Every file changed](#14-every-file-changed)
15. [Testing](#15-testing)
16. [Rollback](#16-rollback)

---

## 1. The problem and the threat model

Before this change, the **only** brute-force defense on `POST /auth/login` was
the AUTH-07 rate limiter: 5 attempts/min per IP, 10/min per submitted email,
held in per-process memory.

That leaves two gaps:

| Gap | Consequence |
|---|---|
| **Distributed attack** — many IPs, one account | Each IP stays under its own 5/min budget. The per-email limiter (10/min) is the only brake, and it resets every minute — so an attacker gets ~14,400 guesses/day against one account, forever, with no escalation. |
| **In-memory counters** | Every restart/deploy resets them to zero, and with N replicas the effective limit is N× the configured value. |

Account lockout addresses the first gap: it counts failures **per account** and
escalates, so guessing does not remain cheap no matter how widely the source is
spread. It is a *second, independent layer* — the rate limiter is not replaced.

```
             ┌─────────────────────────────────────────────┐
Request  ──▶ │ LoginRateLimiter  (per IP, per email/min)   │──▶ 429 + Retry-After
             │   throttles VOLUME from one source          │
             └──────────────────┬──────────────────────────┘
                                ▼
             ┌─────────────────────────────────────────────┐
             │ Account lockout   (per email, escalating)   │──▶ 401 (generic)
             │   refuses ATTEMPTS against one account      │
             └──────────────────┬──────────────────────────┘
                                ▼
                          password check
```

**Not in the threat model:** *credential stuffing* — one guess each against
thousands of different accounts. A per-account counter never trips. That needs a
global/per-IP limiter, which is `PRODUCTION_READINESS.md` **B1**.

---

## 2. Design decisions

### 2.1 Three deliberate deviations from the issue text

The issue as written contained one technical impossibility and two security
regressions. Each was implemented differently, on purpose.

#### Deviation 1 — the counter key is NOT tenant-scoped

*Issue says:* `login:fail:{tenant_id}:{email_hash}`

**Why that cannot work:** `LoginInput` is `{ClientID, ClientSecret, Email,
Password}` — there is no tenant. Without app credentials, `Login` discovers the
tenant by fetching every active account with that email across all tenants and
finding which one's stored hash the password matches. So on a **failed** login
there is no tenant yet. A tenant-scoped failure counter could only ever be
written *after* a successful password check — precisely when a brute-force
counter is useless.

**What was built:** `login:fail:{sha256(lowercase(trim(email)))}` — keyed on the
email alone. Hashed so a Redis dump or `MONITOR` session is not a list of who is
being attacked; lower-cased so flipping capitalisation cannot mint a fresh budget.

**Accepted consequence:** when one address owns accounts in several tenants (or
both a tenant-level and an app-scoped account), they share one counter — an
attack on one temporarily locks the others. Bounded deliberately: locks expire on
their own, revoke nothing, and never touch `is_active`.

#### Deviation 2 — the hard lock is temporary, and never touches `is_active`

*Issue says:* at 10 failures, `is_active = false`; requires an admin to unlock.

**Why that is a self-inflicted DoS:** anyone who knows a victim's email address
could permanently disable that account with ten unauthenticated HTTP requests,
recoverable only by a human. That is account-takeover-of-availability handed to
an anonymous attacker. It also conflates two different states: an operator could
no longer distinguish *"I disabled this user"* from *"the brute-force guard
fired."*

**What was built:** a dedicated `users.locked_until TIMESTAMPTZ` column that
**auto-expires** (default 60 min). Self-healing, so no admin toil in the common
case, while an admin can still lift it early. `is_active` remains purely
administrative. This is also what Auth0/Okta do.

**Why a column rather than just a longer Redis TTL:** the lock must survive a
Redis flush (a Redis-only lock silently evaporates on restart — a free reset for
the attacker), and the admin UI needs SQL-visible state to render its badge and
list locked accounts.

#### Deviation 3 — no `Retry-After` header on the lock path

*Issue says:* both *"never reveal whether account is locked"* **and** *"send
`Retry-After` when soft-locked."* These contradict each other — a header that
appears only when locked **is** the reveal.

**What was built:** every invalid-credential response is byte-identical — `401`,
`{"error":"invalid credentials"}`, no extra header — regardless of whether the
cause was an unknown address, a wrong password, or a lock in force. The existing
per-IP/per-email limiter still owns `Retry-After` on its `429`; that is a
different path and is unaffected.

### 2.2 Other decisions worth knowing

| Decision | Rationale |
|---|---|
| **Neither tier revokes sessions or bumps `token_version`** | Failed attempts do not compromise sessions already established. Killing them would hand the same attacker a way to force-log a victim out of every device at will. Administrative blocking (`SetUserActive`) remains the tool that terminates sessions. |
| **Fails OPEN when Redis is unreachable** | Failing closed would turn a cache outage into a **total authentication outage**. The per-IP limiter still provides a floor. Logged at WARN. (Note this is the opposite of the OTP path, which fails closed — there the blast radius is one user, not everyone.) |
| **The lock check runs AFTER the bcrypt comparison** | Returning early would make a locked account measurably faster to probe than a wrong password — a timing oracle. Every refusal pays the same `loginCompareFloor` (5) bcrypt comparisons. |
| **The counter clears on a correct password, BEFORE the MFA gate** | Once the password is right, the password-brute-force window is over. MFA enforces its own budget (`bumpOTPAttempts`); leaving this counter armed would let a user who fumbles an OTP code get *password*-locked. |
| **Unknown emails are counted too** | Skipping them would make "no such account" cheaper in Redis round-trips than "wrong password", and would let an attacker enumerate addresses by probing which ones can be locked. |
| **`matchCount > 1` is NOT counted as a failure** | That means the submitted password was *correct* for 2+ of the email's tenant accounts — a tenant misconfiguration, not a guess. Counting it would let a legitimate user lock themselves out by retrying. |
| **Tiers fire on the exact crossing (`==`), not `>=`** | One audit row and one metric increment per lockout, rather than one per subsequent attempt. Attempts arriving while a lock is already in force are recorded separately as `auth.login_blocked_account_locked`. |
| **Thresholds are global env vars, not per-tenant** | No per-tenant settings store exists (the only precedent is per-*application*, `application_mfa_settings`). Shipped global; the struct is shaped so a per-app override can layer on later. |

---

## 3. Architecture

```
POST /api/v1/auth/login                 POST /api/v1/auth/apps/login
        │                                        │
        └──────────────┬─────────────────────────┘
                       ▼
        handlers.Login / handlers.AppLogin      ← NO changes needed here.
                       │                          Both already map the error
                       ▼                          "invalid credentials" → 401,
        auth.AuthService.Login                    so lock refusals are
        (internal/auth/service.go)                automatically indistinguishable.
                       │
        ┌──────────────┼───────────────────────┐
        ▼              ▼                       ▼
   Redis counter   PostgreSQL              audit.Logger
   login:fail:…    users.locked_until       (async, fire-and-forget)
   (soft tier)     (hard tier)
                       │
                       ▼
        POST /api/v1/users/{id}/unlock  →  admin.Service.UnlockUser
                                              ├─ clears locked_until (SQL)
                                              └─ clears the counter via
                                                 LoginFailureResetter
                                                 (implemented by AuthService)
```

**Why `LoginFailureResetter` is an interface:** the admin service must clear the
Redis counter on unlock (clearing only the column would leave the soft lock
standing, and the unlock button would look broken). Rather than give
`admin.Service` a Redis client and duplicate the key format — two packages
owning one key layout — it depends on a one-method interface that
`*auth.AuthService` satisfies. Key-format ownership stays in `internal/auth`.

---

## 4. The login flow, step by step

Exact execution order in `AuthService.Login`
([internal/auth/service.go](../internal/auth/service.go)). Steps **2, 4, 7a, 9,
10** are new.

```
 1. If ClientSecret present → authenticateApp()
    Bad app credentials fail fast with ErrInvalidClient, before any user data
    is touched, identically regardless of the submitted email.

 2. ▸ NEW: read the failure counter
    fails, failsKnown := loginFailureCount(email)
    softLocked = failsKnown && SoftThreshold > 0 && fails >= SoftThreshold
    failsKnown is false on any Redis error → gate skipped (fail open).

 3. Candidate query — every active, non-deleted user with this email in an
    active tenant. Scoped to the authenticated app's users, or to tenant-level
    users (application_id IS NULL) for a generic login.
    ▸ NEW: also selects u.locked_until.

 4. ▸ NEW: if softLocked
       padCompares(0)                  ← 5 dummy bcrypt compares (timing parity)
       auditLoginBlocked("soft")       ← audit + metric
       recordLoginFailure(candidates)  ← counter STILL advances, so a sustained
                                         attack escalates to the hard tier
       return ErrInvalidCredentials
    The real password is never compared — the expensive work is skipped while
    the dummy floor keeps the response time indistinguishable.

 5. If no candidates (unknown email)
       padCompares(0)
       ▸ NEW: recordLoginFailure(nil)  ← counted; nothing to hard-lock
       return ErrInvalidCredentials

 6. bcrypt-compare the password against every candidate; count matches.
    Then padCompares(len(candidates)) to reach the floor of 5.

 7. If matchCount == 0 (wrong password)
       ▸ NEW: recordLoginFailure(candidates)   ← 7a
       return ErrInvalidCredentials

 8. If matchCount > 1 → return ErrInvalidCredentials.
    NOT counted: the password was correct for 2+ tenant accounts.

 9. ▸ NEW: if matched.locked_until > now()   (the HARD tier)
       auditLoginBlocked("hard")
       return ErrInvalidCredentials
    Enforced here, after the compare, both for timing parity and because this
    tier outlives the Redis window. A correct password does NOT clear the
    counter while a lock stands.

10. ▸ NEW: clearLoginFailures(email)
    Correct password, no lock → the window is over. Before the MFA gate.

11. mfaGate → may return an OTP or forced-enrollment challenge instead of tokens.
12. issueTokenPair → access + refresh token.
```

### `recordLoginFailure` — the escalation logic

```
count, ttlMS := loginFailBump(key, window, softThreshold)   ← atomic Lua

switch {
case HardThreshold > 0 && count == HardThreshold:
        metrics.AccountLockouts{tier="hard"}++
        hardLockAccounts(...)          → UPDATE users SET locked_until = …
                                       → audit auth.account_hard_locked
case count == SoftThreshold:
        metrics.AccountLockouts{tier="soft"}++
        audit auth.account_soft_locked
}
```

Everything here is best-effort: a Redis or database failure is logged and
swallowed, never converting a plain failed login into a `500`.

`hardLockAccounts` locks **every** candidate account owning the email:

```sql
UPDATE users
SET locked_until  = GREATEST(COALESCE(locked_until, $1), $1),
    locked_reason = 'brute_force',
    updated_at    = NOW()
WHERE id = ANY($3) AND deleted_at IS NULL
```

`GREATEST` means a second burst landing during an existing lock can only
**extend** it, never shorten one an admin has not cleared.

---

## 5. The Redis counter in detail

**Key:** `login:fail:<sha256 hex of lowercase, trimmed email>`
**Value:** integer count of consecutive failures
**TTL:** `AUTH_LOGIN_FAILURE_WINDOW_MINUTES` (default 15)

Increment and TTL are one atomic Lua script — a plain `INCR` then `EXPIRE` can
leave a **TTL-less key** if the process dies between them, which would lock the
account forever:

```lua
local n   = redis.call("INCR",  KEYS[1])
local ttl = redis.call("PTTL",  KEYS[1])
if n <= tonumber(ARGV[2]) or ttl < 0 then     -- ARGV[2] = soft threshold
    redis.call("PEXPIRE", KEYS[1], ARGV[1])   -- ARGV[1] = window in ms
    ttl = tonumber(ARGV[1])
end
return {n, ttl}
```

Two subtleties encoded there:

- **The window slides only up to the soft threshold.** Below it, the window means
  "N failures within N minutes *of each other*". At or above it, the TTL stops
  being refreshed — otherwise an attacker who keeps hammering an already-locked
  account would extend the lock indefinitely and hold the victim out for as long
  as they cared to keep sending requests.
- **`ttl < 0` re-arms an expiry-less key** — defensive against the crash window
  described above.

**Lifecycle**

| Trigger | Effect |
|---|---|
| Failed login | `INCR`, TTL armed/refreshed per above |
| Correct password (no lock in force) | `DEL` — window reset |
| Admin unlock | `DEL` via `ResetLoginFailures` |
| Window elapses | Key expires; soft lock self-heals |

---

## 6. Database schema

`migrations/00061_user_lockout.sql`:

```sql
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS locked_until  TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS locked_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_users_locked_until
    ON users (locked_until)
    WHERE locked_until IS NOT NULL;
```

- `locked_until` — `NULL` or in the past means *not locked*.
- `locked_reason` — short machine tag (`brute_force`), so the admin UI can
  explain the badge without querying `audit_logs`.
- **Partial index** — only currently-locked rows are indexed, so it stays tiny
  no matter how large `users` grows. It serves the admin "locked accounts"
  listing; the login path finds the row by email and reads the column directly.

**Migration is automatic.** The server runs Goose on boot, so deploying the
binary applies it. Nothing manual. Verify with `"migration applied"` /
`"no pending migrations"` in the startup log.

Additive and nullable ⇒ **backward compatible**. An older binary against the new
schema simply ignores the columns.

---

## 7. Configuration reference

All six are plain env vars with production-safe defaults. **Lockout is on by
default** once the binary ships.

| Variable | Default | Meaning |
|---|---|---|
| `AUTH_LOGIN_SOFT_LOCK_THRESHOLD` | `5` | Failures before attempts are refused for the rest of the window, *including one with the correct password*. No DB write. **`0` disables lockout entirely.** |
| `AUTH_LOGIN_HARD_LOCK_THRESHOLD` | `10` | Failures at which `users.locked_until` is stamped. `0` disables the hard tier, leaving soft locks only. |
| `AUTH_LOGIN_FAILURE_WINDOW_MINUTES` | `15` | Counter TTL and soft-lock duration. |
| `AUTH_LOGIN_HARD_LOCK_MINUTES` | `60` | How long a hard lock holds before expiring on its own. |
| `AUTH_LOGIN_RATE_LIMIT_PER_IP` | `5` | AUTH-07 per-IP login budget/min. Newly configurable (was hardcoded). |
| `AUTH_LOGIN_RATE_LIMIT_PER_ACCOUNT` | `10` | AUTH-07 per-email login budget/min. Newly configurable. |

### Validation and clamping

`NewLockoutConfig` refuses to trust its input, because a misconfigured threshold
is a security or availability incident:

- Negative thresholds → `0` (disabled) rather than inverted logic.
- `hard < soft` → raised to `soft`. A hard tier that tripped first would make the
  soft tier unreachable.
- Non-positive durations → defaults (15 min / 60 min), so a typo cannot produce a
  zero-length or eternal lock.
- Unparseable env values → the documented default, via `atoiOr`. (Note
  `config.mustAtoi` returns `0` on error — deliberately **not** used here, since
  `0` means "disabled"/"instant" for these fields and a typo would otherwise
  silently mean *reject every login*.)

### ⚠️ The rate limiter interacts with the thresholds

At the default `PER_IP = 5` and `SOFT_LOCK_THRESHOLD = 5`, a **single-IP**
attacker receives a `429` from the limiter at the exact point the lockout would
engage, and the hard tier (10) is unreachable within a minute.

That is **correct in production** — both defenses hold, and the lockout earns its
keep against *distributed* attacks where the per-IP limiter never trips.

But it means **you cannot exercise the lockout tiers end-to-end from one machine**
without raising `PER_IP` above the hard threshold. See
[`scripts/LOCKOUT_TESTING.md`](../scripts/LOCKOUT_TESTING.md). Raising it in
production disables per-IP brute-force throttling — never leave a test value in
place.

### Docker

`docker-compose.yml` exposes all six with production defaults, interpolated from
`.env`:

```yaml
AUTH_LOGIN_SOFT_LOCK_THRESHOLD: "${AUTH_LOGIN_SOFT_LOCK_THRESHOLD:-5}"
# … etc
```

That service uses an explicit `environment:` block rather than `env_file`, so a
variable **only** reaches the container if compose interpolates it — adding it to
`.env` alone is not enough.

---

## 8. Admin API — the unlock endpoint

```
POST /api/v1/users/{id}/unlock
Authorization: Bearer <access token>
```

**Permission:** `users:write` **or** `admin:access` (identical to
`PUT /users/{id}/status`).

**Success — `200`,** the refreshed user:

```json
{
  "id": "1071",
  "tenant_id": "510",
  "email": "user@example.com",
  "is_active": true,
  "locked_until": null,
  "connections": ["password"]
}
```

| Code | When |
|---|---|
| `200` | Unlocked, or was already unlocked (**idempotent**) |
| `401` / `403` | No token / insufficient permission / cross-tenant attempt |
| `400` | Non-numeric `{id}` |
| `404` | No such user in the caller's tenant |

**What it does:** clears `locked_until` + `locked_reason`, then clears the Redis
failure counter. Both halves are required — the counter alone *is* the soft lock,
so clearing only the column would leave the user refused for the rest of the
window and the button would appear broken. A Redis failure is logged but does not
fail an unlock that already succeeded in the database.

**What it deliberately does NOT do:** touch `is_active`. An account can be
simultaneously brute-force locked *and* administratively blocked; lifting the
lock must not silently reinstate someone an admin disabled. Use
`PUT /users/{id}/status` for that.

**No self-unlock guard** (unlike `SetUserStatus`, which blocks self-disabling):
unlocking only ever *restores* access, so an admin acting on their own account is
harmless.

### Reading lock state

`locked_until` is now on every `UserResult` — `GET /api/v1/users`,
`GET /api/v1/users/{id}`, and the unlock response.

**The server nulls it out once the lock has elapsed:**

```sql
CASE WHEN u.locked_until > NOW() THEN u.locked_until END AS locked_until
```

So **non-`null` always means "locked right now"** — clients never do clock
arithmetic, and never show a stale badge for an expired lock.

---

## 9. Observability

### Audit events

| Action | When | Notes |
|---|---|---|
| `auth.account_soft_locked` | Counter crosses the soft threshold | Once per crossing. Metadata: `failed_attempts`, `threshold`, `unlocks_in_sec`, `tier`. |
| `auth.account_hard_locked` | Counter crosses the hard threshold | Metadata adds `locked_until`. |
| `auth.login_blocked_account_locked` | Every attempt refused while a lock is already in force | One row per attempt — this is how you see *how long an attack kept running*. |
| `admin.account_unlocked` | Admin cleared a lock | Distinct from `admin.user_unblocked`, which reverses an `is_active` block. |

One row per affected account (an email owning accounts in two tenants produces
two rows), or a single account-less row when the email owns none — so a
probed-but-nonexistent address still leaves a trail. All three `auth.*` events
are registered in `riskActions`, so they get the new-device / impossible-travel /
untrusted-IP assessment.

Service-layer events do not carry IP/User-Agent (matching existing
`internal/auth` precedent); the handler's own `auth.login_failed` event for the
same request carries those.

### Prometheus metrics

```
emc_auth_account_lockouts_total{tier="soft"|"hard"}          # lockouts triggered
emc_auth_logins_blocked_by_lockout_total{tier="soft"|"hard"} # attempts refused
```

**The alertable signal:** `logins_blocked_by_lockout_total` rising while
`account_lockouts_total` is flat means an attack is still hammering an
already-locked account. Worth alerting on, because the refusal is invisible to
the client by design — nobody will report it.

`blocked{tier="hard"}` only appears once the Redis counter has expired while
`locked_until` still stands (the soft gate short-circuits first while both are
live). Its absence in a short test run is expected, not a fault.

---

## 10. Impact on consuming applications

### 10.1 No breaking API change

| | |
|---|---|
| New endpoints on the login path | **None** |
| New error codes | **None** — still `401` |
| New response fields on login | **None** |
| New request fields | **None** |
| New response headers | **None** |

`POST /auth/login` and `POST /auth/apps/login` return exactly what they returned
before: `401` with `{"error":"invalid credentials"}`. **Existing clients need no
code change to keep working.**

This is not an accident — the service returns a single `ErrInvalidCredentials`
sentinel whose message is unchanged, so the existing handler branch maps it to
the existing response.

### 10.2 The one behavioural change that matters

> **A user with the correct password can now be refused.**

Before, `401` on login meant "your credentials are wrong". Now it can also mean
"too many recent failures on this account". **The client cannot tell which** —
that is the deliberate enumeration-safety property, not an oversight.

Practical consequences for an integrating app:

1. **Never retry-loop on `401`.** An automated retry now actively drives the
   account toward a hard lock. If you have a client that retries login on
   failure, fix that first.
2. **Your error copy should acknowledge the possibility.** Suggested wording:
   > "Incorrect email or password. If you've tried several times, wait 15 minutes
   > before trying again, or reset your password."

   Do **not** write "your account is locked" — you cannot know that, and saying
   it when you merely got a `401` would confuse the majority case (a genuine typo).
3. **Handle `429` separately from `401`.** The rate limiter still returns `429`
   with `Retry-After`; honour it with backoff. Lockout `401`s carry no
   `Retry-After` and you must not synthesise one.
4. **Expect support tickets phrased as "my password definitely works".** That is
   the signature of a lockout. See [§11](#11-operational-runbook).

### 10.3 What is *not* affected

| Area | Effect |
|---|---|
| **Existing sessions** | **Unaffected.** No tier revokes refresh tokens or bumps `token_version`. A user already signed in stays signed in, and token refresh keeps working, even while hard-locked. Only *new* password logins are refused. |
| **Machine-to-machine** (`client_credentials`, API keys) | Unaffected — no per-account password counter is involved. |
| **App-authenticated login** (`/auth/apps/login`) | Lockout **does** apply (same `Login`), with the same generic `401`. No client change needed. |
| **Google / social login** | **Not gated** — see [§12](#12-what-this-does-not-cover). |
| **Magic-link login** | **Not gated** — see [§12](#12-what-this-does-not-cover). |
| **MFA / TOTP** | A correct password clears the counter *before* the OTP challenge, so fumbling OTP codes cannot password-lock a user. MFA keeps its own attempt budget. |

### 10.4 Configuration from the integrator's side

**There is nothing for a consuming application to configure.** Lockout is a
server-side policy, set by whoever operates the auth server via the env vars in
[§7](#7-configuration-reference). There is no per-application or per-tenant
override in this release.

If an integrator needs different thresholds, that is a request to the auth-server
operator — and a future per-application setting (following the
`application_mfa_settings` precedent) is the intended path.

### 10.5 Admin UI / dashboard work required

**This is the one piece of frontend work this change creates.** It was flagged
rather than implemented, per the frontend/backend boundary rule in `CLAUDE.md`.

`GET /api/v1/users` and `/users/{id}` now return `locked_until`.

1. **A "Locked" badge**, shown when `locked_until != null`. It must be **visually
   distinct from the existing blocked/inactive badge** — they are independent
   states and a user can be in both at once. Consider showing the expiry
   ("locked for 43 more minutes") since the lock self-heals.
2. **An "Unlock" button** → `POST /api/v1/users/{id}/unlock`. Returns the updated
   `UserResult`; re-render from it. It is idempotent, so a double-click is safe.
3. **Do not** repurpose the existing block/unblock control — that endpoint
   (`PUT /users/{id}/status`) changes `is_active` and will not clear a lock.
4. Optional: filter/sort the user list by locked state (the partial index
   supports it efficiently).

---

## 11. Operational runbook

### "A user says their password works but they can't log in"

```sql
SELECT id, email, is_active, locked_until, locked_reason
FROM users WHERE email = 'user@example.com';
```

| Observation | Meaning | Action |
|---|---|---|
| `locked_until` in the future | Hard-locked | Wait for expiry, or unlock via the API |
| `locked_until` NULL, `is_active` true | Possibly **soft**-locked (Redis only — invisible in SQL) | Check Redis (below) or just unlock; it clears both |
| `is_active` false | Administratively **blocked**, not locked | `PUT /users/{id}/status` — a different decision |

Check a soft lock (the key is a hash, so compute it):

```bash
# sha256 of the lowercased email
docker exec emc-auth-server-redis-1 redis-cli GET "login:fail:$(printf 'user@example.com' | sha256sum | cut -d' ' -f1)"
docker exec emc-auth-server-redis-1 redis-cli TTL "login:fail:$(printf 'user@example.com' | sha256sum | cut -d' ' -f1)"
```

**Resolution — one call clears both tiers:**

```bash
curl -X POST https://auth.example.com/api/v1/users/1071/unlock \
     -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Was this an attack or a fumbling user?

```sql
SELECT created_at, action, ip_address, metadata
FROM audit_logs
WHERE actor_email = 'user@example.com'
  AND action IN ('auth.login_failed','auth.account_soft_locked',
                 'auth.account_hard_locked','auth.login_blocked_account_locked')
ORDER BY created_at DESC LIMIT 50;
```

Many distinct `ip_address` values ⇒ distributed attack. One IP, human-paced ⇒
most likely a real user. A long tail of `login_blocked_account_locked` ⇒ the
attack kept running after the guard fired.

### Emergency: disable lockout entirely

Set `AUTH_LOGIN_SOFT_LOCK_THRESHOLD=0` and restart. `Login` reverts to exactly
its pre-#72 behaviour. Existing `locked_until` values in the database **are still
enforced** — clear them if needed:

```sql
UPDATE users SET locked_until = NULL, locked_reason = NULL
WHERE locked_until IS NOT NULL;
```

---

## 12. What this does NOT cover

Honest scope boundaries. The first three are **verified gaps**, not speculation.

### 12.1 A password reset does NOT clear the lock

`ResetService` does not touch `locked_until` or the failure counter. A user who
locks themselves out, then completes the email password-reset flow, **still
cannot log in** until the lock expires.

This is arguably wrong: completing a reset proves control of the mailbox, and
Auth0/Okta clear brute-force lockout on a successful reset. **Recommended
follow-up** — call `ResetLoginFailures` plus clear `locked_until` at the end of
`ResetPassword`. Low risk, small change. It is a UX gap, not a security hole.

### 12.2 Federated and passwordless logins are not gated

`locked_until` is checked only inside `Login` (the password path). Google login
([internal/auth/google.go](../internal/auth/google.go)) and magic-link
([internal/auth/magic_link.go](../internal/auth/magic_link.go)) call
`issueTokenPair` directly, so a hard-locked user **can still sign in** through
them.

Defensible — the lock exists to stop *password guessing*, and both alternatives
independently prove identity (OAuth with the provider, or control of the
mailbox). But know it: if an account is under attack and you want it fully frozen,
lockout is not the tool — `PUT /users/{id}/status` (`is_active = false`) is.

### 12.3 Other boundaries

| Not covered | Why / where it lives |
|---|---|
| **Credential stuffing** (one guess across many accounts) | A per-account counter never trips. Needs a global/per-IP limiter → `PRODUCTION_READINESS.md` **B1**. |
| **`X-Tenant-Slug` limiter bypass** | The per-tenant limiter still keys on an unvalidated header. Independent of #72; **H5 stays open** for it. |
| **Multi-replica rate limiting** | The AUTH-07 limiter is still in-process. The lockout counter itself **is** shared (Redis), so lockout is already correct across replicas — the limiter is not. → **B1**. |
| **Per-tenant / per-application thresholds** | No per-tenant settings store exists. Global only in this release. |
| **CAPTCHA / progressive delays** | Not implemented. |
| **User self-service unlock** | Admin-only. Locks self-heal, so the common case needs nobody. |

---

## 13. Failure modes

| Scenario | Behaviour | Rationale |
|---|---|---|
| **Redis down** | Lockout silently disabled (WARN logged); logins proceed normally. Per-IP limiter still applies. | Failing closed would make a cache outage a total auth outage. |
| **Redis flushed / restarted** | Soft locks vanish. **Hard locks survive** — they live in Postgres. | Exactly why the column exists. |
| **DB write of the hard lock fails** | Logged at ERROR; the soft lock still holds for the rest of the window. | Never turn a failed login into a `500`. |
| **Audit pipeline saturated** | Events dropped (counted in Prometheus); enforcement unaffected. | Pre-existing async-audit design. |
| **Misconfigured threshold** | Clamped — see [§7](#7-configuration-reference). | A `0` threshold would reject every login. |
| **Same email, multiple tenants** | Shared counter; an attack on one locks the others. Unlock clears the shared counter but only *that* tenant's column. | Consequence of email-only keying (Deviation 1). |

---

## 14. Every file changed

### New

| File | Purpose |
|---|---|
| `migrations/00061_user_lockout.sql` | `locked_until`, `locked_reason`, partial index |
| `internal/auth/lockout.go` | All lockout logic: config, key, Lua script, tiers, audit |
| `internal/auth/lockout_test.go` | 9 integration tests |
| `internal/admin/unlock_test.go` | 6 unlock tests |
| `docs/ACCOUNT_LOCKOUT.md` | This document |
| `scripts/lockout-helpers.ps1` | PowerShell helpers for manual testing |
| `scripts/test-lockout.ps1` | Self-contained end-to-end test script |
| `scripts/LOCKOUT_TESTING.md` | Manual testing guide |

### Modified

| File | Change |
|---|---|
| `internal/auth/service.go` | `lockoutRedis`/`lockout`/`audit` fields; `WithLockout`, `WithAudit`; `ErrInvalidCredentials` sentinel; `padCompares` helper; `loginCandidate.lockedUntil`; the flow changes in [§4](#4-the-login-flow-step-by-step) |
| `internal/config/config.go` | 6 new fields; `atoiOr` (default-preserving, unlike `mustAtoi`) |
| `internal/audit/logger.go` | 4 new action constants; `swaggertype:"object"` on `LogEntry.Metadata` (**this also fixed swagger generation, which had been failing silently — see [§15](#15-testing)**) |
| `internal/audit/enrich.go` | 3 lock actions added to `riskActions` |
| `internal/metrics/metrics.go` | `AccountLockouts`, `LoginsBlockedByLockout` |
| `internal/admin/service.go` | `UserResult.LockedUntil`; `locked_until` in `userEnrichmentColumns` (elapsed ⇒ NULL); `UnlockUser`; `LoginFailureResetter`; `WithLockoutReset` |
| `internal/api/handlers/admin.go` | `UnlockUser` handler + swagger annotations |
| `internal/api/routes.go` | 6 `RoutesConfig` fields; rate-limit env overrides; `authSvc.WithAudit`/`WithLockout`; `adminSvc.WithLockoutReset`; route registration |
| `cmd/server/main.go` | Pass the 6 config values through |
| `docker-compose.yml` | 6 env vars with production defaults |
| `.env.example` | Two documented blocks (lockout + rate limits) |
| `docs/swagger.{json,yaml}`, `docs/docs.go` | Regenerated |
| `PRODUCTION_READINESS.md` | H5 updated; the 3 spec bugs recorded; kept **open** |

---

## 15. Testing

### Automated — 15 tests, all passing

`internal/auth/lockout_test.go` (real Postgres + Redis, skip if env unset):

1. Soft lock refuses the correct password; **no DB write**; TTL bounded
2. Hard lock persists independently of Redis (counter deleted → still refused)
3. A successful login resets the window
4. All four failure states are indistinguishable (`errors.Is` + exact message)
5. Case-varied emails share one counter (bypass guard)
6. `SoftThreshold = 0` fully disables the feature
7. Audit rows for all three `auth.*` actions
8. `ResetLoginFailures` clears a soft lock
9. `NewLockoutConfig` clamping (table-driven, no infra needed)

`internal/admin/unlock_test.go`: clears both halves · does **not** reinstate a
blocked user · idempotent · elapsed lock reports as unlocked · `404` on missing
id · survives a counter-reset failure.

```bash
DATABASE_URL='postgres://emc_auth:password@localhost:5433/emc_auth_test?sslmode=disable' \
REDIS_URL='redis://localhost:6379/1' \
TOTP_ENCRYPTION_KEY=$(openssl rand -hex 32) \
go test ./internal/auth/ ./internal/admin/ -run 'Lockout|UnlockUser' -p 1 -v
```

Use a **separate** database — `testhelper.CleanupTables` truncates whatever
`DATABASE_URL` points at (`CLAUDE.md` deferred item #8).

### Manual — 21/21 checks passed

See [`scripts/LOCKOUT_TESTING.md`](../scripts/LOCKOUT_TESTING.md). Verified on a
live server: both tiers, the DB/no-DB split, unlock (incl. `401`/`404`/idempotent),
counter reset, case bypass, all four audit actions, both metrics.

Audit rows and metrics cross-checked exactly — e.g. `soft_locked` = 2 rows =
`lockouts{tier="soft"} 2`; `login_blocked` = 4 rows = `blocked{tier="soft"} 4`.

**One caveat recorded for honesty:** the *manual* "identical response body" check
passed vacuously — PowerShell 5.1's `Invoke-WebRequest` consumes the response
stream when building its exception, so both bodies read as empty and the
comparison was `'' == ''`. The property is genuinely covered by automated test #4
and by code inspection ([auth.go:261](../internal/api/handlers/auth.go#L261)
maps one sentinel to one body); confirm on the wire with `curl.exe`, which does
not throw.

### Incidental fix

Swagger generation had been **failing silently** before this work: `swag` could
not resolve `json.RawMessage` on `audit.LogEntry.Metadata` and aborted the run,
so the committed `docs/` was missing ~30 endpoints. Adding
`swaggertype:"object"` unblocked it — hence the large `docs/` diff.

---

## 16. Rollback

**Config-only (no deploy):** `AUTH_LOGIN_SOFT_LOCK_THRESHOLD=0` + restart. Login
reverts to pre-#72 behaviour. Existing `locked_until` values are still enforced —
`UPDATE users SET locked_until = NULL` to clear them.

**Full code rollback:** deploy the previous binary. The migration is additive and
nullable, so the old code ignores the new columns; **no down-migration needed**.
Redis counters expire within the window on their own.

**Down migration** (only if you truly want the columns gone):

```bash
goose -dir migrations postgres "$DATABASE_URL" down-to 60
```
