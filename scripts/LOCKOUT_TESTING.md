# Manual testing — account lockout (issue #72)

Everything here drives the real HTTP API against a running server. The automated
Go integration tests already cover the same ground
(`internal/auth/lockout_test.go`, `internal/admin/unlock_test.go`); this is for
eyeballing the actual wire behaviour and hunting for anything the tests missed.

---

## What I need from you

1. **Postgres + Redis running.** Yours are already up (`docker compose ps` shows
   `emc-auth-server-postgres-1` and `-redis-1` healthy).
2. **The server started with raised login rate limits** — see below. This is the
   one thing that will silently ruin the run if skipped.
3. **The migration applied.** The server auto-migrates on boot, so just starting
   it applies `00061_user_lockout.sql`. Confirm from the boot log:
   `goose: OK 00061_user_lockout.sql`.
4. Run the script, paste me the output. Any `[FAIL]` line includes an
   `expected` / `actual` / `meaning` triple — send those and I'll fix.

---

## ⚠️ Why you must raise the rate limit for testing

The AUTH-07 login limiter defaults to **5 attempts/min per IP**. The soft-lock
threshold is also **5**. So from a single machine you get `HTTP 429` from the
limiter *at the exact point* the lockout would engage — and the hard tier (10
failures) is simply unreachable inside a minute.

That is **correct in production**: the two defenses are layered, and a
single-source attacker being throttled first is the desired outcome. The account
lockout earns its keep against *distributed* attacks (many IPs, one account),
where the per-IP limiter never trips.

But to exercise the tiers end-to-end from one laptop, the limiter needs headroom.
`AUTH_LOGIN_RATE_LIMIT_PER_IP` / `AUTH_LOGIN_RATE_LIMIT_PER_ACCOUNT` exist for
exactly this. The script **aborts with instructions** if it detects a 429, so you
cannot accidentally get a screen of false failures.

---

## Start the server (PowerShell, one block)

```powershell
cd C:\projects\EMC_AUTH\emc-auth-server

# ── Infra ──
$env:DATABASE_URL = 'postgres://emc_auth:password@localhost:5433/emc_auth?sslmode=disable'
$env:REDIS_URL    = 'redis://localhost:6379/0'
$env:PORT         = '9090'
$env:ENV          = 'development'

# ── Required keys ──
$env:TOTP_ENCRYPTION_KEY                  = '0000000000000000000000000000000000000000000000000000000000000000'
$env:OAUTH_CLIENT_SECRET_ENCRYPTION_KEY   = '0000000000000000000000000000000000000000000000000000000000000000'
$env:SEED_ADMIN_PASSWORD                  = 'ChangeMe123!'

# ── Lockout: small thresholds so the run is quick ──
$env:AUTH_LOGIN_SOFT_LOCK_THRESHOLD    = '3'
$env:AUTH_LOGIN_HARD_LOCK_THRESHOLD    = '5'
$env:AUTH_LOGIN_FAILURE_WINDOW_MINUTES = '15'
$env:AUTH_LOGIN_HARD_LOCK_MINUTES      = '60'

# ── TEST ONLY: give the limiter headroom (production keeps 5 / 10) ──
$env:AUTH_LOGIN_RATE_LIMIT_PER_IP      = '1000'
$env:AUTH_LOGIN_RATE_LIMIT_PER_ACCOUNT = '1000'

go run ./cmd/server
```

Leave that terminal running — its structured JSON logs are half the evidence.
Watch for `lockout: account hard-locked after repeated failed logins`.

## Run the tests (second PowerShell window)

```powershell
cd C:\projects\EMC_AUTH\emc-auth-server
.\scripts\test-lockout.ps1 -SoftThreshold 3 -HardThreshold 5 -Verbose
```

`-SoftThreshold` / `-HardThreshold` **must match the server's env vars** — the
script has no way to read the server's config, so a mismatch shows up as
confusing failures in sections 3 and 4.

> Note: each wrong-password attempt costs ~5 bcrypt-cost-12 comparisons
> (deliberate anti-timing padding), so roughly 0.6–1s per attempt. A full run
> takes a couple of minutes. That slowness is the feature working.

---

## What each section proves

| § | Check | Maps to |
|---|---|---|
| 0 | Server up; rate-limiter headroom | test prerequisite |
| 1 | Super-admin login | prerequisite for §5, §8 |
| 2 | Victim registered; **baseline login works** | prevents false positives later |
| 3 | N failures ⇒ correct password refused; **body identical** to unknown-email; **no `Retry-After`**; `locked_until` still NULL; `is_active` untouched | "5 failures → soft lock (no DB write)", "Generic error always returned" |
| 4 | Escalation to hard tier persists `locked_until`, bounded, `is_active` still true | "10 failures → hard lock (DB + audit)" |
| 5 | Unlock needs a token; returns 200; clears lock; **login works again**; idempotent; 404 on missing id | "Unlock API scoped to tenant admin / super_admin" |
| 6 | Success resets the counter | "window reset" |
| 7 | Case-varied emails share one counter | bypass hunt (not in the issue) |
| 8 | Audit rows for all four actions | "audit log entry written" |
| 9 | Prometheus counters exported | operability |

---

## Things worth poking at manually (where I'd look for flaws)

These are deliberate design decisions rather than known bugs — but they're the
places where a second pair of eyes is most valuable.

1. **Shared counter across tenants.** Register the *same email* in two tenants
   (needs a second tenant), lock it via one, confirm the other is affected too.
   The counter is email-keyed because on a failed login there is no tenant yet.
   Accepted trade-off; verify the blast radius is only what's documented.

2. **Redis down ⇒ fails open.** Stop Redis (`docker compose stop redis`) and
   confirm logins still work (with a warning logged) rather than everyone being
   locked out. Failing closed would turn a cache outage into an auth outage.
   Then restart it.

3. **Locked user's existing sessions survive.** Log in, keep the refresh token,
   trigger a hard lock, and confirm the old session still refreshes. Intentional:
   otherwise anyone knowing your email could force-log you out of every device.

4. **`/auth/apps/login`** (app-authenticated flow) goes through the same
   `Login`, so lockout should apply identically. Worth confirming with a real
   `client_id`/`client_secret`.

5. **MFA interaction.** For a TOTP-enrolled user, a correct password clears the
   counter *before* the OTP challenge. Confirm that fumbling OTP codes does not
   password-lock the account (MFA has its own budget).

6. **Timing.** Compare response times for wrong-password vs soft-locked. They
   should be indistinguishable (~5 bcrypt compares each). A locked account
   answering noticeably faster would be a timing oracle:
   ```powershell
   Measure-Command { .\scripts\test-lockout.ps1 } # or time individual curls
   ```

---

## Cleanup

Test users accumulate in the `users` table (`*@lockout.test`). They are
soft-deletable via the admin API, or:

```powershell
docker exec emc-auth-server-postgres-1 psql -U emc_auth -d emc_auth `
  -c "DELETE FROM users WHERE email LIKE '%@lockout.test'"
```

To clear lingering Redis counters:

```powershell
docker exec emc-auth-server-redis-1 redis-cli --scan --pattern 'login:fail:*' |
  ForEach-Object { docker exec emc-auth-server-redis-1 redis-cli DEL $_ }
```
