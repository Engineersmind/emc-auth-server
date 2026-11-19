# perf/ — k6 NFR suite (issue #218)

The performance test surface for emc-auth-server: a k6 scenario suite, a
seed/teardown pair that creates an isolated perf tenant, one canonical targets
file, and a GitHub Actions smoke workflow.

```
perf/
  k6/main.js                the suite — 7 flows, 6 scenarios
  seed/seed.js              creates the perf tenant/apps/users, records state
  seed/teardown.js          deactivates what a recorded run created
  lib/                      targets/guard/results helpers + node:test tests
  scripts/check-target.js   standalone production-host refusal (CLI)
  scripts/results-dir.js    prints docs/perf/<date>/<scenario>-<sha>-<ts>/
  scripts/mint-admin-token.js  mints an admin JWT through the forced-MFA path
  targets.json              canonical NFR numbers (placeholders until #170 lands)
  targets.local.json        gentle numbers for the docker compose smoke
  targets.fail-demo.json    deliberately impossible — proves thresholds fail runs
  refused-hosts.json        production host deny list for the guard
  docker-compose.perf.yml   overlay: TRUSTED_PROXIES + raised per-IP app limit
  .state/                   seed state (gitignored, 0600 — client secrets live here)
docs/perf/<date>/           run output: summary.json + meta.json + report.html
```

## The seven flows and six scenarios

| flow | request |
|---|---|
| `auth_login` | `POST /api/v1/auth/login` |
| `apps_login` | `POST /api/v1/auth/apps/login` (Basic app creds) |
| `apps_register` | `POST /api/v1/auth/apps/register` (Basic app creds) |
| `oauth_client_credentials` | `POST /oauth/token` grant_type=client_credentials |
| `oauth_refresh` | `POST /oauth/token` grant_type=refresh_token (rotated, single-use) |
| `jwks` | `GET /tenants/{slug}/.well-known/jwks.json` |
| `apps_me` | `GET /api/v1/auth/apps/me` (Bearer user + X-Client-Authorization) |

`SCENARIO` env picks one of `smoke|load|stress|soak|spike|ratelimit`. Stress is
sized at 2x the load target; soak holds the load rate for the soak duration;
spike jumps to the spike rate and back. `ratelimit` is separate and short: it
probes the compiled-in default limiters (per-IP login, per-user app-login,
per-IP app-login, in that order) and fails unless each returns 429 with a
`Retry-After`. Each probe's first request must reach authentication, and the
app-login 429s must name the expected limiter (`user`, then `ip`) in the body,
so one probe's spent bucket cannot pass the other.

## Never production

`perf/scripts/check-target.js` (also embedded in `main.js` and the seed)
accepts only localhost/loopback/::1, private-LAN addresses and docker-compose
service names, and refuses every host in `refused-hosts.json` — currently
`senie.ai`, `engineersmind.com`, `pollenx.ai` and subdomains. The guard runs
before the first request and before the admin token is read. Add future
production hosts to `refused-hosts.json`.

## Prereqs

- k6 (`go install go.k6.io/k6@<tag>` or https://k6.io/docs/getting-started/installation/)
- Node 22+
- the stack up on `http://localhost:9090`
- **For the measured scenarios** (not `ratelimit`): the perf overlay, because
  the suite sends a unique `X-Forwarded-For` per iteration to spread per-IP
  limiter buckets:

  ```bash
  export PERF_TRUSTED_PROXIES=<subnet k6 traffic arrives from, e.g. 172.18.0.0/16>
  docker compose -f docker-compose.yml -f perf/docker-compose.perf.yml up -d
  # find the subnet: docker network inspect <project>_default
  ```

- An admin JWT for the seed (15-minute life — mint one per run). The seeded
  `admin@emc.local` is under the forced administrator-MFA policy, so a plain
  password login returns an enrollment/OTP challenge, not a token.
  `perf/scripts/mint-admin-token.js` walks that for you — enrolls TOTP once
  (secret kept at `perf/.state/admin-totp.json`, 0600) and completes the OTP
  challenge on later mints:

  ```bash
  export PERF_ADMIN_TOKEN=$(BASE_URL=http://localhost:9090 \
    PERF_ADMIN_PASSWORD="$SEED_ADMIN_PASSWORD" \
    node perf/scripts/mint-admin-token.js)
  # prints ONLY the token on stdout; a second run reuses the stored secret.
  # On a foreign stack: PERF_ADMIN_TOTP_SECRET=<base32> overrides it, or mint
  # however you normally get admin JWTs and export PERF_ADMIN_TOKEN directly.
  ```

## Run loop

```bash
# 1. seed — creates perf-<runid> tenant, 3 apps (web/m2m/defaults), the user
#    pools, and writes perf/.state/<runid>.json + latest.json (0600)
BASE_URL=http://localhost:9090 PERF_ADMIN_TOKEN=... \
  TARGETS_FILE=$PWD/perf/targets.local.json node perf/seed/seed.js

# 2. run — RESULTS_DIR must exist first; k6 writes summary.json, meta.json,
#    report.html into it
RESULTS_DIR=$(GIT_SHA=$(git rev-parse --short HEAD) node perf/scripts/results-dir.js smoke) && \
mkdir -p "$RESULTS_DIR" && \
BASE_URL=http://localhost:9090 SCENARIO=smoke \
  TARGETS_FILE=$PWD/perf/targets.local.json \
  PERF_STATE_FILE=$PWD/perf/.state/latest.json \
  GIT_SHA=$(git rev-parse --short HEAD) RESULTS_DIR=$RESULTS_DIR \
  k6 run perf/k6/main.js

# (or `make load-test` for the same smoke run)

# 3. teardown — deactivates the recorded tenant/apps, then removes state
PERF_ADMIN_TOKEN=... PERF_STATE_FILE=$PWD/perf/.state/latest.json \
  node perf/seed/teardown.js
```

## Thresholds

`perf/targets.json` is the single source of truth: per-flow VU/RPS, p95, p99
and error-rate values under each scenario key. Placeholder flows
(`"placeholder": true`) are unagreed numbers — the suite prints which flows
they belong to and the HTML report banners them. `targets.fail-demo.json`
exists to prove the wiring: running with it must fail the k6 run.

Per flow, the run fails on: p95 or p99 over target; `http_req_failed` above
`error_rate`; a `checks` pass rate below `1 - error_rate` (a 200 without the
expected body, such as an OTP challenge with no `access_token`, or a token
holder that could not log in); zero requests; and, on arrival-rate scenarios,
any dropped iteration.

## What "green" means on a laptop

`targets.local.json` is sized so **smoke, ratelimit and load** run green on a
local Docker Desktop stack. The credential flows are bcrypt-bound and the
server holds a DB connection for the whole login; its pool is 25. On a
constrained box, `stress` (2x), `spike` and `soak` legitimately breach — the
suite correctly reports p95 blow-out, dropped iterations and context-deadline
500s. That is the suite measuring capacity, not a suite bug: real NFR numbers
land in `targets.json` when #170 agrees them, and they are meant to be run
against a realistically provisioned test deployment — never a laptop.

## Workflow

`.github/workflows/perf-smoke.yml` — `workflow_dispatch` with a required
`target_url` input. The guard step refuses non-local targets before any
secrets are touched; seed, run, teardown (`if: always()`), job summary and a
`docs/perf/` artifact upload follow. It needs the `PERF_ADMIN_TOKEN` repo
secret — without it the seed fails before k6 runs. No schedule.

## House rules

- No credentials in the tree: app secrets/passwords live only in
  `perf/.state/` (gitignored); nothing logs tokens.
- Teardown deactivates, never hard-deletes, and only touches resources the
  recorded run created — a missing state file fails before any request.
- Run output under `docs/perf/<date>/` is generated locally/in CI; the dated
  dirs are gitignored, the tree's `README.md` is not.
- Tests: `node --test perf/lib/*.test.js perf/seed/seed.test.js`
