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
probes the compiled-in default limiters (per-IP login, per-IP app-login,
per-user app-login) and fails unless each returns 429 with a `Retry-After`.

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

- An admin JWT for the seed (15-minute life — mint one per run):

  ```bash
  curl -s http://localhost:9090/api/v1/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"email":"admin@emc.local","password":"<SEED_ADMIN_PASSWORD>"}' \
    | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>console.log(JSON.parse(s).access_token))"
  export PERF_ADMIN_TOKEN=<token from above>
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
