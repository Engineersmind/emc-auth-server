# Phase 4 cutover runbook — reject HS256, drop `tenants.jwt_secret` and `tenants.jwt_secret_enc`

Issue #95, Phase 4. **This is the step that actually removes the forging risk.**

Phases 1–3 (shipped) give tenants the ability to verify tokens safely. They do **not**
take away anyone's ability to forge one: while HS256 still verifies, any holder of a
tenant's `jwt_secret` can still mint a token for any user in that tenant, including
`super_admin`. Only this phase closes that.

It is deliberately **not** part of the Phases 1–3 pull request, because it is one-way
and time-gated: the issue's own gate is *"must not run until every live HS256 token has
expired."* Bundling it would mean a single deploy both introduces RS256 and rejects
every token minted a second earlier.

---

## What is already in the codebase

The code for this phase **is written and tested** — the strict posture is now
the default, and the permissive window is an explicit opt-in
(GHSA-4x5m-3gph-938r).

| Piece | Where | State |
|---|---|---|
| `JWT_ALLOW_LEGACY_HS256` env var | `internal/config/config.go` | defaults to `false` — strict; set `true` only for a migration window |
| Deploy-path pin | `infra/docker-compose.prod.yml` | forwards `JWT_ALLOW_LEGACY_HS256` with the same secure default (`:-false`) — an operator opens ONE migration window by setting it `true` in `.env`, then removes it |
| Both algorithm pins narrow to RS256 | `internal/auth/jwt.go` — `WithValidMethods` **and** the keyfunc's HMAC branch | active when the flag is `false` |
| Startup warning while the window is open | `internal/api/routes.go` | active — logs `JWT_ALLOW_LEGACY_HS256=true — HS256 tokens are still ACCEPTED` until the flag is off |
| Rejection counter | `emc_auth_legacy_hs256_verifications_total{reason="rejected"}` | active |
| Test coverage | `TestJWTService_Phase4Cutover` | passing |

So step 2 below is an **env var change and a restart**, not a code change —
and for the shipped compose deployment it means unsetting the variable an
operator set for the migration window (or never having set it at all).

---

## Prerequisites

### 1. Establish who holds a tenant `jwt_secret`

`FRONTEND_M2M_PLAN.md` previously told consumers to hold the secret and verify locally,
so the holder set is not assumed empty. Every holder is a party with **current forging
authority** and must be migrated to JWKS before cutover.

Audit performed 2026-07-31 across sibling repos:

| Consumer | Holds a tenant secret? | Notes |
|---|---|---|
| `emc-insurance-platform` | **No** | Verifies via a network call to `GET /api/v1/auth/me` — see `apps/api/src/config/env.ts:45-50`. Its own `JWT_SECRET`/`LOCAL_AUTH_JWT_SECRET` belong to its local-auth mode and are unrelated. |
| `AUTO_filler` | **No** | No matches. `INTEGRATION_AUTOFILLER_BACKEND.md` *proposed* shared-secret verification; it was never implemented. |

**Result: no known holders.** Re-run before cutover — the guidance that encouraged it
existed for a while, so confirm with each consuming team rather than trusting this table.

Discovery greps:

```bash
grep -rniE "jwt_secret|EMC_AUTH_SECRET|hs256" <consumer-repo> --include=*.ts --include=*.go --include=*.env*
```

### 2. Confirm no live HS256 tokens

Do **not** use a stopwatch. Watch the counter:

```promql
sum(rate(emc_auth_legacy_hs256_verifications_total[5m]))
```

Proceed when this has been **flat at zero for at least 2 hours**. The longest-lived
symmetric token is the 1 h agent token (`auth.AgentTokenTTL`), so a 2 h quiet window
clears it with margin.

A non-zero rate long after Phases 1–3 shipped means something is still minting or
replaying symmetric tokens — investigate before continuing, do not force it.

### 3. Back up

```bash
pg_dump --data-only --table=tenants "$DATABASE_URL" > tenants-backup-$(date +%F).sql
```

Required: step 3's migration destroys both columns. Keep this until cutover is confirmed
stable — reverting the flag is instant, but restoring a dropped column is not.

---

## Cutover

### Step 1 — verify RS256 is actually in use

```bash
curl -s "$APP_BASE_URL/tenants/<slug>/.well-known/jwks.json" | jq '.keys[].kid'
```

Then decode a freshly issued access token and confirm `alg: "RS256"` and that its `kid`
appears in that list. If it does not, **stop** — cutover would reject everything.

### Step 2 — reject HS256

Since GHSA-4x5m-3gph-938r the flag **defaults to false** — deployments that
never set it are already strict, and the shipped `docker-compose.prod.yml`
defers to that default (`JWT_ALLOW_LEGACY_HS256: ${JWT_ALLOW_LEGACY_HS256:-false}`).
If an operator opened a migration window by setting `JWT_ALLOW_LEGACY_HS256=true`
in `.env`, the cutover is to remove it:

```bash
# delete the JWT_ALLOW_LEGACY_HS256=true line from .env, or set explicitly:
JWT_ALLOW_LEGACY_HS256=false
```

Restart. Confirm at startup that the migration-window warning is **gone**:

```
# this line must NOT appear:
WARN  JWT_ALLOW_LEGACY_HS256=true — HS256 tokens are still ACCEPTED (issue #95 Phase 4 migration window)
```

**Blast radius, honestly:** any access token minted before RS256 went live now fails.
Access and management tokens are 15 minutes, so the window is short, and **refresh tokens
are opaque random strings, not JWTs — they are unaffected**, so a client that refreshes on
401 recovers on its own. The risk is a client that treats a signature failure as "log the
user out" instead of "refresh". That is exactly what the quiet-counter gate in
prerequisite 2 exists to avoid.

**Rollback:** set the flag back to `true` and restart. Instant, no data loss. This is why
step 3 is separate — keep the flag flipped for at least one full business day before
dropping the columns.

### Step 3 — drop the columns and the code that reads them

Only after step 2 has been stable and `..._total{reason="rejected"}` is not climbing.

`jwt_secret` and `jwt_secret_enc` come out **together**. Dropping only `jwt_secret`
would leave the actual secret behind: since migration 00105 the real value lives in
`jwt_secret_enc` and the plaintext column is blanked, so a partial drop removes a
column that is already empty and keeps the credential.

**Order matters.** Every reference to either column must be gone from the running
binary before the drop migration lands, not after: the startup sweeps SELECT both
columns on every boot and `CreateTenant` INSERTs into both, so a binary left pointing
at a dropped column logs backfill errors on each start and fails every tenant
creation. For the shipped single-container compose deploy the code cleanup and the
migration can ride in one release — goose applies migrations at boot, before seeds
run and before the app serves, so no request ever meets the new schema on old code.
For a multi-instance fleet, ship the cleanup first and let the drop land on the next
deploy, once every instance runs the cleaned binary — a mixed roll would put the old
binary on the new schema.

Remove the dependent code — everything that reads or writes either column:

- `JWTService.tenantSecret`, the only reader of both columns, with its callers: the
  HS256 branch in `signClaims`, `legacyHMACKeyForToken`, and the
  `*jwt.SigningMethodHMAC` case in `VerifyForAudience` (`internal/auth/jwt.go`)
- `JWTService.EncryptAllTenantSecrets` and `JWTService.ReencryptTenantSecrets` — the
  backfill that fills `jwt_secret_enc` and the sweep that re-seals it
  (`internal/auth/jwt.go`) — and their boot call sites and log lines in
  `internal/api/routes.go`. Leave `SigningKeyService.ReencryptPrivateKeys` and the
  rotation-complete log: `signing_keys.private_key_enc` stays
- `JWTService`'s `secretBox` field and `WithSecretBox`, and the
  `jwtSvc.WithSecretBox(...)` wiring in `internal/api/routes.go`
- `admin.Service`'s `secretBox` field and `WithSecretBox`, the generate-and-encrypt
  block and the `jwt_secret`/`jwt_secret_enc` columns in `CreateTenant`'s INSERT,
  `generateSecret` itself (`internal/admin/service.go`), and `adminSvc.WithSecretBox`
  in `internal/api/routes.go`
- The `jwt_secret` column in the tenant inserts in `internal/store/seed.go` and
  `internal/store/seed_demo.go`, and `generateTenantSecret` once it has no callers
- The `allowLegacyHS256` field, `WithLegacyHS256`, the `JWT_ALLOW_LEGACY_HS256` config
  field and env parse (`internal/config/config.go`), its compose pin
  (`infra/docker-compose.prod.yml`) and `.env.example` entry, the startup warning in
  `internal/api/routes.go`, and `TestLoad_SecureDefaults_M02`
- Tests and fixtures: `TestJWTService_Phase4Cutover`'s HS256 halves, the backfill and
  re-encryption tests and the legacy tests in `jwt_test.go`, all of
  `internal/admin/tenant_secret_enc_test.go`, and every
  `INSERT INTO tenants (..., jwt_secret, ...)` fixture across `internal/**` — grep
  `jwt_secret` and `jwt_secret_enc` to catch them all; a fixture left naming a
  dropped column fails at insert time, not at compile time
- Docs that describe the column: this file, and the `jwt_secret` references in
  `README.md`, `docs/DEPLOYMENT.md`, and `.env.example`

Then add this as the next migration (`00106_drop_tenant_jwt_secret_columns.sql`).
It is **not** in the repo yet on purpose: goose auto-applies on boot, so committing
it earlier would drop the columns on the very first deploy, while HS256 verification
was still expected to work.

```sql
-- +goose Up
-- +goose StatementBegin

-- Issue #95, Phase 4. Removes the symmetric signing secret entirely. Signing keys
-- have lived in signing_keys since migration 00065; jwt_secret has been
-- verification-only since and unused entirely since JWT_ALLOW_LEGACY_HS256=false,
-- and jwt_secret_enc (00105) holds the only remaining copies of those secrets.
-- Both come out together — dropping jwt_secret alone would leave the real secret
-- behind, which is the asset this phase exists to remove.
--
-- PREREQUISITES (see docs/PHASE4_HS256_CUTOVER.md):
--   1. JWT_ALLOW_LEGACY_HS256=false deployed and stable
--   2. emc_auth_legacy_hs256_verifications_total flat at zero
--   3. pg_dump of the tenants table taken
--   4. Every code reference to either column already removed — the startup sweeps
--      and CreateTenant both touch these columns on the uncleaned binary
--
-- After this, nothing can resolve a tenant's shared secret at all. That is
-- correct — nothing asks for one once legacy HS256 is refused.

ALTER TABLE tenants
    DROP COLUMN IF EXISTS jwt_secret,
    DROP COLUMN IF EXISTS jwt_secret_enc;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Restores the columns but NOT their values: the old secrets are gone, and
-- inventing new ones would not restore any token's verifiability. Restore from
-- the pg_dump taken in prerequisite 3 if the values are genuinely needed — and
-- roll the application back to a release that still reads them, because a binary
-- whose secret code was removed cannot verify with either column present.
--
-- jwt_secret is backfilled with crypto-random-equivalent values so its NOT NULL
-- constraint holds; these sign nothing. jwt_secret_enc stays empty: plaintext is
-- what a rolled-back binary reads.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS jwt_secret TEXT,
    ADD COLUMN IF NOT EXISTS jwt_secret_enc TEXT;
UPDATE tenants SET jwt_secret = encode(gen_random_bytes(32), 'hex') WHERE jwt_secret IS NULL;
ALTER TABLE tenants ALTER COLUMN jwt_secret SET NOT NULL;

-- +goose StatementEnd
```

**Rollback of the release that carries this migration:** run the Down **before**
reverting the binary — a rolled-back binary that still references the columns
cannot boot against the dropped schema (its seed insert fails), let alone run
`CreateTenant`.

Keep `emc_auth_legacy_hs256_verifications_total` for one release after the drop: a
non-zero `rejected` count then means a consumer is still sending symmetric tokens.

### Step 4 — tell consumers to destroy their copies

For every holder found in prerequisite 1: delete the secret from config, secret stores,
CI, and manifests. **Treat it as decommissioning a private key, not rotating a password.**

---

## Verification after cutover

- [ ] A fresh login returns a token with `alg: "RS256"` and a `kid` present in the tenant's JWKS
- [ ] A hand-crafted HS256 token signed with the old secret is refused
- [ ] `emc_auth_legacy_hs256_verifications_total{reason="rejected"}` is not climbing
- [ ] Third-party verification still works (`TestJWKS_ThirdPartyVerificationInSeparateProcess`)
- [ ] `/auth/refresh` still works — refresh tokens are opaque and must be unaffected
- [ ] A rotation drill still passes end to end
- [ ] `go test ./... -p 1 -count=1` green
