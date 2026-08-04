# Phase 4 cutover runbook — reject HS256, drop `tenants.jwt_secret`

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

The code for this phase **is written and tested** — it is switched off, not missing.

| Piece | Where | State |
|---|---|---|
| `JWT_ALLOW_LEGACY_HS256` env var | `internal/config/config.go` | defaults to `true` |
| Both algorithm pins narrow to RS256 | `internal/auth/jwt.go` — `WithValidMethods` **and** the keyfunc's HMAC branch | active when the flag is `false` |
| Startup warning on cutover | `internal/api/routes.go` | active |
| Rejection counter | `emc_auth_legacy_hs256_verifications_total{reason="rejected"}` | active |
| Test coverage | `TestJWTService_Phase4Cutover` | passing |

So step 2 below is an **env var change and a restart**, not a code change.

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

Required: step 3's migration destroys the column. Keep this until cutover is confirmed
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

```bash
JWT_ALLOW_LEGACY_HS256=false
```

Restart. Confirm at startup:

```
WARN  JWT_ALLOW_LEGACY_HS256=false — HS256 tokens are REJECTED (issue #95 Phase 4 cutover)
```

**Blast radius, honestly:** any access token minted before RS256 went live now fails.
Access and management tokens are 15 minutes, so the window is short, and **refresh tokens
are opaque random strings, not JWTs — they are unaffected**, so a client that refreshes on
401 recovers on its own. The risk is a client that treats a signature failure as "log the
user out" instead of "refresh". That is exactly what the quiet-counter gate in
prerequisite 2 exists to avoid.

**Rollback:** set the flag back to `true` and restart. Instant, no data loss. This is why
step 3 is separate — keep the flag flipped for at least one full business day before
dropping the column.

### Step 3 — drop the column

Only after step 2 has been stable and `..._total{reason="rejected"}` is not climbing.

Add this as the next migration (`00063_drop_tenant_jwt_secret.sql`). It is **not** in the
repo yet on purpose: goose auto-applies on boot, so committing it earlier would drop the
column on the very first deploy, while HS256 verification was still expected to work.

```sql
-- +goose Up
-- +goose StatementBegin

-- Issue #95, Phase 4. Removes the symmetric signing secret. Signing keys have lived
-- in signing_keys since migration 00062; this column has been verification-only
-- since, and unused entirely since JWT_ALLOW_LEGACY_HS256=false.
--
-- PREREQUISITES (see docs/PHASE4_HS256_CUTOVER.md):
--   1. JWT_ALLOW_LEGACY_HS256=false deployed and stable
--   2. emc_auth_legacy_hs256_verifications_total flat at zero
--   3. pg_dump of the tenants table taken
--
-- After this, JWTService.tenantSecret can no longer resolve anything. That is
-- correct — nothing calls it once legacy HS256 is refused.

ALTER TABLE tenants DROP COLUMN IF EXISTS jwt_secret;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Restores the column but NOT its values: the old secrets are gone, and inventing
-- new ones would not restore any token's verifiability. Restore from the pg_dump
-- taken in prerequisite 3 if the values are genuinely needed.
--
-- Backfilled with crypto-random-equivalent values so the NOT NULL constraint holds;
-- these sign nothing.

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS jwt_secret TEXT;
UPDATE tenants SET jwt_secret = encode(gen_random_bytes(32), 'hex') WHERE jwt_secret IS NULL;
ALTER TABLE tenants ALTER COLUMN jwt_secret SET NOT NULL;

-- +goose StatementEnd
```

Then remove the now-dead code:

- `JWTService.tenantSecret` (`internal/auth/jwt.go`)
- `legacyHMACKeyForToken` and the `*jwt.SigningMethodHMAC` case in `VerifyForAudience`
- The `allowLegacyHS256` field, `WithLegacyHS256`, and the `JWT_ALLOW_LEGACY_HS256` config
- `TestJWTService_Phase4Cutover`'s HS256 halves, and the legacy tests in `jwt_test.go`
- The `hs256` rows from `internal/store/seed.go` / `seed_demo.go` tenant inserts

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
