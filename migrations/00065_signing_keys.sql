-- +goose Up
-- +goose StatementBegin

-- Asymmetric JWT signing keys (issue #95, Phase 2). Supersedes ADR-01's HS256
-- choice: HS256 is symmetric, so the ability to VERIFY a token is the ability to
-- FORGE one. A tenant wanting to validate our tokens in its own service had to be
-- handed tenants.jwt_secret, which is signing authority for that whole tenant.
-- With RSA the private key never leaves this server and verifiers get only the
-- public half.
--
-- NOTE: this ALTERs rather than CREATEs. Migration 00033 already created
-- signing_keys — in anticipation of exactly this feature — but no Go code ever
-- read or wrote it (verified by repo-wide grep). Issue #95 was written on the
-- assumption that the table did not exist and specified a fresh CREATE; doing that
-- would have silently no-op'd against the existing table under IF NOT EXISTS and
-- left the new columns missing. So this migration adapts what is there instead.
--
-- Inherited from 00033 and kept: per-tenant scope (tenant_id NOT NULL — which
-- matches the key-scope decision for this issue, keeping tenant isolation
-- cryptographic rather than dependent on every consumer checking a claim),
-- kid, algorithm, public_key, private_key_enc, and soft-delete columns.

-- Rotation needs to know when a key started and stopped signing: the retired
-- window is what keeps tokens minted before a rotation verifiable, and it is
-- measured from retired_at.
ALTER TABLE signing_keys
    ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS retired_at   TIMESTAMPTZ;

-- Backfill: 00033's rows (if any deployment has them) carry no activation time.
UPDATE signing_keys SET activated_at = created_at
 WHERE status = 'active' AND activated_at IS NULL;

-- Replace the status vocabulary. 00033 allowed ('active','retiring','retired');
-- 'next' is the state this feature actually needs and 'retiring' was never
-- written by any code. 'next' means generated and PUBLISHED in JWKS but not yet
-- signing — publishing before first use is what makes rotation zero-downtime,
-- because verifiers cache JWKS and would otherwise reject a new key's first token
-- until they refetched.
ALTER TABLE signing_keys DROP CONSTRAINT IF EXISTS signing_keys_status_check;
ALTER TABLE signing_keys
    ADD CONSTRAINT signing_keys_status_check
    CHECK (status IN ('next', 'active', 'retired'));

-- +goose StatementEnd

-- +goose StatementBegin

-- At most one ACTIVE key per tenant. 00033's idx_signing_keys_tenant_active was
-- non-unique, which would let rotation leave two active keys and make "which key
-- signs now" ambiguous — a split-brain state where tokens verify inconsistently.
CREATE UNIQUE INDEX IF NOT EXISTS signing_keys_one_active_per_tenant
    ON signing_keys (tenant_id)
    WHERE status = 'active' AND deleted_at IS NULL;

-- +goose StatementEnd

-- +goose StatementBegin

-- Same for 'next': rotation promotes "the" pending key, so there must be exactly
-- one candidate.
CREATE UNIQUE INDEX IF NOT EXISTS signing_keys_one_next_per_tenant
    ON signing_keys (tenant_id)
    WHERE status = 'next' AND deleted_at IS NULL;

-- +goose StatementEnd

-- +goose StatementBegin

-- Serves the JWKS endpoint: every publishable key for one tenant.
CREATE INDEX IF NOT EXISTS signing_keys_tenant_status_idx
    ON signing_keys (tenant_id, status)
    WHERE deleted_at IS NULL;

-- +goose StatementEnd

-- +goose StatementBegin

-- Serves retired-key garbage collection.
CREATE INDEX IF NOT EXISTS signing_keys_retired_at_idx
    ON signing_keys (retired_at)
    WHERE status = 'retired';

-- +goose StatementEnd

-- +goose StatementBegin

-- Now redundant: superseded by the unique variant above, and keeping both means
-- paying write cost for two indexes covering the same predicate.
DROP INDEX IF EXISTS idx_signing_keys_tenant_active;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Reverts to 00033's shape. Does NOT drop the table — 00033 owns it.
--
-- WARNING: destructive in effect. Dropping activated_at/retired_at destroys the
-- rotation state, so retired keys can no longer be aged out and the server loses
-- track of which key is which generation. Any token signed by a key this leaves
-- behind still verifies only if that key is still 'active'. Only safe while HS256
-- signing is still accepted (i.e. before the Phase 4 cutover) and after a backup.

CREATE INDEX IF NOT EXISTS idx_signing_keys_tenant_active
    ON signing_keys (tenant_id)
    WHERE status = 'active' AND deleted_at IS NULL;

DROP INDEX IF EXISTS signing_keys_retired_at_idx;
DROP INDEX IF EXISTS signing_keys_tenant_status_idx;
DROP INDEX IF EXISTS signing_keys_one_next_per_tenant;
DROP INDEX IF EXISTS signing_keys_one_active_per_tenant;

-- Any 'next' row violates 00033's CHECK, so retire it before restoring the
-- constraint rather than letting the ALTER fail.
UPDATE signing_keys SET status = 'retired' WHERE status = 'next';

ALTER TABLE signing_keys DROP CONSTRAINT IF EXISTS signing_keys_status_check;
ALTER TABLE signing_keys
    ADD CONSTRAINT signing_keys_status_check
    CHECK (status IN ('active', 'retiring', 'retired'));

ALTER TABLE signing_keys
    DROP COLUMN IF EXISTS retired_at,
    DROP COLUMN IF EXISTS activated_at;

-- +goose StatementEnd
