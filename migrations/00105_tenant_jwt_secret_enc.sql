-- +goose Up
-- +goose StatementBegin

-- Encrypt tenants.jwt_secret at rest — GHSA-4x5m-3gph-938r (M-02).
--
-- jwt_secret is HS256 signing authority for the whole tenant. Stored plaintext,
-- any read of the table (backup, replica, SQLi, SELECT * in a log) hands over
-- the ability to mint tokens for any user in that tenant. This column holds
-- the AES-256-GCM envelope instead; application code decrypts with
-- JWT_SIGNING_KEY_ENCRYPTION_KEY — the same SecretBox that already protects
-- signing_keys.private_key_enc, because a leaked symmetric secret IS signing
-- authority, the same asset class.
--
-- ADDITIVE and lazily populated: jwt_secret stays populated so a rollback never
-- strands a deployment, and existing rows keep their plaintext until the
-- startup backfill (JWTService.EncryptAllTenantSecrets) encrypts them and
-- blanks the plaintext column. New writes store '' in jwt_secret and the real
-- value in jwt_secret_enc.
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS jwt_secret_enc TEXT;

COMMENT ON COLUMN tenants.jwt_secret_enc IS
    'AES-256-GCM envelope of the tenant HS256 secret (JWT_SIGNING_KEY_ENCRYPTION_KEY). jwt_secret is legacy plaintext, blanked once encrypted.';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Dropping the column strands tenants whose plaintext was already blanked by
-- the backfill — their secret then exists nowhere the rolled-back binary can
-- read. A real rollback must therefore restore from a pre-migration backup;
-- this Down only documents that and leaves the schema alone.
SELECT 1;

-- +goose StatementEnd
