-- +goose Up
-- +goose StatementBegin

-- Administrator second factors are the authenticator app (TOTP) and email.
--
-- Earlier drafts of 00094 also listed 'passkey' as a second factor. A passkey
-- is now a sign-in method only — with user verification it is already two
-- factors, so a passkey sign-in needs no second step. This brings any database
-- that ran those drafts to the final shape; on a fresh database 00094 already
-- creates it and every statement below is a no-op.

UPDATE admin_mfa_policies
SET allowed_methods = array_remove(allowed_methods, 'passkey'), updated_at = NOW()
WHERE 'passkey' = ANY (allowed_methods);

-- A policy that listed only passkeys would now allow nothing, which the
-- requirement cannot survive. Give it both second factors.
UPDATE admin_mfa_policies
SET allowed_methods = '{totp,email}', updated_at = NOW()
WHERE cardinality(allowed_methods) = 0;

-- The platform default is both second factors, so an administrator always has
-- a fallback when one is not to hand.
UPDATE admin_mfa_policies
SET allowed_methods = '{totp,email}', updated_at = NOW()
WHERE tenant_id IS NULL;

INSERT INTO admin_mfa_policies (tenant_id, allowed_methods)
SELECT NULL, '{totp,email}'
WHERE NOT EXISTS (SELECT 1 FROM admin_mfa_policies WHERE tenant_id IS NULL);

ALTER TABLE admin_mfa_policies
    ALTER COLUMN allowed_methods SET DEFAULT '{totp,email}';
ALTER TABLE admin_mfa_policies
    DROP CONSTRAINT IF EXISTS admin_mfa_policies_methods_valid;
ALTER TABLE admin_mfa_policies
    ADD CONSTRAINT admin_mfa_policies_methods_valid
    CHECK (allowed_methods <@ ARRAY['totp', 'email']::TEXT[]);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Nothing to undo: 'passkey' is no longer a second factor the server can run.
SELECT 1;
-- +goose StatementEnd
