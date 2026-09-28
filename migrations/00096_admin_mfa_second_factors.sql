-- +goose Up
-- +goose StatementBegin

-- Administrator second factors are the authenticator app (TOTP) and email.
--
-- Earlier drafts of 00094 also listed 'passkey' as a second factor. A passkey
-- is now a sign-in method only — with user verification it is already two
-- factors, so a passkey sign-in needs no second step. This brings any database
-- that ran those drafts to the final shape; on a fresh database 00094 already
-- creates it and every statement below is a no-op.

-- In one statement: removing 'passkey' from a policy that listed nothing else
-- would leave it empty, which the non-empty CHECK refuses mid-update. Such a
-- policy gets both second factors instead. Every other selection is kept as the
-- operator set it.
UPDATE admin_mfa_policies
SET allowed_methods = CASE
        WHEN cardinality(array_remove(allowed_methods, 'passkey')) = 0 THEN '{totp,email}'::TEXT[]
        ELSE array_remove(allowed_methods, 'passkey')
    END,
    updated_at = NOW()
WHERE 'passkey' = ANY (allowed_methods);

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
