-- +goose Up
-- +goose StatementBegin

-- Bind sessions, authorization codes and audit events to an organisation.
--
-- Every column here is NULLABLE WITH NO DEFAULT, which PostgreSQL adds as a
-- catalogue change only: no table rewrite, no long lock on user_sessions or
-- audit_logs. NULL means "no organisation" and is what every existing row, and
-- every row written by an instance still running the previous release during a
-- rolling deploy, carries. The new code treats NULL exactly as the old code
-- treated the absence of the column.

-- The organisation is a property of the SESSION, decided once at sign-in, like
-- auth_time and amr. Refresh rotation reads it from here and re-validates the
-- membership; switching organisation creates a new session rather than mutating
-- this one.
--
-- ON DELETE CASCADE, not SET NULL: nulling the column would silently turn an
-- organisation session into an organisation-less one, which in 'optional' mode
-- is a different authority. An organisation is soft-deleted in practice; a hard
-- delete only happens when its application is deleted, and the sessions go with
-- it then anyway.
ALTER TABLE user_sessions
    ADD COLUMN IF NOT EXISTS organization_id BIGINT
    REFERENCES organizations(id) ON DELETE CASCADE;

COMMENT ON COLUMN user_sessions.organization_id IS
    'Organisation this session was signed in to (00103). NULL = no organisation — every pre-existing session.';

-- The hosted /oauth/authorize flow resolves the organisation before issuing a
-- code; the code carries it to /oauth/token so the exchange cannot pick another.
ALTER TABLE oauth_authorization_codes
    ADD COLUMN IF NOT EXISTS organization_id BIGINT
    REFERENCES organizations(id) ON DELETE CASCADE;

-- No foreign key on the audit table: audit rows are immutable (00056) and must
-- outlive the organisation they describe.
ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS organization_id BIGINT;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE audit_logs DROP COLUMN IF EXISTS organization_id;
ALTER TABLE oauth_authorization_codes DROP COLUMN IF EXISTS organization_id;
ALTER TABLE user_sessions DROP COLUMN IF EXISTS organization_id;
-- +goose StatementEnd
