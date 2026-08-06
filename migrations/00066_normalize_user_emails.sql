-- +goose Up
-- +goose StatementBegin

-- Email addresses are case-insensitive in practice, but nothing in this schema
-- said so: users.email was plain TEXT, every unique index was on the raw
-- column, and every login/reset/magic-link lookup used a case-sensitive `=`.
--
-- The visible failure: an owner invited as Subham.D@engineersmind.com could not
-- log in as subham.d@engineersmind.com — the lookup simply missed. Worse, the
-- unique indexes permitted BOTH spellings to exist as separate accounts in one
-- tenant, and the OAuth auto-link (which did compare case-insensitively) would
-- then bind an identity to whichever LIMIT 1 happened to return.
--
-- This migration establishes the invariant the code now relies on: every stored
-- address is already lowercase, so exact-match lookups are correct AND can use
-- idx_users_login_covering. Application code normalizes on the way in
-- (internal/emailaddr); the CHECK constraint below is the backstop that turns
-- any future write that forgets into a loud error rather than a silent
-- unreachable account.

-- 1. Refuse to proceed if lowercasing would collide two real accounts.
--
-- A collision means two distinct user rows in the same scope that differ only
-- in casing — genuinely separate accounts today, each with its own
-- credentials, sessions and audit trail. Picking a survivor is a data decision
-- an operator must make, not one a migration should make silently, so this
-- aborts with the offending addresses named.
DO $$
DECLARE
    conflicts TEXT;
BEGIN
    SELECT string_agg(detail, '; ')
    INTO   conflicts
    FROM (
        SELECT tenant_id || '/' || COALESCE(application_id::TEXT, 'tenant-level')
                 || ': ' || string_agg(email, ', ' ORDER BY email) AS detail
        FROM   users
        WHERE  deleted_at IS NULL
        GROUP  BY tenant_id, application_id, lower(email)
        HAVING count(*) > 1
    ) c;

    IF conflicts IS NOT NULL THEN
        RAISE EXCEPTION
            'cannot normalize user emails: case-variant duplicate accounts exist and must be merged or soft-deleted first -> %',
            conflicts;
    END IF;
END
$$;

-- 2. Backfill. Soft-deleted rows are included: they still occupy the partial
-- unique indexes' complement and may be restored later, and leaving them
-- mixed-case would break the CHECK added below.
UPDATE users
SET    email = lower(btrim(email)),
       updated_at = NOW()
WHERE  email <> lower(btrim(email));

-- Pending email changes are compared against users.email on confirmation, so
-- they must be canonical too.
UPDATE email_change_requests
SET    new_email = lower(btrim(new_email))
WHERE  new_email <> lower(btrim(new_email));

-- Federated identities: provider_email is informational, but a mixed-case copy
-- is misleading when reconciling an account against its IdP.
UPDATE user_identities
SET    provider_email = lower(btrim(provider_email))
WHERE  provider_email IS NOT NULL
  AND  provider_email <> lower(btrim(provider_email));

-- 3. Enforce it. NOT VALID would leave the door open for the very rows we just
-- fixed to reappear via an unvalidated path; the table is already clean after
-- step 2, so validate immediately.
ALTER TABLE users
    ADD CONSTRAINT chk_users_email_lowercase
    CHECK (email = lower(email));

-- +goose StatementEnd


-- +goose Down
-- +goose StatementBegin

-- Only the constraint is reversible. The lowercasing is not: the original
-- casing was not retained anywhere, and restoring it is neither possible nor
-- desirable (mixed-case rows are what broke login in the first place).
ALTER TABLE users DROP CONSTRAINT IF EXISTS chk_users_email_lowercase;

-- +goose StatementEnd
