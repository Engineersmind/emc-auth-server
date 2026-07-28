-- +goose Up
-- +goose StatementBegin

-- Per-account brute-force lockout state (issue #72).
--
-- Deliberately a SEPARATE column from is_active rather than reusing it:
--   * is_active is an ADMIN decision — "this person may not sign in".
--   * locked_until is a SECURITY REFLEX — set by the server after repeated
--     failed logins and cleared automatically once the window elapses.
--
-- Overloading is_active would (a) make "an admin blocked them" indistinguishable
-- from "the brute-force guard tripped", and (b) hand anyone who knows a victim's
-- email a permanent, admin-intervention-only denial of service against that
-- account. A self-expiring timestamp keeps the lock temporary (no admin toil)
-- while still surviving a Redis restart — the failure COUNTER itself lives in
-- Redis and is intentionally ephemeral, but the lock decision must not be.
--
-- locked_reason is a short machine-readable tag (e.g. 'brute_force') so the
-- admin UI can explain the badge without consulting audit_logs.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS locked_until  TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS locked_reason TEXT;

-- Partial index: only currently-locked rows are ever indexed, so this stays
-- tiny no matter how large users grows. Serves the admin "locked accounts"
-- listing; the login path finds the row by email and reads the column directly.
CREATE INDEX IF NOT EXISTS idx_users_locked_until
    ON users (locked_until)
    WHERE locked_until IS NOT NULL;

COMMENT ON COLUMN users.locked_until IS
    'Brute-force lockout expiry (issue #72). NULL or past = not locked. Distinct from is_active, which is an administrative block.';
COMMENT ON COLUMN users.locked_reason IS
    'Short tag for why the account was locked, e.g. brute_force. NULL when never locked.';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_users_locked_until;

ALTER TABLE users
    DROP COLUMN IF EXISTS locked_until,
    DROP COLUMN IF EXISTS locked_reason;

-- +goose StatementEnd
