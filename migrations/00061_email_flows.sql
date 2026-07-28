-- +goose Up
-- +goose StatementBegin

-- Backing tables for the transactional email flows that previously had a
-- template but no trigger: user invitations, self-service email change, and
-- account blocking (automatic lockout + admin block + risk alert).
--
-- Every token table follows the established pattern (password_reset_tokens,
-- email_verification_tokens): only the SHA-256 hash is stored, the raw token is
-- emailed and never persisted, and single use is enforced via used_at.

-- Invitations: an admin-created account that has not yet been claimed. Accepting
-- an invitation sets the user's password and marks the address verified.
CREATE TABLE IF NOT EXISTS user_invitations (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    invited_by  BIGINT REFERENCES users(id) ON DELETE SET NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS user_invitations_user_idx ON user_invitations (user_id);

-- Email change: the NEW address is held here (not on users) until it is proven,
-- so an unconfirmed request can never lock the user out of their real address.
CREATE TABLE IF NOT EXISTS email_change_requests (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    new_email   TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS email_change_requests_user_idx ON email_change_requests (user_id);

-- Unblock tokens are issued ONLY for automatic (failed-attempt) blocks. An
-- admin block deliberately has no self-service unblock path.
CREATE TABLE IF NOT EXISTS account_unblock_tokens (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS account_unblock_tokens_user_idx ON account_unblock_tokens (user_id);

-- Brute-force lockout state. failed_login_attempts is reset on any successful
-- sign-in and on an admin unblock; blocked_at/block_reason record why is_active
-- was cleared, so an automatic lockout is distinguishable from an admin block.
-- breach_notified_at records that the password-breach warning has been sent for
-- the CURRENT password, so a user who keeps a breached password is warned once
-- rather than on every sign-in. It is cleared whenever the password changes.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS failed_login_attempts INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_failed_login_at  TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS blocked_at            TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS block_reason          TEXT,
    ADD COLUMN IF NOT EXISTS breach_notified_at    TIMESTAMPTZ;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE users
    DROP COLUMN IF EXISTS failed_login_attempts,
    DROP COLUMN IF EXISTS last_failed_login_at,
    DROP COLUMN IF EXISTS blocked_at,
    DROP COLUMN IF EXISTS block_reason,
    DROP COLUMN IF EXISTS breach_notified_at;

DROP TABLE IF EXISTS account_unblock_tokens;
DROP TABLE IF EXISTS email_change_requests;
DROP TABLE IF EXISTS user_invitations;

-- +goose StatementEnd
