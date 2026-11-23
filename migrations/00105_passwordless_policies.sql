-- +goose Up
-- +goose StatementBegin

-- Passwordless sign-in policy (issue #203, docs/plans/passwordless-email-otp.md).
--
-- A user enters an email address, receives a one-time code and is signed in, or
-- has an account created and is signed in. Password login is untouched and stays
-- the default: an application with no row anywhere in its chain behaves exactly
-- as it did before this migration.
--
-- Scope model and resolution match captcha_policies (00090): NULL/NULL is the
-- platform row, tenant_id set is a tenant row, both set is an application row,
-- and the most specific non-NULL value of each field wins. Every tunable column
-- is nullable because NULL means "inherit". A row therefore records only what an
-- administrator chose to override, and a later change to a parent applies to
-- every scope that never overrode it.
--
-- Platform rows are also CEILINGS: a tenant or application may tighten a limit
-- but not exceed the platform's. That is enforced by the application layer on
-- write, where it can produce a useful error; the CHECKs here are the hard
-- outer bounds only.
--
-- The rule "an application always keeps at least one first factor" cannot be a
-- CHECK once values inherit, so it is enforced on the RESOLVED policy at write
-- time and re-checked at request time, failing safe to password.
--
-- Challenges live in Redis with a TTL. There is deliberately no durable table of
-- codes: nothing here needs to outlive the code, and a table would be a store of
-- credentials to protect and to clean up.
CREATE TABLE IF NOT EXISTS passwordless_policies (
    id                    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id             BIGINT REFERENCES tenants(id) ON DELETE CASCADE,
    application_id        BIGINT REFERENCES oauth_clients(id) ON DELETE CASCADE,

    -- Sign in (and, with signup_enabled, register) by emailed code.
    email_otp_enabled     BOOLEAN,
    -- Create an account on the first verified code. Off until an owner turns it on.
    signup_enabled        BOOLEAN,
    -- false closes the password flow for this scope. Stored hashes are kept and
    -- are never read while it is false; setting it true again re-opens them.
    password_enabled      BOOLEAN,
    -- Sign-up is restricted to these domains when non-empty. Blocked domains are
    -- merged up the chain rather than overridden: a tenant cannot unblock what
    -- the platform blocked.
    allowed_email_domains TEXT[],
    blocked_email_domains TEXT[],

    code_ttl_seconds      INTEGER CHECK (code_ttl_seconds BETWEEN 300 AND 900),
    max_attempts          INTEGER CHECK (max_attempts BETWEEN 3 AND 5),
    max_resends           INTEGER CHECK (max_resends BETWEEN 0 AND 5),
    resend_cooldown_secs  INTEGER CHECK (resend_cooldown_secs BETWEEN 30 AND 300),
    -- Code requests per hour for one email address.
    starts_per_hour       INTEGER CHECK (starts_per_hour BETWEEN 1 AND 10),
    -- Code emails per scope per day. 0 = unlimited.
    daily_email_budget    INTEGER CHECK (daily_email_budget >= 0),
    allow_persistent      BOOLEAN,
    welcome_email_enabled BOOLEAN,

    -- Optimistic concurrency for the console: every PUT carries the version it
    -- read, and a mismatch is a 409 showing the other administrator's change.
    version               INTEGER NOT NULL DEFAULT 1,
    updated_by            BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- An application row names its tenant: the application belongs to one.
    CONSTRAINT passwordless_policies_app_has_tenant
        CHECK (application_id IS NULL OR tenant_id IS NOT NULL),
    -- One row per scope, NULLs included, so the platform row is unique too.
    CONSTRAINT passwordless_policies_scope_key
        UNIQUE NULLS NOT DISTINCT (tenant_id, application_id)
);

-- Append-only record of every change, powering "history and restore". Restore
-- writes a NEW version from an old snapshot; nothing here is ever rewritten.
CREATE TABLE IF NOT EXISTS passwordless_policy_history (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id      BIGINT,
    application_id BIGINT,
    version        INTEGER NOT NULL,
    action         TEXT NOT NULL CHECK (action IN ('create', 'update', 'delete', 'restore')),
    changed_by     BIGINT,
    -- Full snapshot of the row after the change (NULL for delete) and the
    -- field-level before/after, so the console can render a diff without
    -- replaying anything.
    snapshot       JSONB,
    change         JSONB NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_passwordless_policy_history_scope
    ON passwordless_policy_history (tenant_id, application_id, id DESC);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS passwordless_policy_history;
DROP TABLE IF EXISTS passwordless_policies;
-- +goose StatementEnd
