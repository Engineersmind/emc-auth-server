-- +goose Up
-- +goose StatementBegin

-- Per-tenant account-lockout policy (issue #72).
--
-- Until now lockout was a single pair of Go constants (MaxFailedLogins = 10,
-- FailedLoginWindow = 15m) applied to every tenant, with exactly one tier: ten
-- failures disabled the account permanently. Two problems with that shape:
--
--   1. One tier is too blunt. Five wrong passwords is well inside normal human
--      behaviour (stale password manager entry, Caps Lock, an old password), so
--      the only control available was the most severe one. Auth0, Okta and Entra
--      all escalate — delay, then temporary lock, then disable — for that reason.
--
--   2. A permanent lock reachable in ten unauthenticated requests is a denial of
--      service primitive. Anyone who knows an email address could disable that
--      account until an operator intervened. NIST SP 800-63B §5.2.2 recommends a
--      time-based automatic unlock precisely to close this; hard_lock_duration_seconds
--      below is that unlock, and it defaults to on.
--
-- Resolution is most-specific-wins: application row → tenant row → the platform
-- default row (both ids NULL, seeded at the bottom), matching session_policies
-- (migration 00067). The platform default exists so resolution can never come up
-- empty and force the caller to hardcode a fallback.
CREATE TABLE IF NOT EXISTS lockout_policies (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    -- NULL/NULL is the platform default. tenant_id set with application_id NULL
    -- is a tenant policy; both set is an application policy.
    tenant_id      BIGINT REFERENCES tenants(id) ON DELETE CASCADE,
    application_id BIGINT REFERENCES oauth_clients(id) ON DELETE CASCADE,

    -- Tier 1: warn the account owner. Emails the USER (never an administrator —
    -- see internal/auth/lockout_notify.go for why staff notification is
    -- aggregated instead) once per window, so a victim learns about an attack
    -- while it is still in progress rather than after they are locked out.
    -- 0 disables the tier.
    notify_user_threshold            INTEGER NOT NULL DEFAULT 3,

    -- Tier 2: soft lock. Refuses authentication for soft_lock_duration_seconds
    -- WITHOUT touching account state — held in Redis, self-healing on expiry.
    -- This is the tier that keeps ordinary password trouble off the support
    -- queue: it costs an attacker real time but costs a fumbling user nothing
    -- except a wait.
    soft_lock_threshold              INTEGER NOT NULL DEFAULT 5,
    soft_lock_duration_seconds       INTEGER NOT NULL DEFAULT 900,      -- 15 min

    -- Tier 3: hard lock. Disables the account, bumps token_version, revokes
    -- refresh tokens and denies live sessions.
    hard_lock_threshold              INTEGER NOT NULL DEFAULT 10,

    -- How long a hard lock lasts before the account admits logins again.
    --
    -- NULL means "until an administrator acts" — the pre-#72 behaviour, kept
    -- available because a high-assurance tenant may genuinely want it. It is NOT
    -- the default: see the DoS reasoning at the top of this file. Only automatic
    -- locks expire; an administrator's block carries block_reason = 'admin' and
    -- is never lifted by the clock.
    hard_lock_duration_seconds       INTEGER DEFAULT 1800,              -- 30 min

    -- How long a failed attempt counts toward the thresholds above. A user who
    -- mistypes twice today and once next week is never locked out.
    failure_window_seconds           INTEGER NOT NULL DEFAULT 900,      -- 15 min

    -- How many DISTINCT accounts must hard-lock inside failure_window_seconds
    -- before the tenant's owner and affected co-owners are emailed once about a
    -- suspected attack. Per-account locks deliberately do not email staff: at
    -- credential-stuffing volume that turns this server into a mail flood aimed
    -- at its own operators, and it trains them to filter the alert that matters.
    -- 0 disables the alert.
    tenant_spike_threshold           INTEGER NOT NULL DEFAULT 10,

    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- An application policy without a tenant is meaningless: application_id
    -- alone cannot be resolved, since resolution walks app → tenant → default.
    CONSTRAINT lockout_policies_scope_check
        CHECK (application_id IS NULL OR tenant_id IS NOT NULL),

    -- Bounds. Enforced here as well as in Go because the table is reachable by
    -- hand during incident response, and a mistyped threshold here locks out a
    -- tenant's entire user base.
    CONSTRAINT lockout_policies_notify_range
        CHECK (notify_user_threshold BETWEEN 0 AND 1000),
    CONSTRAINT lockout_policies_soft_range
        CHECK (soft_lock_threshold BETWEEN 1 AND 1000),
    CONSTRAINT lockout_policies_hard_range
        CHECK (hard_lock_threshold BETWEEN 1 AND 1000),
    CONSTRAINT lockout_policies_soft_duration_range
        CHECK (soft_lock_duration_seconds BETWEEN 30 AND 86400),        -- 30s .. 24h
    CONSTRAINT lockout_policies_hard_duration_range
        CHECK (hard_lock_duration_seconds IS NULL
               OR hard_lock_duration_seconds BETWEEN 60 AND 2592000),   -- 1 min .. 30 days
    CONSTRAINT lockout_policies_window_range
        CHECK (failure_window_seconds BETWEEN 60 AND 86400),
    CONSTRAINT lockout_policies_spike_range
        CHECK (tenant_spike_threshold BETWEEN 0 AND 100000),

    -- The tiers must escalate. A soft threshold at or above the hard one makes
    -- the soft tier unreachable (the account is disabled before it can fire),
    -- and a notify threshold above the soft one warns the user only after they
    -- are already locked out — both are silent misconfigurations rather than
    -- errors, which is exactly the kind the database should catch.
    CONSTRAINT lockout_policies_tiers_escalate
        CHECK (soft_lock_threshold < hard_lock_threshold
           AND (notify_user_threshold = 0 OR notify_user_threshold <= soft_lock_threshold))
);

-- +goose StatementEnd

-- +goose StatementBegin

-- One policy per scope. Partial unique indexes rather than a single index over
-- COALESCE(...): they express the three distinct scopes directly, and NULLs in a
-- plain unique index do not conflict, so the platform-default row would
-- otherwise be duplicable.
CREATE UNIQUE INDEX IF NOT EXISTS lockout_policies_platform_default
    ON lockout_policies ((true)) WHERE tenant_id IS NULL AND application_id IS NULL;

-- +goose StatementEnd

-- +goose StatementBegin

CREATE UNIQUE INDEX IF NOT EXISTS lockout_policies_per_tenant
    ON lockout_policies (tenant_id) WHERE application_id IS NULL AND tenant_id IS NOT NULL;

-- +goose StatementEnd

-- +goose StatementBegin

CREATE UNIQUE INDEX IF NOT EXISTS lockout_policies_per_application
    ON lockout_policies (tenant_id, application_id) WHERE application_id IS NOT NULL;

-- +goose StatementEnd

-- +goose StatementBegin

-- Supports the auto-expiry predicate on the login candidate query: it scans only
-- accounts an automatic lock is holding down, which is a small set even in a
-- large tenant, instead of testing blocked_at on every matching email row.
CREATE INDEX IF NOT EXISTS idx_users_auto_locked
    ON users (tenant_id, blocked_at)
    WHERE block_reason = 'failed_attempts' AND is_active = false AND deleted_at IS NULL;

-- +goose StatementEnd

-- +goose StatementBegin

-- Seed the platform default.
--
-- hard_lock_threshold matches the historical MaxFailedLogins (10) so this
-- migration does not, by itself, lock anybody out sooner than before. The two
-- behavioural changes are the new soft tier at 5 (which previously did not
-- exist) and hard_lock_duration_seconds (which makes an existing permanent lock
-- expire after 30 minutes) — both strictly reduce how long a legitimate user is
-- kept out, so the migration is safe to deploy without a coordinated release.
INSERT INTO lockout_policies
    (tenant_id, application_id, notify_user_threshold,
     soft_lock_threshold, soft_lock_duration_seconds,
     hard_lock_threshold, hard_lock_duration_seconds,
     failure_window_seconds, tenant_spike_threshold)
VALUES (NULL, NULL, 3, 5, 900, 10, 1800, 900, 10)
ON CONFLICT DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_users_auto_locked;
DROP INDEX IF EXISTS lockout_policies_per_application;
DROP INDEX IF EXISTS lockout_policies_per_tenant;
DROP INDEX IF EXISTS lockout_policies_platform_default;
DROP TABLE IF EXISTS lockout_policies;

-- +goose StatementEnd
