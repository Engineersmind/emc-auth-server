-- +goose Up
-- +goose StatementBegin

-- Per-tenant session lifetime policy.
--
-- Until now session lifetime was a single Go constant (RefreshTokenTTL = 30
-- days) applied to every tenant, with no idle clock at all. That is the wrong
-- shape for a multi-tenant IdP: a bank and a consumer app need different
-- numbers, and Auth0/Okta/Entra all expose these as per-tenant policy for
-- exactly that reason.
--
-- Resolution is most-specific-wins: application row → tenant row → the platform
-- default row (both ids NULL, seeded below). The platform default exists so
-- resolution can never come up empty and force the caller to hardcode a
-- fallback — the fallback lives in one place, in the database, where an operator
-- can see and change it.
CREATE TABLE IF NOT EXISTS session_policies (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    -- NULL/NULL is the platform default. tenant_id set with application_id NULL
    -- is a tenant policy; both set is an application policy.
    tenant_id      BIGINT REFERENCES tenants(id) ON DELETE CASCADE,
    application_id BIGINT REFERENCES oauth_clients(id) ON DELETE CASCADE,

    -- Idle clock for a persistent ("remember me") session: how long a session
    -- may go without a successful refresh before it dies. This is the setting
    -- that actually bounds session-list growth — without it, every login that is
    -- never explicitly logged out stays listed for the full absolute lifetime.
    idle_ttl_seconds                 INTEGER NOT NULL DEFAULT 604800,   -- 7 days

    -- Idle clock for a non-persistent session (the user did not ask to be
    -- remembered — typically a shared or public machine). Deliberately much
    -- shorter; Entra ID draws the same distinction.
    non_persistent_idle_ttl_seconds  INTEGER NOT NULL DEFAULT 86400,    -- 24 hours

    -- Absolute cap, measured from the session's FIRST authentication and never
    -- extended by a refresh. This is what stops a session that refreshes daily
    -- from living forever — the classic sliding-window bug.
    absolute_ttl_seconds             INTEGER NOT NULL DEFAULT 2592000,  -- 30 days

    -- Hard ceiling on concurrent live sessions per user; the oldest is evicted
    -- when a new login would exceed it. A backstop, not the primary control: it
    -- keeps the session list usable even if an idle-clock regression ships.
    max_concurrent_sessions          INTEGER NOT NULL DEFAULT 20,

    -- When false, "remember me" is refused and every session uses the
    -- non-persistent idle clock, whatever the client asked for.
    allow_persistent                 BOOLEAN NOT NULL DEFAULT true,

    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- An application policy without a tenant is meaningless: application_id
    -- alone cannot be resolved, since resolution walks app → tenant → default.
    CONSTRAINT session_policies_scope_check
        CHECK (application_id IS NULL OR tenant_id IS NOT NULL),

    -- Bounds. The upper limits are deliberate: a 10-year refresh token is not a
    -- session, and an operator who sets one has made a mistake the database
    -- should catch rather than honour. Enforced here as well as in Go because
    -- the table is also reachable by hand during incident response.
    CONSTRAINT session_policies_idle_positive
        CHECK (idle_ttl_seconds BETWEEN 60 AND 7776000),                -- 1 min .. 90 days
    CONSTRAINT session_policies_np_idle_positive
        CHECK (non_persistent_idle_ttl_seconds BETWEEN 60 AND 7776000),
    CONSTRAINT session_policies_absolute_positive
        CHECK (absolute_ttl_seconds BETWEEN 300 AND 7776000),           -- 5 min .. 90 days
    CONSTRAINT session_policies_max_sessions_positive
        CHECK (max_concurrent_sessions BETWEEN 1 AND 1000),

    -- An idle clock longer than the absolute cap can never fire, which would
    -- silently reinstate the pre-policy behaviour the idle clock exists to fix.
    CONSTRAINT session_policies_idle_within_absolute
        CHECK (idle_ttl_seconds <= absolute_ttl_seconds
           AND non_persistent_idle_ttl_seconds <= absolute_ttl_seconds)
);

-- +goose StatementEnd

-- +goose StatementBegin

-- One policy per scope. Partial unique indexes rather than a single index over
-- COALESCE(...): they express the three distinct scopes directly, and NULLs in a
-- plain unique index do not conflict, so the platform-default row would
-- otherwise be duplicable.
CREATE UNIQUE INDEX IF NOT EXISTS session_policies_platform_default
    ON session_policies ((true)) WHERE tenant_id IS NULL AND application_id IS NULL;

-- +goose StatementEnd

-- +goose StatementBegin

CREATE UNIQUE INDEX IF NOT EXISTS session_policies_per_tenant
    ON session_policies (tenant_id) WHERE application_id IS NULL AND tenant_id IS NOT NULL;

-- +goose StatementEnd

-- +goose StatementBegin

CREATE UNIQUE INDEX IF NOT EXISTS session_policies_per_application
    ON session_policies (tenant_id, application_id) WHERE application_id IS NOT NULL;

-- +goose StatementEnd

-- +goose StatementBegin

-- Seed the platform default.
--
-- absolute_ttl_seconds matches the historical RefreshTokenTTL (30 days) so this
-- migration does not, by itself, shorten any live session. The idle clock is the
-- behavioural change, and 7 days is deliberately generous for a first deploy:
-- tighten it from the admin API once the metrics show what real usage looks
-- like, rather than expiring a month of accumulated sessions on deploy day.
INSERT INTO session_policies
    (tenant_id, application_id, idle_ttl_seconds, non_persistent_idle_ttl_seconds,
     absolute_ttl_seconds, max_concurrent_sessions, allow_persistent)
VALUES (NULL, NULL, 604800, 86400, 2592000, 20, true)
ON CONFLICT DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS session_policies_per_application;
DROP INDEX IF EXISTS session_policies_per_tenant;
DROP INDEX IF EXISTS session_policies_platform_default;
DROP TABLE IF EXISTS session_policies;

-- +goose StatementEnd
