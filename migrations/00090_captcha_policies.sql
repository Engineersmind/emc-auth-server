-- +goose Up
-- +goose StatementBegin

-- Per-scope CAPTCHA policy — issue #145.
--
-- The login surface is already defended by rate limiters (per IP, per account,
-- per client_id, per application) and, since #72, by the three-tier lockout
-- ladder in lockout_policies. Both are throttles: they slow an attacker and
-- eventually lock an account, but neither asks the caller to prove it is a
-- human, and neither does anything at all on /auth/register, where there is no
-- account to count against. A captcha is that missing tier.
--
-- WHAT THIS IS, AND WHAT IT IS NOT
--
-- A self-hosted image CAPTCHA is a speed bump, not a bot defence. Commodity OCR
-- and human solver farms defeat it, and a distributed botnet with one attempt
-- per IP never trips the trigger at all. It is here because it cheaply kills
-- single-host scripted credential stuffing — the overwhelming majority of what
-- actually reaches a login endpoint — and because doing it ourselves keeps user
-- IP addresses out of a third party's hands, which is the whole reason this
-- server exists. It sits ALONGSIDE the limiters and the lockout ladder, never in
-- place of them.
--
-- Resolution is most-specific-wins — application row → tenant row → the
-- platform-default row (both ids NULL, seeded below) — the same shape as
-- session_policies (00068), passkey_policies (00072) and lockout_policies
-- (00086), for the same reason: the fallback lives in the database where an
-- operator can see and change it, rather than being hardcoded in whichever
-- caller happens to look first.
--
-- WHY THE PLATFORM DEFAULT IS 'false'
--
-- Turning a captcha on changes what every user of an application has to do to
-- sign in, and unlike passkeys there is no per-user layer to soften it: a
-- passkey is a credential somebody opts into, a captcha is a gate imposed on a
-- request, including requests from people who have no account yet. A tenant's
-- users are the tenant's to inconvenience, so the feature is off until somebody
-- says otherwise. Setting CAPTCHA_ENABLED is the deployment-level opt-in; a row
-- here is the tenant-level one, and both are required.
--
-- Off-by-default is the safe first release, NOT the intended end state — the
-- tenants most likely to be credential-stuffed are the ones who never open the
-- security page. Once production metrics show a near-zero false-positive rate,
-- a follow-up migration is expected to flip this row to enabled with a high
-- trigger threshold. That is deferred rather than done here because under
-- default-on a bug in the captcha path is a login outage for every tenant
-- rather than for the ones who asked for it.
CREATE TABLE IF NOT EXISTS captcha_policies (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    -- NULL/NULL is the platform default. tenant_id set with application_id NULL
    -- is a tenant policy; both set is an application policy.
    tenant_id      BIGINT REFERENCES tenants(id) ON DELETE CASCADE,
    application_id BIGINT REFERENCES oauth_clients(id) ON DELETE CASCADE,

    -- The master switch. False short-circuits the gate before it does any work,
    -- so a disabled scope costs one cached policy read and nothing else.
    enabled        BOOLEAN NOT NULL DEFAULT false,

    -- Which implementation answers. Only 'internal' is accepted today; the
    -- column exists now so that adding Turnstile or reCAPTCHA later is a CHECK
    -- change and a new code path rather than a migration against a live table.
    provider       TEXT NOT NULL DEFAULT 'internal',

    -- 'adaptive' demands a captcha only after trigger_after_failures failures
    -- from the same origin; 'always' demands one on every attempt.
    --
    -- Adaptive is the default because an always-on captcha taxes the ~99% of
    -- sign-ins that are a person typing their own password correctly, to slow
    -- down the fraction that is not. Setting trigger_after_failures to 1 gives
    -- always-on behaviour without needing the other mode, but 'always' is kept
    -- distinct so the intent is legible in the row.
    mode           TEXT NOT NULL DEFAULT 'adaptive',

    -- Which flows the gate applies to. Named rather than a bitmask so the set is
    -- readable in psql during an incident.
    --
    -- 'session' is the admin console's own sign-in: the console posts to
    -- /auth/session, not /auth/login, so leaving it out would ship a captcha
    -- feature whose administrative front door — holding the super-admin
    -- accounts — is the one door left open. 'login_otp' is where a brute-forcer
    -- moves once the password door is gated.
    protected_flows TEXT[] NOT NULL
        DEFAULT '{login,session,login_otp,register,forgot_password}',

    -- How many failures from one origin inside failure_window_seconds before a
    -- captcha is demanded. Only consulted in 'adaptive' mode.
    trigger_after_failures INTEGER NOT NULL DEFAULT 2,
    failure_window_seconds INTEGER NOT NULL DEFAULT 900,   -- 15 min

    -- Number of characters in the challenge. Six over the 28-character
    -- unambiguous alphabet (see internal/auth/captchaimage.go) is ~4.8e8
    -- combinations, which is far past what matters here: a challenge is
    -- single-use and TTL-bounded, so guessing is bounded by the number of
    -- challenges an attacker can obtain, not by the size of the answer space.
    code_length    INTEGER NOT NULL DEFAULT 6,

    -- Whether the typed answer must match case.
    --
    -- Default false, because case-insensitive is what users expect and what a
    -- mistyped answer should not punish. Setting it true switches the generator
    -- to a different alphabet: only the twelve letters whose lowercase form is a
    -- different SHAPE rather than a smaller one (see captchaglyphs.go), because
    -- the renderer jitters per-glyph scale and a shrunken C is a c. That keeps
    -- case readable at the cost of nine letters, and the answer space is
    -- slightly larger either way.
    case_sensitive BOOLEAN NOT NULL DEFAULT false,

    -- How long a challenge stays solvable. Long enough for somebody who reads
    -- slowly or is interrupted, short enough that a harvested batch of
    -- challenges goes stale faster than a solver farm can work through it.
    ttl_seconds    INTEGER NOT NULL DEFAULT 120,

    -- How many answers one challenge accepts before it is burned.
    --
    -- Default 1. A second attempt on the SAME image is worth very little to a
    -- human — if they misread it once they will likely misread it the same way —
    -- and is worth a great deal to an automated solver, which gets another
    -- sample of the same target for free.
    max_attempts_per_challenge INTEGER NOT NULL DEFAULT 1,

    -- Distortion strength. 'high' is genuinely hard for people, not only for
    -- machines; the admin console renders a live sample beside this field so an
    -- operator cannot set it without seeing what they are about to impose.
    noise_level    TEXT NOT NULL DEFAULT 'medium',

    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- An application policy without a tenant cannot be resolved: resolution
    -- walks app → tenant → default, and application_id alone matches nothing.
    CONSTRAINT captcha_policies_scope_check
        CHECK (application_id IS NULL OR tenant_id IS NOT NULL),

    CONSTRAINT captcha_policies_provider
        CHECK (provider IN ('internal')),
    CONSTRAINT captcha_policies_mode
        CHECK (mode IN ('adaptive', 'always')),
    CONSTRAINT captcha_policies_noise
        CHECK (noise_level IN ('low', 'medium', 'high')),

    -- Bounds, enforced here as well as in Go because this table is reachable by
    -- hand during support work — and a mistyped value here is imposed on a
    -- tenant's entire user base at once.
    CONSTRAINT captcha_policies_trigger_range
        CHECK (trigger_after_failures BETWEEN 1 AND 100),
    CONSTRAINT captcha_policies_window_range
        CHECK (failure_window_seconds BETWEEN 60 AND 86400),      -- 1 min .. 24h
    CONSTRAINT captcha_policies_length_range
        CHECK (code_length BETWEEN 4 AND 8),
    CONSTRAINT captcha_policies_ttl_range
        CHECK (ttl_seconds BETWEEN 30 AND 600),                   -- 30s .. 10 min
    CONSTRAINT captcha_policies_attempts_range
        CHECK (max_attempts_per_challenge BETWEEN 1 AND 5),

    -- An empty flow list with the feature enabled is a policy that says "on" and
    -- does nothing — a silent misconfiguration rather than an error, which is
    -- exactly the kind the database should catch. Disabled scopes may hold an
    -- empty array; nothing reads it.
    CONSTRAINT captcha_policies_flows_not_empty
        CHECK (enabled = false OR cardinality(protected_flows) > 0)
);

-- +goose StatementEnd

-- +goose StatementBegin

-- One policy per scope. Partial unique indexes rather than one index over
-- COALESCE(...): they express the three scopes directly, and because NULLs do
-- not conflict in a plain unique index the platform-default row would otherwise
-- be duplicable — after which resolution would depend on which duplicate the
-- planner returned first.
CREATE UNIQUE INDEX IF NOT EXISTS captcha_policies_platform_default
    ON captcha_policies ((true)) WHERE tenant_id IS NULL AND application_id IS NULL;

-- +goose StatementEnd

-- +goose StatementBegin

CREATE UNIQUE INDEX IF NOT EXISTS captcha_policies_per_tenant
    ON captcha_policies (tenant_id) WHERE application_id IS NULL AND tenant_id IS NOT NULL;

-- +goose StatementEnd

-- +goose StatementBegin

CREATE UNIQUE INDEX IF NOT EXISTS captcha_policies_per_application
    ON captcha_policies (tenant_id, application_id) WHERE application_id IS NOT NULL;

-- +goose StatementEnd

-- +goose StatementBegin

-- Seed the platform default: feature off, and every other value at the setting a
-- tenant switching it on would want. Because enabled is false, this migration
-- changes the behaviour of exactly nothing that is running today.
INSERT INTO captcha_policies
    (tenant_id, application_id, enabled, provider, mode, protected_flows,
     trigger_after_failures, failure_window_seconds, code_length, case_sensitive,
     ttl_seconds, max_attempts_per_challenge, noise_level)
VALUES (NULL, NULL, false, 'internal', 'adaptive',
        '{login,session,login_otp,register,forgot_password}',
        2, 900, 6, false, 120, 1, 'medium')
ON CONFLICT DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS captcha_policies_per_application;
DROP INDEX IF EXISTS captcha_policies_per_tenant;
DROP INDEX IF EXISTS captcha_policies_platform_default;
DROP TABLE IF EXISTS captcha_policies;

-- +goose StatementEnd
