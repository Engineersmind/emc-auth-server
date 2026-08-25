-- +goose Up
-- +goose StatementBegin

-- Per-scope passkey (WebAuthn) policy — issue #112.
--
-- Until now the relying-party configuration was read from server environment
-- variables alone (WEBAUTHN_RP_ID, WEBAUTHN_ORIGINS, WEBAUTHN_REQUIRE_UV), so
-- one deployment served exactly one relying party and no tenant could enable,
-- disable, or scope the feature. That is fine for a spike and wrong for a
-- multi-tenant IdP: the RP ID is the registrable domain of the page running the
-- ceremony, and every tenant application has its own.
--
-- Resolution is most-specific-wins — application row → tenant row → the
-- platform-default row (both ids NULL, seeded below) — the same shape as
-- session_policies (00068), for the same reason: the fallback lives in the
-- database where an operator can see and change it, rather than being hardcoded
-- in whichever caller happens to look first.
--
-- WHY THE PLATFORM DEFAULT IS 'false'
--
-- A passkey sign-in deliberately does not consult the MFA gate: a verified
-- passkey with a user-verification gesture already is two factors, so
-- challenging again would ask the user to prove the same thing twice. The
-- consequence is that enabling passkeys changes the effective authentication
-- policy of an application — a tenant that mandates TOTP would find its users
-- signing in with one gesture and no TOTP at all. That is a decision only the
-- tenant can make, so the feature is off until somebody says otherwise. Setting
-- WEBAUTHN_RP_ID is the deployment-level opt-in; a row here is the tenant-level
-- one, and both are required.
CREATE TABLE IF NOT EXISTS passkey_policies (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    -- NULL/NULL is the platform default. tenant_id set with application_id NULL
    -- is a tenant policy; both set is an application policy.
    tenant_id      BIGINT REFERENCES tenants(id) ON DELETE CASCADE,
    application_id BIGINT REFERENCES oauth_clients(id) ON DELETE CASCADE,

    -- The master switch. False refuses both registration and passkey sign-in
    -- with a distinguishable error code, so a user is told the feature is off
    -- rather than being handed a generic authentication failure.
    allow_passkeys            BOOLEAN NOT NULL DEFAULT false,

    -- Whether a passkey alone may complete a sign-in. Separate from
    -- allow_passkeys on purpose: a tenant may want passkeys as a second factor
    -- (registration allowed) while still requiring a password first. With this
    -- false, registration and credential management work and the passwordless
    -- login endpoints refuse.
    allow_passwordless        BOOLEAN NOT NULL DEFAULT true,

    -- Enforce a biometric/PIN gesture. Default true, and lowering it is a real
    -- downgrade: with no password in a passwordless flow the gesture is the only
    -- evidence the right human is present, and an assertion without it makes
    -- this weaker than a password. Exists for deployments that must support
    -- older security keys with no UV capability.
    require_user_verification BOOLEAN NOT NULL DEFAULT true,

    -- The relying-party ID: the registrable domain of the page running the
    -- ceremony ("insurance.acme.com"), no scheme and no port. NULL inherits the
    -- server's WEBAUTHN_RP_ID.
    --
    -- This is the field that makes the table more than a set of switches. A
    -- credential is bound to an RP ID by the browser, so two tenants on
    -- different domains are two different relying parties and their credentials
    -- are not interchangeable — which is exactly the isolation we want, and
    -- exactly what a single server-wide RP ID cannot express.
    rp_id                     TEXT,

    -- What the authenticator shows the user when it asks whether to create a
    -- passkey. The user sees this string in their password manager effectively
    -- forever, so it belongs to the tenant, not to the platform. NULL inherits
    -- the server's WEBAUTHN_RP_DISPLAY_NAME.
    rp_display_name           TEXT,

    -- Exact-match allow-list of page origins permitted to run a ceremony,
    -- INCLUDING scheme and port ("https://insurance.acme.com"). Empty inherits
    -- the server's WEBAUTHN_ORIGINS.
    --
    -- Distinct from tenant CORS origins by design: CORS decides who may read our
    -- responses, this decides who may mint credentials against our relying
    -- party. Conflating them would let any origin a tenant allowed for API reads
    -- also create passkeys.
    origins                   TEXT[] NOT NULL DEFAULT '{}',

    -- Ceiling on live credentials per user, so a compromised session cannot
    -- quietly enrol an unbounded number of authenticators the user will never
    -- look at. 10 is generous for a real person (phone, laptop, tablet, a
    -- hardware key or two) and small enough that the list stays reviewable.
    max_credentials_per_user  INTEGER NOT NULL DEFAULT 10,

    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- An application policy without a tenant cannot be resolved: resolution
    -- walks app → tenant → default, and application_id alone matches nothing.
    CONSTRAINT passkey_policies_scope_check
        CHECK (application_id IS NULL OR tenant_id IS NOT NULL),

    -- An empty string is not a relying party. NULL means inherit; '' would be a
    -- silent override to nothing, and every ceremony under it would fail with an
    -- origin mismatch nobody could explain.
    CONSTRAINT passkey_policies_rp_id_not_blank
        CHECK (rp_id IS NULL OR rp_id <> ''),

    -- Origins without an RP ID are meaningless — and worse than meaningless: it
    -- would look like the tenant had configured its own relying party while the
    -- ceremony ran under the server's, so credentials would be created for the
    -- wrong RP and silently never offered.
    CONSTRAINT passkey_policies_origins_need_rp_id
        CHECK (cardinality(origins) = 0 OR rp_id IS NOT NULL),

    CONSTRAINT passkey_policies_max_credentials_bounds
        CHECK (max_credentials_per_user BETWEEN 1 AND 100)
);

-- +goose StatementEnd

-- +goose StatementBegin

-- One policy per scope. Partial unique indexes rather than one index over
-- COALESCE(...): they express the three scopes directly, and because NULLs do
-- not conflict in a plain unique index the platform-default row would otherwise
-- be duplicable — after which resolution would depend on which duplicate the
-- planner returned first.
CREATE UNIQUE INDEX IF NOT EXISTS passkey_policies_platform_default
    ON passkey_policies ((true)) WHERE tenant_id IS NULL AND application_id IS NULL;

-- +goose StatementEnd

-- +goose StatementBegin

CREATE UNIQUE INDEX IF NOT EXISTS passkey_policies_per_tenant
    ON passkey_policies (tenant_id) WHERE application_id IS NULL AND tenant_id IS NOT NULL;

-- +goose StatementEnd

-- +goose StatementBegin

CREATE UNIQUE INDEX IF NOT EXISTS passkey_policies_per_application
    ON passkey_policies (tenant_id, application_id) WHERE application_id IS NOT NULL;

-- +goose StatementEnd

-- +goose StatementBegin

-- Seed the platform default: feature off, and every other value at the setting
-- a tenant switching it on would want. rp_id/origins stay NULL/empty so the
-- default inherits the server configuration and a single-RP deployment needs no
-- rows at all beyond flipping allow_passkeys.
INSERT INTO passkey_policies
    (tenant_id, application_id, allow_passkeys, allow_passwordless,
     require_user_verification, rp_id, rp_display_name, origins,
     max_credentials_per_user)
VALUES (NULL, NULL, false, true, true, NULL, NULL, '{}', 10)
ON CONFLICT DO NOTHING;

-- +goose StatementEnd

-- +goose StatementBegin

-- Credential-name length. The name is user-supplied and purely for display; an
-- unbounded TEXT here is a free write amplifier and makes the settings list
-- unrenderable. Enforced in the database as well as in Go because the column is
-- also reachable by hand during support work.
--
-- Added here rather than in 00078 so a database that already ran the spike
-- migration picks it up.
ALTER TABLE webauthn_credentials
    DROP CONSTRAINT IF EXISTS webauthn_credentials_name_length;

-- +goose StatementEnd

-- +goose StatementBegin

ALTER TABLE webauthn_credentials
    ADD CONSTRAINT webauthn_credentials_name_length
    CHECK (char_length(name) <= 64);

-- +goose StatementEnd

-- +goose StatementBegin

-- When a credential was revoked, and by whom. is_active alone records that a
-- passkey is gone but not when — and "which passkey was removed and when" is the
-- audit-relevant part that motivated soft-deleting in the first place.
--
-- revoked_by_admin distinguishes a user removing their own device from support
-- removing a lost one. The audit log carries the actor; this column is what lets
-- the user's own settings list say "removed by your administrator" rather than
-- leaving them to wonder.
ALTER TABLE webauthn_credentials
    ADD COLUMN IF NOT EXISTS revoked_at       TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revoked_by_admin BOOLEAN NOT NULL DEFAULT false;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE webauthn_credentials
    DROP COLUMN IF EXISTS revoked_by_admin,
    DROP COLUMN IF EXISTS revoked_at;

ALTER TABLE webauthn_credentials
    DROP CONSTRAINT IF EXISTS webauthn_credentials_name_length;

DROP INDEX IF EXISTS passkey_policies_per_application;
DROP INDEX IF EXISTS passkey_policies_per_tenant;
DROP INDEX IF EXISTS passkey_policies_platform_default;
DROP TABLE IF EXISTS passkey_policies;

-- +goose StatementEnd
