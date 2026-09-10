-- +goose Up
-- +goose StatementBegin

-- Per-application audience with explicit client grants — issue #131.
--
-- #130 moved the token type out of `aud` into `gty`, which freed `aud` without
-- putting anything in it. This migration supplies the value: a real, per-
-- application audience, so the application boundary is enforced by every
-- standard JWT library for free. Before this, `aud` was byte-identical across
-- every application in a tenant, so a Marketing Site token passed a Payroll
-- API's textbook validation — signature ✓ (same tenant key), iss ✓, exp ✓,
-- aud ✓. The only claim that could catch it was `app_id`, and no JWT library
-- knows to check it. emc-insurance-platform hand-rolled middleware for exactly
-- this reason.
--
-- EXPLICIT GRANTS ONLY. No client may request an arbitrary audience; it must
-- hold a row here. "Any client within its own tenant" was considered and
-- rejected — it makes the tenant, not the operator, the security boundary.
CREATE TABLE IF NOT EXISTS oauth_client_grants (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id  BIGINT NOT NULL REFERENCES tenants(id)       ON DELETE CASCADE,
    client_id  BIGINT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,

    -- The audience this client may request. Namespaced api://<tenant>/<app>,
    -- never a bare client_id: that collides with the ID token's own `aud`
    -- (internal/auth/idtoken.go:147) and recreates #84 in a new form.
    audience   TEXT   NOT NULL,

    -- Scopes this grant permits. A token never carries a scope the grant omits;
    -- the requested set is intersected with this one at mint time.
    scopes     TEXT[] NOT NULL DEFAULT '{}',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT oauth_client_grants_client_audience_key UNIQUE (client_id, audience)
);

-- +goose StatementEnd

-- +goose StatementBegin

-- "Who is granted this audience" — the read behind GET /api/v1/audiences and
-- behind any future revocation of a grant across clients. The UNIQUE above
-- already serves the per-client direction.
CREATE INDEX IF NOT EXISTS idx_oauth_client_grants_audience
    ON oauth_client_grants (audience);

-- +goose StatementEnd

-- +goose StatementBegin

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS audience TEXT;

-- Enforcement is per client and OFF by default, so this migration changes no
-- token that is issued today. Rollback of the whole feature is this flag, not a
-- deploy.
ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS require_audience BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN oauth_clients.audience IS
    'Immutable per-application audience identifier (api://<tenant-slug>/<app-slug>). Never updated: every resource server validating it would break. No update path exists in the admin API by design.';

-- +goose StatementEnd

-- +goose StatementBegin

-- PRE-FLIGHT. Fail with the offending rows rather than with a bare
-- unique_violation on an index name — the 00080 precedent.
--
-- Two ways the backfill below can collide, and the second is the one the
-- ticket's pre-flight query misses:
--
--   1. Two LIVE clients in one tenant whose names slugify identically.
--      oauth_clients.name is unique per tenant, but "Payroll API" and
--      "payroll-api" are different names and one slug.
--
--   2. A live client and a SOFT-DELETED one sharing a name. Legal today:
--      idx_oauth_clients_tenant_name is partial on WHERE deleted_at IS NULL
--      (migration 00035). The backfill excludes deleted rows for this reason,
--      so case 2 cannot actually fire — this block covers it anyway, because
--      the exclusion is one WHERE clause away from being edited out.
DO $$
DECLARE
    n INTEGER;
    detail TEXT;
BEGIN
    SELECT count(*), string_agg(format('%s/%s: %s', tenant, app_slug, names), '; ')
      INTO n, detail
      FROM (
        SELECT lower(t.slug) AS tenant,
               lower(regexp_replace(regexp_replace(c.name, '[^a-zA-Z0-9]+', '-', 'g'),
                                    '(^-+|-+$)', '', 'g')) AS app_slug,
               string_agg(c.name, ' / ') AS names
          FROM oauth_clients c
          JOIN tenants t ON t.id = c.tenant_id
         WHERE c.deleted_at IS NULL
         GROUP BY 1, 2
        HAVING count(*) > 1
      ) dupes;

    IF n > 0 THEN
        RAISE EXCEPTION
            'cannot assign per-application audiences: % colliding app slug(s): %', n, detail
            USING HINT = 'rename one client in each colliding pair, then re-run this migration';
    END IF;
END $$;

-- +goose StatementEnd

-- +goose StatementBegin

-- A FULL unique index, deliberately unlike idx_oauth_clients_client_id, which
-- is partial on WHERE deleted_at IS NULL and therefore permits reuse after a
-- soft delete. An audience must NEVER be recycled: grants and tokens outlive
-- the client row, and a reissued identifier silently redirects them to a
-- different application.
CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_clients_audience
    ON oauth_clients (audience);

-- +goose StatementEnd

-- +goose StatementBegin

-- Backs the composite FK below. Adds no new uniqueness — audience is already
-- globally unique — it exists only so (tenant_id, audience) is a referencable
-- key.
CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_clients_tenant_audience
    ON oauth_clients (tenant_id, audience);

-- +goose StatementEnd

-- +goose StatementBegin

-- The reserved namespace is a privilege escalation if missed. Without it a
-- tenant registers api://emc-auth, receives a legitimately signed token bearing
-- this server's own management audience, and reaches the admin surface with it.
-- Matches auth.ReservedAudiencePrefix (internal/auth/jwt.go:201). The prefix
-- match is deliberately broader than equality, so api://emc-auth-anything is
-- refused too.
--
-- Enforced in the service layer as WELL as here, so an operator gets a sentence
-- rather than a constraint name. Here so the invariant holds for every writer,
-- psql included.
--
-- No format CHECK accompanies it, and that is not an omission: the identifier
-- format caps each label near 40 characters and forbids leading/trailing
-- hyphens, but nothing constrains tenants.slug length and chk_tenants_slug
-- (migration 00031) is `~*`, so it admits both uppercase and `-foo-`. A format
-- CHECK here would refuse legitimate existing data and abort the backfill.
-- Format is validated in Go, on creation, for new rows only.
ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS oauth_clients_audience_not_reserved;

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_audience_not_reserved
    CHECK (audience IS NULL OR audience !~ '^api://emc-auth');

-- +goose StatementEnd

-- +goose StatementBegin

-- Pin the audience to the refresh chain, so a refresh cannot change the
-- audience it was issued for. ON DELETE CASCADE matches user_id and tenant_id
-- on this table: a hard-deleted client's refresh tokens go with it, which is
-- the revocation you want. Bare NO ACTION would instead make the delete fail.
--
-- Both columns are nullable and pre-existing rows stay NULL — a chain minted
-- before this migration has no audience to pin, which is the pre-#131
-- behaviour and stays valid while require_audience is false.
--
-- application_id also closes deferred #22: /oauth/revoke had no column to
-- compare an authenticated client_id against, so two clients inside one tenant
-- could revoke each other's tokens.
ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS application_id BIGINT REFERENCES oauth_clients(id) ON DELETE CASCADE;

ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS audience TEXT;

-- +goose StatementEnd

-- +goose StatementBegin

-- Not in the ticket body — see the corrections comment on #131.
--
-- The AuthzRequest carrying an authorize request lives in Redis and is consumed
-- at /oauth/authorize (internal/auth/authzsession.go:90). The code row is the
-- ONLY thing linking an authorize request to its later token exchange, so
-- without this column the audience cannot survive the exchange and "carry the
-- audience through authorize → code → token" is unimplementable.
ALTER TABLE oauth_authorization_codes
    ADD COLUMN IF NOT EXISTS audience TEXT;

-- +goose StatementEnd

-- +goose StatementBegin

-- BACKFILL, part 1: give every live client its own stored audience.
--
-- slugify() does not exist — not in these migrations, not in the codebase, not
-- in stock Postgres. The ticket body's backfill calls it and errors on
-- execution. The expression is inlined instead.
--
-- lower(t.slug) because chk_tenants_slug is `~*` and therefore admits uppercase,
-- while the audience format is lowercase-only.
--
-- deleted_at IS NULL matters, and not only to keep the unique index happy:
-- reservation exists to stop a PREVIOUSLY ISSUED audience being recycled onto a
-- different application, and a soft-deleted client never had one. Backfilling
-- deleted rows would instead collide head-on with a live client of the same
-- name, which idx_oauth_clients_tenant_name permits.
--
-- The empty-slug guard catches a name that is entirely punctuation, which would
-- otherwise yield the degenerate `api://tenant/`. Rare — migration 00035 set
-- name = client_id for every empty one — but one WHERE clause.
UPDATE oauth_clients c
SET audience = 'api://' || lower(t.slug) || '/' ||
    lower(regexp_replace(regexp_replace(c.name, '[^a-zA-Z0-9]+', '-', 'g'),
                         '(^-+|-+$)', '', 'g')),
    updated_at = NOW()
FROM tenants t
WHERE t.id = c.tenant_id
  AND c.deleted_at IS NULL
  AND c.audience IS NULL
  AND regexp_replace(regexp_replace(c.name, '[^a-zA-Z0-9]+', '-', 'g'),
                     '(^-+|-+$)', '', 'g') <> '';

-- +goose StatementEnd

-- +goose StatementBegin

-- BACKFILL, part 2: the self-grant. This is why the backfill cannot be split
-- into a later migration — a client with no self-grant cannot get a token for
-- its own API once enforcement is switched on, so the window between the two
-- would be a window in which the feature is broken.
--
-- Idempotent: ON CONFLICT DO NOTHING, so a re-run after a partial failure is
-- safe.
INSERT INTO oauth_client_grants (tenant_id, client_id, audience)
SELECT tenant_id, id, audience
  FROM oauth_clients
 WHERE audience IS NOT NULL
ON CONFLICT (client_id, audience) DO NOTHING;

-- +goose StatementEnd

-- +goose StatementBegin

-- A granted audience must belong to a client in the SAME tenant. Added AFTER
-- the backfill, which satisfies it by construction (every self-grant names its
-- own client's tenant).
--
-- The service layer refuses a cross-tenant grant with a readable error; this
-- makes it impossible rather than merely refused, which matters because the
-- admin API takes tenant_id from two addressing shapes
-- (tenantFromClaimsOrPath) and a grant is exactly the kind of row an operator
-- reaches by hand.
--
-- ON DELETE CASCADE: hard-deleting the client that OWNS an audience removes the
-- grants pointing at it. Soft deletes leave the row in place and are unaffected.
ALTER TABLE oauth_client_grants
    DROP CONSTRAINT IF EXISTS oauth_client_grants_audience_fkey;

ALTER TABLE oauth_client_grants
    ADD CONSTRAINT oauth_client_grants_audience_fkey
    FOREIGN KEY (tenant_id, audience)
    REFERENCES oauth_clients (tenant_id, audience)
    ON DELETE CASCADE;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Reverse dependency order: the referencing table first, then the columns, then
-- the keys they depend on.
ALTER TABLE oauth_client_grants DROP CONSTRAINT IF EXISTS oauth_client_grants_audience_fkey;

DROP TABLE IF EXISTS oauth_client_grants;

ALTER TABLE oauth_authorization_codes DROP COLUMN IF EXISTS audience;

ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS audience;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS application_id;

ALTER TABLE oauth_clients DROP CONSTRAINT IF EXISTS oauth_clients_audience_not_reserved;
DROP INDEX IF EXISTS idx_oauth_clients_tenant_audience;
DROP INDEX IF EXISTS idx_oauth_clients_audience;

ALTER TABLE oauth_clients DROP COLUMN IF EXISTS require_audience;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS audience;

-- +goose StatementEnd
