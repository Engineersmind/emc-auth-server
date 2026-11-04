-- +goose Up
-- +goose StatementBegin

-- Organizations — customer organisations inside one application.
--
-- EMC's hierarchy is tenant → application → users and roles, and a role attaches
-- to the user, so it applies everywhere in the application. A B2B application
-- needs one more level: "Sarah is Admin at Acme and Viewer at Globex". This
-- table is that level. Membership and per-organisation roles follow in 00101.
--
-- OPT-IN PER APPLICATION. oauth_clients.organizations_mode below defaults to
-- 'off' for every existing row, and 'off' means every login, refresh and token
-- this server produces for the application is byte-for-byte what it was before
-- this migration. Nothing reads these tables for an application that has not
-- been switched on, and nothing at all while ORGANIZATIONS_ENABLED is false.
--
-- An organisation belongs to exactly ONE application. Users are already
-- application-scoped (00042) and so are roles (00043); an organisation spanning
-- two applications would have no coherent user base or role catalogue.
CREATE TABLE IF NOT EXISTS organizations (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    -- The identifier that leaves this server: tokens (org_id), APIs and logs.
    -- Random rather than the row id so an organisation's existence, count and
    -- creation order cannot be inferred from ids a relying party has seen.
    public_id      TEXT        NOT NULL,

    tenant_id      BIGINT      NOT NULL REFERENCES tenants(id)       ON DELETE CASCADE,
    application_id BIGINT      NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,

    -- Immutable, human-readable handle; carried as the org_name claim. Immutable
    -- because relying parties log and display it, and a rename would make two
    -- tokens for the same organisation disagree about what it is called.
    slug           TEXT        NOT NULL,
    display_name   TEXT        NOT NULL,

    -- Free-form application data. Bounded so it cannot be used as bulk storage.
    metadata       JSONB       NOT NULL DEFAULT '{}'::jsonb,

    -- false suspends the organisation: nobody can sign in to it and its live
    -- sessions are revoked, but members, roles and audit history are kept.
    is_active      BOOLEAN     NOT NULL DEFAULT true,

    created_by     BIGINT      REFERENCES users(id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at     TIMESTAMPTZ,

    CONSTRAINT organizations_public_id_format
        CHECK (public_id ~ '^org_[A-Za-z0-9]{20}$'),
    CONSTRAINT organizations_slug_format
        CHECK (slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'),
    CONSTRAINT organizations_display_name_length
        CHECK (char_length(display_name) BETWEEN 1 AND 200),
    CONSTRAINT organizations_metadata_object
        CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT organizations_metadata_size
        CHECK (pg_column_size(metadata) <= 4096)
);

CREATE UNIQUE INDEX IF NOT EXISTS organizations_public_id_key
    ON organizations (public_id);

-- One live organisation per slug per application. Soft-deleted rows release the
-- slug, matching how users and roles treat their natural keys.
CREATE UNIQUE INDEX IF NOT EXISTS organizations_app_slug_key
    ON organizations (application_id, slug)
    WHERE deleted_at IS NULL;

-- Composite target for the membership foreign key in 00101: it is what lets the
-- database itself refuse a membership whose application differs from the
-- organisation's, rather than trusting every writer to check.
CREATE UNIQUE INDEX IF NOT EXISTS organizations_id_app_key
    ON organizations (id, application_id);

CREATE INDEX IF NOT EXISTS idx_organizations_app_created
    ON organizations (application_id, created_at DESC)
    WHERE deleted_at IS NULL;

-- The per-application switch. A constant default is applied by PostgreSQL as
-- metadata only, so this does not rewrite oauth_clients.
--
--   off      — today's behaviour; organisation parameters are ignored.
--   optional — a session may be inside one organisation or none.
--   required — every end-user session is inside exactly one organisation.
ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS organizations_mode TEXT NOT NULL DEFAULT 'off';

ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS oauth_clients_organizations_mode_check;
ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_organizations_mode_check
    CHECK (organizations_mode IN ('off', 'optional', 'required'));

COMMENT ON COLUMN oauth_clients.organizations_mode IS
    'Organizations: off (default, unchanged behaviour), optional, or required. See migration 00100.';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE oauth_clients DROP CONSTRAINT IF EXISTS oauth_clients_organizations_mode_check;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS organizations_mode;
DROP TABLE IF EXISTS organizations;
-- +goose StatementEnd
