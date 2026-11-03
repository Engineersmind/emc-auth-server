-- +goose Up
-- +goose StatementBegin

-- Organisation invitations.
--
-- Separate from user_invitations (00061) on purpose. That table finishes setting
-- up an account an administrator already created; an organisation invitation is
-- addressed to an EMAIL that may or may not have an account in the application
-- yet, and carries the organisation and roles the invitee receives on accepting.
--
-- Only the SHA-256 of the token is stored, as for every other emailed token.
CREATE TABLE IF NOT EXISTS organization_invitations (
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id        TEXT        NOT NULL,
    organization_id  BIGINT      NOT NULL,
    application_id   BIGINT      NOT NULL,
    tenant_id        BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Normalised (lower-cased, trimmed) like users.email. Acceptance requires
    -- the accepting account's email to equal this exactly.
    email            TEXT        NOT NULL,

    -- Role ids granted on acceptance. Re-validated against live roles at accept
    -- time, so a role deleted in the meantime is dropped rather than resurrected.
    role_ids         BIGINT[]    NOT NULL DEFAULT '{}',

    token_hash       TEXT        NOT NULL,
    invited_by       BIGINT      REFERENCES users(id) ON DELETE SET NULL,
    -- The application's client_id when an application backend sent it, so the
    -- audit trail can answer "which system invited this person".
    invited_by_client TEXT,

    expires_at       TIMESTAMPTZ NOT NULL,
    accepted_at      TIMESTAMPTZ,
    accepted_user_id BIGINT      REFERENCES users(id) ON DELETE SET NULL,
    revoked_at       TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    FOREIGN KEY (organization_id, application_id)
        REFERENCES organizations (id, application_id) ON DELETE CASCADE,
    CONSTRAINT organization_invitations_public_id_format
        CHECK (public_id ~ '^inv_[A-Za-z0-9]{20}$')
);

CREATE UNIQUE INDEX IF NOT EXISTS organization_invitations_public_id_key
    ON organization_invitations (public_id);
CREATE UNIQUE INDEX IF NOT EXISTS organization_invitations_token_hash_key
    ON organization_invitations (token_hash);

-- At most one pending invitation per email per organisation: re-inviting
-- replaces rather than piling up live tokens for the same person.
CREATE UNIQUE INDEX IF NOT EXISTS organization_invitations_pending_key
    ON organization_invitations (organization_id, email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_organization_invitations_org_created
    ON organization_invitations (organization_id, created_at DESC);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS organization_invitations;
-- +goose StatementEnd
