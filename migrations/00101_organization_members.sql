-- +goose Up
-- +goose StatementBegin

-- Organisation membership and per-organisation roles.
--
-- A role granted here applies ONLY inside its organisation. user_roles (00092)
-- keeps meaning "application-wide", and the two are surfaced in separate token
-- claims (roles/permissions vs org_roles/org_permissions) so no existing
-- consumer sees a claim change meaning.
--
-- ISOLATION IS ENFORCED BY THE DATABASE, not only by the service layer:
--   * a member must be a user of the organisation's own application;
--   * an organisation role must be a live, non-system role of that application.
-- Both are a single bug away from a cross-application privilege grant if left
-- to application code alone, so they are constraints here.
CREATE TABLE IF NOT EXISTS organization_members (
    organization_id BIGINT      NOT NULL,
    application_id  BIGINT      NOT NULL,
    user_id         BIGINT      NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    tenant_id       BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- suspended keeps the membership and its roles but refuses sign-in to the
    -- organisation and revokes its sessions. Reversible, unlike removal.
    status          TEXT        NOT NULL DEFAULT 'active',

    invited_by      BIGINT      REFERENCES users(id) ON DELETE SET NULL,
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (organization_id, user_id),
    -- The membership's application must be the organisation's application.
    FOREIGN KEY (organization_id, application_id)
        REFERENCES organizations (id, application_id) ON DELETE CASCADE,
    CONSTRAINT organization_members_status_check
        CHECK (status IN ('active', 'suspended'))
);

-- "Which organisations does this user belong to" — read on every login of an
-- organisation-enabled application.
CREATE INDEX IF NOT EXISTS idx_organization_members_user
    ON organization_members (user_id, application_id);

CREATE TABLE IF NOT EXISTS organization_member_roles (
    organization_id BIGINT      NOT NULL,
    user_id         BIGINT      NOT NULL,
    role_id         BIGINT      NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    application_id  BIGINT      NOT NULL,
    tenant_id       BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Provenance, as on user_roles: SET NULL so losing the grantor never
    -- silently revokes what they granted.
    granted_by      BIGINT      REFERENCES users(id) ON DELETE SET NULL,
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (organization_id, user_id, role_id),
    FOREIGN KEY (organization_id, user_id)
        REFERENCES organization_members (organization_id, user_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_organization_member_roles_role
    ON organization_member_roles (role_id);

-- Membership integrity: the user must belong to the organisation's application
-- and tenant. application_id on the row is already pinned to the organisation by
-- the composite foreign key, so checking the user against it closes the loop.
CREATE OR REPLACE FUNCTION organization_members_check_user()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM users u
        WHERE u.id = NEW.user_id
          AND u.tenant_id = NEW.tenant_id
          AND u.application_id = NEW.application_id
    ) THEN
        RAISE EXCEPTION 'organization member must be a user of the organization''s application'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'organization_members_user_application';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS organization_members_check_user ON organization_members;
CREATE TRIGGER organization_members_check_user
    BEFORE INSERT OR UPDATE OF user_id, application_id, tenant_id ON organization_members
    FOR EACH ROW EXECUTE FUNCTION organization_members_check_user();

-- Role integrity: only the organisation's own application roles, never a system
-- role, never a soft-deleted one, and the row's application must match the
-- membership it hangs off.
CREATE OR REPLACE FUNCTION organization_member_roles_check_role()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM organization_members m
        WHERE m.organization_id = NEW.organization_id
          AND m.user_id = NEW.user_id
          AND m.application_id = NEW.application_id
          AND m.tenant_id = NEW.tenant_id
    ) THEN
        RAISE EXCEPTION 'organization role must match its membership''s application'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'organization_member_roles_membership';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM roles r
        WHERE r.id = NEW.role_id
          AND r.application_id = NEW.application_id
          AND r.tenant_id = NEW.tenant_id
          AND r.is_system = false
          AND r.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'organization role must be a live, non-system role of the organization''s application'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'organization_member_roles_role_application';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS organization_member_roles_check_role ON organization_member_roles;
CREATE TRIGGER organization_member_roles_check_role
    BEFORE INSERT OR UPDATE ON organization_member_roles
    FOR EACH ROW EXECUTE FUNCTION organization_member_roles_check_role();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS organization_member_roles;
DROP TABLE IF EXISTS organization_members;
DROP FUNCTION IF EXISTS organization_member_roles_check_role();
DROP FUNCTION IF EXISTS organization_members_check_user();
-- +goose StatementEnd
