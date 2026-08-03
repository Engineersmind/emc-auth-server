-- +goose Up
-- +goose StatementBegin

-- Tenant administration as a first-class entity (issue #97).
--
-- Until now the only thing separating a tenant administrator from an
-- application end user was the nullable users.application_id column: NULL meant
-- "tenant-level, probably an admin". That is a soft boundary guarding the most
-- privileged accounts in the system — a single query that forgets
-- "AND application_id IS NULL" conflates the two populations, and end-user rows
-- are created by paths that are deliberately permissive (self-registration,
-- Google/GitHub OAuth, SAML JIT).
--
-- tenant_admins makes administration an explicit membership. Application end
-- users can never appear in it, because a row is only permitted to reference a
-- tenant-level user (enforced by trigger below — Postgres cannot express that
-- as a plain foreign key).
--
-- Deliberately NOT separated: credentials and tokens. users.id carries 16
-- foreign keys across 15 tables (user_credentials, refresh_tokens,
-- totp_secrets, email_mfa_settings, password_reset_tokens, user_invitations,
-- email_change_requests, account_unblock_tokens, user_identities,
-- oauth_consents, audit_logs, ...). Forking those would duplicate the whole of
-- internal/auth — login, refresh, both MFA paths, reset, verification, email
-- change, block/unblock — into a second copy that receives less traffic and
-- therefore less scrutiny, and would force audit_logs into a polymorphic actor.
-- The separation that carries the security value is of identity and lifecycle,
-- not of the password hash.
--
-- Three tiers, only two of which live here:
--
--   platform admin  super_admin / tenant:manage — cross-tenant, NOT a
--                   tenant_admins row: it is a platform tier, not a membership
--                   in any one tenant.
--   owner           every application in the tenant. Holds NO rows in
--                   tenant_admin_app_scopes.
--   co_owner        only the applications named in tenant_admin_app_scopes.
--
-- Owners hold zero grants rather than one grant per application ("absence means
-- all"). Encoding an owner as grants-for-every-app would oblige every present
-- and future application-creation path to backfill a grant row for every owner
-- of the tenant, forever. A missed backfill fails silently — the owner simply
-- gets 403 on an application they just created themselves, with no error to
-- trace. Making it a rule in the permission check instead makes that
-- unrepresentable at the cost of one branch.
--
-- The converse is NOT symmetric: a co_owner with zero grants has no application
-- access at all. Grants only ever narrow; they never widen. Fail closed.

CREATE TABLE IF NOT EXISTS tenant_admins (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id  BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The shared identity: credentials, sessions, MFA, and every email flow
    -- continue to hang off this users row.
    user_id    BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    admin_role TEXT        NOT NULL CHECK (admin_role IN ('owner', 'co_owner')),
    -- Who issued the invitation. SET NULL rather than CASCADE: losing the
    -- inviter must never delete the administrator they onboarded.
    invited_by BIGINT      REFERENCES tenant_admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- One live administration row per user. Soft-delete aware so an admin can be
-- removed and later re-invited without colliding with their own tombstone.
CREATE UNIQUE INDEX IF NOT EXISTS tenant_admins_user_key
    ON tenant_admins (user_id)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_tenant_admins_tenant
    ON tenant_admins (tenant_id, admin_role)
    WHERE deleted_at IS NULL;

-- The invariant the entire separation rests on: a tenant_admins row may only
-- reference a tenant-level user (application_id IS NULL) belonging to the same
-- tenant. Without this the table is a naming convention rather than a
-- guarantee — an application end user could be made a tenant administrator by
-- any code path that inserts here with the wrong id.
--
-- A CHECK constraint cannot reach another table and a foreign key cannot
-- constrain a column of the parent, so this has to be a trigger.
CREATE OR REPLACE FUNCTION tenant_admins_assert_tenant_level_user()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  u_tenant_id BIGINT;
  u_app_id    BIGINT;
BEGIN
  SELECT tenant_id, application_id INTO u_tenant_id, u_app_id
  FROM users WHERE id = NEW.user_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant_admins.user_id % does not exist', NEW.user_id
      USING ERRCODE = 'foreign_key_violation';
  END IF;

  IF u_app_id IS NOT NULL THEN
    RAISE EXCEPTION
      'tenant_admins.user_id % is an application-scoped user (application_id %); administrators must be tenant-level',
      NEW.user_id, u_app_id
      USING ERRCODE = 'check_violation';
  END IF;

  IF u_tenant_id <> NEW.tenant_id THEN
    RAISE EXCEPTION
      'tenant_admins.tenant_id % does not match users.tenant_id % for user %',
      NEW.tenant_id, u_tenant_id, NEW.user_id
      USING ERRCODE = 'check_violation';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS tenant_admins_tenant_level_user ON tenant_admins;
CREATE TRIGGER tenant_admins_tenant_level_user
  BEFORE INSERT OR UPDATE OF user_id, tenant_id ON tenant_admins
  FOR EACH ROW EXECUTE FUNCTION tenant_admins_assert_tenant_level_user();

-- Per-application grants. Only meaningful for co_owner: see the "absence means
-- all" note above.
CREATE TABLE IF NOT EXISTS tenant_admin_app_scopes (
    admin_id       BIGINT      NOT NULL REFERENCES tenant_admins(id) ON DELETE CASCADE,
    application_id BIGINT      NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    granted_by     BIGINT      REFERENCES tenant_admins(id) ON DELETE SET NULL,
    granted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (admin_id, application_id)
);

-- Answers "who administers this application?" without scanning the table.
CREATE INDEX IF NOT EXISTS idx_tenant_admin_app_scopes_app
    ON tenant_admin_app_scopes (application_id);

-- Two things a foreign key cannot say: an owner must hold no grants (so
-- "absence means all" can never be quietly contradicted by stale rows left
-- behind when a co_owner is promoted), and a grant must not cross a tenant
-- boundary.
CREATE OR REPLACE FUNCTION tenant_admin_app_scopes_assert_valid()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  a_tenant_id  BIGINT;
  a_role       TEXT;
  app_tenant_id BIGINT;
BEGIN
  SELECT tenant_id, admin_role INTO a_tenant_id, a_role
  FROM tenant_admins WHERE id = NEW.admin_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant_admin_app_scopes.admin_id % does not exist', NEW.admin_id
      USING ERRCODE = 'foreign_key_violation';
  END IF;

  IF a_role = 'owner' THEN
    RAISE EXCEPTION
      'tenant_admins %: owners administer every application in the tenant and must hold no application grants',
      NEW.admin_id
      USING ERRCODE = 'check_violation';
  END IF;

  SELECT tenant_id INTO app_tenant_id FROM oauth_clients WHERE id = NEW.application_id;
  IF app_tenant_id IS DISTINCT FROM a_tenant_id THEN
    RAISE EXCEPTION
      'application % belongs to tenant % but administrator % belongs to tenant %',
      NEW.application_id, app_tenant_id, NEW.admin_id, a_tenant_id
      USING ERRCODE = 'check_violation';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS tenant_admin_app_scopes_valid ON tenant_admin_app_scopes;
CREATE TRIGGER tenant_admin_app_scopes_valid
  BEFORE INSERT OR UPDATE ON tenant_admin_app_scopes
  FOR EACH ROW EXECUTE FUNCTION tenant_admin_app_scopes_assert_valid();

-- Promoting a co_owner to owner must clear their now-meaningless grants rather
-- than leave rows the owner trigger would reject on any later touch.
CREATE OR REPLACE FUNCTION tenant_admins_clear_grants_on_promote()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.admin_role = 'owner' AND OLD.admin_role <> 'owner' THEN
    DELETE FROM tenant_admin_app_scopes WHERE admin_id = NEW.id;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS tenant_admins_promote_clears_grants ON tenant_admins;
CREATE TRIGGER tenant_admins_promote_clears_grants
  AFTER UPDATE OF admin_role ON tenant_admins
  FOR EACH ROW EXECUTE FUNCTION tenant_admins_clear_grants_on_promote();

-- The tenant's primary administrator: billing contact, the address platform
-- notices go to, and the default target when ownership is handed over. Kept on
-- the parent as a single nullable FK rather than a boolean on tenant_admins so
-- that "two rows both claim primary" is unrepresentable.
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS primary_admin_id BIGINT
    REFERENCES tenant_admins(id) ON DELETE SET NULL;

-- Backfill: every existing tenant-level user holding the seeded system "owner"
-- role becomes an owner row. CreateTenant has always produced exactly one of
-- these per tenant, but the query does not assume that — a tenant that acquired
-- extra owners by hand gets all of them.
INSERT INTO tenant_admins (tenant_id, user_id, admin_role, created_at)
SELECT u.tenant_id, u.id, 'owner', u.created_at
FROM users u
JOIN roles r ON r.id = u.role_id
WHERE r.name = 'owner'
  AND r.is_system = true
  AND r.application_id IS NULL
  AND r.deleted_at IS NULL
  AND u.application_id IS NULL
  AND u.deleted_at IS NULL
ON CONFLICT DO NOTHING;

-- Point each tenant at its earliest owner. Ties broken by id so the result is
-- deterministic if two owners share a created_at.
UPDATE tenants t
SET primary_admin_id = pick.id
FROM (
    SELECT DISTINCT ON (tenant_id) id, tenant_id
    FROM tenant_admins
    WHERE admin_role = 'owner' AND deleted_at IS NULL
    ORDER BY tenant_id, created_at, id
) AS pick
WHERE pick.tenant_id = t.id
  AND t.primary_admin_id IS NULL;

-- +goose StatementEnd


-- +goose Down
-- +goose StatementBegin

ALTER TABLE tenants DROP COLUMN IF EXISTS primary_admin_id;

DROP TRIGGER IF EXISTS tenant_admins_promote_clears_grants ON tenant_admins;
DROP FUNCTION IF EXISTS tenant_admins_clear_grants_on_promote();

DROP TRIGGER IF EXISTS tenant_admin_app_scopes_valid ON tenant_admin_app_scopes;
DROP FUNCTION IF EXISTS tenant_admin_app_scopes_assert_valid();

DROP TABLE IF EXISTS tenant_admin_app_scopes;

DROP TRIGGER IF EXISTS tenant_admins_tenant_level_user ON tenant_admins;
DROP FUNCTION IF EXISTS tenant_admins_assert_tenant_level_user();

DROP TABLE IF EXISTS tenant_admins;

-- +goose StatementEnd
