-- +goose Up
-- +goose StatementBegin

-- Multi-tenant administration: one human, one credential, N grants.
--
-- Until now a tenant administrator reached exactly one tenant, because
-- tenant_admins_user_key (migration 00062) is UNIQUE on user_id ALONE — one live
-- administration row per user, full stop. The requirement is now that one person
-- may own tenant A and co-own tenant B at the same time, so that constraint has
-- to go, and with it the assumption that an administrator's identity and their
-- reach are the same fact.
--
-- admin_grants carries BOTH object dimensions in one table:
--
--   tenant_id                        which tenant this grant is about
--   application_id IS NULL           every application in it, present and future
--   application_id IS NOT NULL       exactly that one application
--
-- so a row is read as "this user administers this much of this tenant". An owner
-- of A and co-owner of B holds one NULL-application row for A and one row per
-- granted application in B.
--
-- Deliberately NOT a role_id column. A co-owner has full authority over each
-- application they are granted — the grant decides WHICH applications, never
-- WHAT may be done to them — so permissions are a pure function of admin_role
-- and are resolved from the tenant's seeded owner/co_owner role at token-issue
-- time. Storing a role per grant would add a column, a backfill, and an
-- assumption about existing users.role_id values, to express something that
-- cannot vary.
--
-- Two things migration 00062 had to enforce with plpgsql become a CHECK here.
-- "An owner holds no application grants" was a trigger on a second table
-- (tenant_admin_app_scopes_assert_valid); expressed as a shape constraint on one
-- row it is unrepresentable rather than trigger-rejected, which is both cheaper
-- and stronger.
--
-- "Absence means all" is preserved exactly as 00062 argued it: encoding an owner
-- as one grant per application would oblige every present and future
-- application-creation path to backfill a row for every owner of the tenant,
-- forever, and a missed backfill fails SILENTLY — the owner gets 403 on an
-- application they just created, with no error to trace. The converse stays
-- asymmetric: a co_owner with zero grants has no access at all. Grants only ever
-- narrow. Fail closed.
--
-- tenant_admins and tenant_admin_app_scopes are left in place and are NOT
-- dropped here. loadAdminScope keeps reading them until ADMIN_GRANTS_ENABLED is
-- flipped, and grant writes go to both models until then, so rollback is a
-- config change rather than a migration.

CREATE TABLE IF NOT EXISTS admin_grants (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The shared identity. Credentials, sessions, MFA and every email flow
    -- continue to hang off this users row — see 00062 on why the password hash
    -- is not what gets separated. users.tenant_id is now only where those
    -- credentials LIVE; reach is this table's business.
    user_id        BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id      BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    admin_role     TEXT        NOT NULL CHECK (admin_role IN ('owner', 'co_owner')),
    -- NULL = every application in this tenant, present and future.
    application_id BIGINT      REFERENCES oauth_clients(id) ON DELETE CASCADE,
    -- Who issued the invitation. SET NULL rather than CASCADE: losing the
    -- inviter must never delete the administrator they onboarded.
    invited_by     BIGINT      REFERENCES admin_grants(id) ON DELETE SET NULL,
    -- NULL = granted but not yet confirmed by the recipient. Such a row carries
    -- no reach (loadAdminScope skips it) and no RBAC role, so an operator alone
    -- cannot make someone an administrator. Same contract as 00064.
    activated_at   TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at     TIMESTAMPTZ,

    -- The shape rule, replacing two triggers from 00062: an owner's reach is
    -- defined by the ABSENCE of an application, a co-owner's by its presence.
    -- Neither half can be quietly contradicted by a stale row.
    CONSTRAINT admin_grants_role_shape CHECK (
        (admin_role = 'owner'    AND application_id IS NULL) OR
        (admin_role = 'co_owner' AND application_id IS NOT NULL)
    )
);

-- One live owner grant per (user, tenant). Soft-delete aware so an
-- administrator can be removed and later re-invited without colliding with
-- their own tombstone.
CREATE UNIQUE INDEX IF NOT EXISTS admin_grants_owner_key
    ON admin_grants (user_id, tenant_id)
    WHERE admin_role = 'owner' AND deleted_at IS NULL;

-- A co-owner holds one row per application, so uniqueness includes it.
CREATE UNIQUE INDEX IF NOT EXISTS admin_grants_coowner_key
    ON admin_grants (user_id, tenant_id, application_id)
    WHERE admin_role = 'co_owner' AND deleted_at IS NULL;

-- "Which tenants does this user administer?" — the login and /admin/my-tenants
-- query. This is the one that has to be fast: it runs on every admin login.
CREATE INDEX IF NOT EXISTS idx_admin_grants_user
    ON admin_grants (user_id)
    WHERE deleted_at IS NULL;

-- "Who administers this tenant?" — the per-tenant admin listing.
CREATE INDEX IF NOT EXISTS idx_admin_grants_tenant
    ON admin_grants (tenant_id, admin_role)
    WHERE deleted_at IS NULL;

-- "Who administers this application?" — without scanning the table.
CREATE INDEX IF NOT EXISTS idx_admin_grants_app
    ON admin_grants (application_id)
    WHERE deleted_at IS NULL;

-- Pending grants, for the "granted but never accepted" listing.
CREATE INDEX IF NOT EXISTS idx_admin_grants_pending
    ON admin_grants (user_id)
    WHERE activated_at IS NULL AND deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- Invariants a CHECK cannot express, because they reach another table.
-- ---------------------------------------------------------------------------

-- The invariant the whole separation rests on: only a tenant-level user may
-- administer anything. Application end users are created by paths that are
-- deliberately permissive — self-registration, Google/GitHub OAuth, SAML JIT —
-- and must never become administrators through one of them.
--
-- Ported from tenant_admins_assert_tenant_level_user (00062), MINUS its
-- users.tenant_id = NEW.tenant_id check. That check is precisely what forbade
-- cross-tenant administration: it required an administrator to live in the
-- tenant they administer. Dropping it is the point of this migration. What
-- replaces it is the rule that users.tenant_id is the credential home and
-- carries no authority of its own.
CREATE OR REPLACE FUNCTION admin_grants_assert_tenant_level_user()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  u_app_id BIGINT;
BEGIN
  SELECT u.application_id INTO u_app_id
  FROM users u WHERE u.id = NEW.user_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'admin_grants.user_id % does not exist', NEW.user_id
      USING ERRCODE = 'foreign_key_violation';
  END IF;

  IF u_app_id IS NOT NULL THEN
    RAISE EXCEPTION
      'admin_grants.user_id % is an application-scoped user (application_id %); administrators must be tenant-level',
      NEW.user_id, u_app_id
      USING ERRCODE = 'check_violation';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS admin_grants_tenant_level_user ON admin_grants;
CREATE TRIGGER admin_grants_tenant_level_user
  BEFORE INSERT OR UPDATE OF user_id ON admin_grants
  FOR EACH ROW EXECUTE FUNCTION admin_grants_assert_tenant_level_user();

-- A grant must not cross a tenant boundary: the named application has to belong
-- to the tenant the grant is about. Ported from
-- tenant_admin_app_scopes_assert_valid (00062); the owner half of that function
-- is now the CHECK above, so only the tenant-boundary half remains.
CREATE OR REPLACE FUNCTION admin_grants_assert_app_in_tenant()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  app_tenant_id BIGINT;
BEGIN
  -- Owners name no application; nothing to check.
  IF NEW.application_id IS NULL THEN
    RETURN NEW;
  END IF;

  SELECT tenant_id INTO app_tenant_id
  FROM oauth_clients WHERE id = NEW.application_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'admin_grants.application_id % does not exist', NEW.application_id
      USING ERRCODE = 'foreign_key_violation';
  END IF;

  IF app_tenant_id IS DISTINCT FROM NEW.tenant_id THEN
    RAISE EXCEPTION
      'application % belongs to tenant % but the grant is for tenant %',
      NEW.application_id, app_tenant_id, NEW.tenant_id
      USING ERRCODE = 'check_violation';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS admin_grants_app_in_tenant ON admin_grants;
CREATE TRIGGER admin_grants_app_in_tenant
  BEFORE INSERT OR UPDATE OF application_id, tenant_id ON admin_grants
  FOR EACH ROW EXECUTE FUNCTION admin_grants_assert_app_in_tenant();

-- Note: 00062's tenant_admins_clear_grants_on_promote has no counterpart here.
-- Promotion is now "soft-delete the co_owner rows, insert an owner row" in one
-- transaction — the CHECK makes a promoted row with a leftover application_id
-- impossible, so there is nothing for a trigger to clean up.

-- ---------------------------------------------------------------------------
-- Backfill from the 00062 model.
-- ---------------------------------------------------------------------------

-- An owner becomes one row with no application, preserving absence-means-all.
INSERT INTO admin_grants (user_id, tenant_id, admin_role, application_id, activated_at, created_at, updated_at)
SELECT ta.user_id, ta.tenant_id, 'owner', NULL, ta.activated_at, ta.created_at, ta.updated_at
FROM tenant_admins ta
WHERE ta.admin_role = 'owner'
  AND ta.deleted_at IS NULL
ON CONFLICT DO NOTHING;

-- A co-owner becomes one row per application they were granted.
--
-- A co-owner holding ZERO scopes produces ZERO rows, and that is correct: under
-- 00062 such an administrator already had no application access at all
-- (AdminScopeApps with an empty list, which RequireAppScope denies). Inventing a
-- row here would widen their authority during a migration, which is the one
-- thing a migration must never do.
INSERT INTO admin_grants (user_id, tenant_id, admin_role, application_id, activated_at, created_at, updated_at)
SELECT ta.user_id, ta.tenant_id, 'co_owner', sc.application_id, ta.activated_at, ta.created_at, ta.updated_at
FROM tenant_admins ta
JOIN tenant_admin_app_scopes sc ON sc.admin_id = ta.id
WHERE ta.admin_role = 'co_owner'
  AND ta.deleted_at IS NULL
ON CONFLICT DO NOTHING;

-- invited_by is deliberately left NULL by this backfill.
--
-- 00062's invited_by referenced tenant_admins(id) — one row per administrator.
-- Here an administrator may hold several rows (a co-owner, one per application),
-- so "the inviter's grant" is ambiguous: mapping it would mean choosing one of
-- the inviter's rows to name, and any choice is arbitrary.
--
-- The column is provenance metadata, not authorization — nothing reads it to
-- decide access. A NULL reads as "unknown, predates the new model", which is
-- true. A wrongly-mapped value would read as fact and misattribute who onboarded
-- a privileged account, which is worse than not knowing. The 00062 chain remains
-- intact in tenant_admins for as long as that table exists, so the history is not
-- lost — only not duplicated.
--
-- Grants created AFTER this migration populate invited_by normally.

-- ---------------------------------------------------------------------------
-- Backfill verification. Each block raises if the migration changed anyone's
-- reach; the whole migration is one transaction, so a raise rolls it back.
--
-- These run against real data at deploy time, which is the only place the
-- backfill can actually be wrong. Do not remove them once the migration has
-- shipped — a re-run on a restored backup needs them just as much.
-- ---------------------------------------------------------------------------

DO $$
DECLARE
  n BIGINT;
BEGIN
  -- 1. Every live owner produced exactly one all-applications grant.
  SELECT COUNT(*) INTO n
  FROM tenant_admins ta
  WHERE ta.admin_role = 'owner' AND ta.deleted_at IS NULL
    AND NOT EXISTS (
      SELECT 1 FROM admin_grants g
      WHERE g.user_id = ta.user_id AND g.tenant_id = ta.tenant_id
        AND g.admin_role = 'owner' AND g.application_id IS NULL
        AND g.deleted_at IS NULL);
  IF n > 0 THEN
    RAISE EXCEPTION 'admin_grants backfill: % live owner(s) have no matching grant', n;
  END IF;

  -- 2. Every live co-owner application scope produced exactly one grant.
  SELECT COUNT(*) INTO n
  FROM tenant_admin_app_scopes sc
  JOIN tenant_admins ta ON ta.id = sc.admin_id
  WHERE ta.deleted_at IS NULL
    AND NOT EXISTS (
      SELECT 1 FROM admin_grants g
      WHERE g.user_id = ta.user_id AND g.tenant_id = ta.tenant_id
        AND g.admin_role = 'co_owner' AND g.application_id = sc.application_id
        AND g.deleted_at IS NULL);
  IF n > 0 THEN
    RAISE EXCEPTION 'admin_grants backfill: % co-owner application scope(s) have no matching grant', n;
  END IF;

  -- 3. THE SECURITY CHECK: no grant invented reach that did not exist before.
  -- Queries 1 and 2 prove nothing was lost; this one proves nothing was gained.
  SELECT COUNT(*) INTO n
  FROM admin_grants g
  WHERE g.deleted_at IS NULL
    AND NOT EXISTS (
      SELECT 1 FROM tenant_admins ta
      WHERE ta.user_id = g.user_id AND ta.tenant_id = g.tenant_id
        AND ta.admin_role = g.admin_role AND ta.deleted_at IS NULL);
  IF n > 0 THEN
    RAISE EXCEPTION 'admin_grants backfill: % grant(s) confer reach with no 00062 counterpart', n;
  END IF;

  -- 4. activated_at preserved — a pending grant must not have become live.
  SELECT COUNT(*) INTO n
  FROM admin_grants g
  JOIN tenant_admins ta
    ON ta.user_id = g.user_id AND ta.tenant_id = g.tenant_id AND ta.admin_role = g.admin_role
  WHERE ta.deleted_at IS NULL AND g.deleted_at IS NULL
    AND (ta.activated_at IS NULL) <> (g.activated_at IS NULL);
  IF n > 0 THEN
    RAISE EXCEPTION 'admin_grants backfill: % grant(s) changed activation state', n;
  END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- tenants.primary_admin_id
-- ---------------------------------------------------------------------------

-- The primary administrator is the billing contact and the default target when
-- ownership is handed over. It stays a single nullable FK on the parent, so
-- "two rows both claim primary" remains unrepresentable (00062).
--
-- Added alongside the old column rather than replacing it: the old one keeps
-- working while ADMIN_GRANTS_ENABLED is off, which is what makes step 3
-- reversible. The 00062 column is dropped in the same release that drops
-- tenant_admins.
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS primary_admin_grant_id BIGINT
    REFERENCES admin_grants(id) ON DELETE SET NULL;

UPDATE tenants t
SET primary_admin_grant_id = g.id
FROM tenant_admins ta
JOIN admin_grants g
  ON g.user_id = ta.user_id
 AND g.tenant_id = ta.tenant_id
 AND g.admin_role = ta.admin_role
 AND g.deleted_at IS NULL
WHERE t.primary_admin_id = ta.id
  AND t.primary_admin_grant_id IS NULL;

-- Record that users.tenant_id no longer means what its name suggests for an
-- administrator. A comment is not enforcement, but it is where the next person
-- to write a query against this column will look.
COMMENT ON COLUMN users.tenant_id IS
  'The tenant whose credentials, sessions, MFA and email flows this account uses — its HOME tenant. For an administrator this is NOT their administrative reach: see admin_grants, which may span several tenants. Do not use this column to decide what an admin may access.';

COMMENT ON TABLE admin_grants IS
  'Administrative reach: which tenants, and how much of each, a user administers. application_id IS NULL means every application in the tenant, present and future (owner); NOT NULL means exactly that application (co_owner). Permissions come from admin_role, not from the row.';

-- +goose StatementEnd


-- +goose Down
-- +goose StatementBegin

-- Reversible in full: nothing in the Up section modifies or removes 00062 data.
-- tenant_admins and tenant_admin_app_scopes were left intact and authoritative,
-- so dropping admin_grants returns the system to its pre-migration state.

ALTER TABLE tenants DROP COLUMN IF EXISTS primary_admin_grant_id;

COMMENT ON COLUMN users.tenant_id IS NULL;

DROP TRIGGER IF EXISTS admin_grants_app_in_tenant ON admin_grants;
DROP FUNCTION IF EXISTS admin_grants_assert_app_in_tenant();

DROP TRIGGER IF EXISTS admin_grants_tenant_level_user ON admin_grants;
DROP FUNCTION IF EXISTS admin_grants_assert_tenant_level_user();

DROP TABLE IF EXISTS admin_grants;

-- +goose StatementEnd
