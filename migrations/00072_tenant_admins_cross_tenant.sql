-- +goose Up
-- +goose StatementBegin

-- Allow a tenant administrator to administer a tenant that is not their home
-- tenant, in the legacy 00062 model.
--
-- Migration 00071 lifted the one-tenant-per-administrator limit in admin_grants,
-- but tenant_admins is still written on every invitation (the dual-write that
-- keeps ADMIN_GRANTS_ENABLED reversible), and its trigger asserts
--
--     users.tenant_id = tenant_admins.tenant_id
--
-- so the legacy write fails before the mirror is ever reached. The observable
-- symptom is not an error: InviteTenantAdmin looks the recipient up with
-- "WHERE tenant_id = $1 AND email = $2", finds nothing for an address that lives
-- in another tenant, and creates a SECOND users row — a parallel account with its
-- own password hash, its own MFA enrolment, and its own audit history, sharing
-- only the email string. Both passwords then work, each signing the operator in
-- as a different person who administers exactly one tenant, and switching between
-- them is refused because neither holds a grant in the other's tenant.
--
-- The same-tenant assertion is what has to go. What replaces it is the rule
-- 00071 states: users.tenant_id is where an account's CREDENTIALS live — its home
-- tenant — and carries no administrative authority of its own. Reach is
-- admin_grants (and, until it is dropped, tenant_admins).
--
-- The other half of the trigger is KEPT and still matters: an application-scoped
-- user (users.application_id IS NOT NULL) must never become a tenant
-- administrator. Application end users are created by deliberately permissive
-- paths — self-registration, Google/GitHub OAuth, SAML JIT — and that assertion
-- is the boundary between those populations. Only the tenant equality is relaxed.

CREATE OR REPLACE FUNCTION tenant_admins_assert_tenant_level_user()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  u_app_id BIGINT;
BEGIN
  SELECT u.application_id INTO u_app_id
  FROM users u WHERE u.id = NEW.user_id;

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

  -- Deliberately no users.tenant_id = NEW.tenant_id check: see the header.
  RETURN NEW;
END;
$$;


-- The other half of the same limit: tenant_admins_user_key (00062) is UNIQUE on
-- user_id ALONE, so one person could hold exactly one administration row in the
-- entire system. Relaxing the trigger above lets the row reference a foreign
-- tenant; this lets a SECOND row exist at all.
--
-- Widened to (user_id, tenant_id): one live administration per person per tenant,
-- which is the invariant that was actually intended. Still soft-delete aware, so
-- an administrator can be removed and later re-invited without colliding with
-- their own tombstone.
--
-- Mirrors admin_grants_owner_key in 00071. The two models must agree on
-- cardinality for the dual-write to be meaningful.
DROP INDEX IF EXISTS tenant_admins_user_key;
CREATE UNIQUE INDEX IF NOT EXISTS tenant_admins_user_tenant_key
    ON tenant_admins (user_id, tenant_id)
    WHERE deleted_at IS NULL;

-- +goose StatementEnd


-- +goose Down
-- +goose StatementBegin

-- Restores 00062's single-administration-per-user index. Like the trigger below,
-- this cannot succeed while a person holds administrations in two tenants — the
-- CREATE will fail on the duplicate rather than silently discard one, which is
-- the correct failure: which of the two to drop is a data decision.
DROP INDEX IF EXISTS tenant_admins_user_tenant_key;
CREATE UNIQUE INDEX IF NOT EXISTS tenant_admins_user_key
    ON tenant_admins (user_id)
    WHERE deleted_at IS NULL;

-- Restores 00062's single-tenant assertion verbatim.
--
-- NOT safe to run once cross-tenant administrators exist: rows already committed
-- are not re-validated by restoring the trigger, so the constraint would hold for
-- new writes while the existing violations stay. Reverting therefore needs those
-- rows removed first, which is a data decision rather than a schema one.
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

-- +goose StatementEnd
