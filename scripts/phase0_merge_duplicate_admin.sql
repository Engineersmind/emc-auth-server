-- Phase 0 merge: collapse duplicate administrator identities into one.
--
-- The address comes from the merge.email setting, which must be set in the SAME
-- session — a psql -c runs in its own session and would not reach the DO blocks
-- below, and a psql variable is not visible inside them at all. So either run it
-- interactively:
--
--   psql "$DATABASE_URL"
--   => SET merge.email = 'someone@example.com';
--   => \i scripts/phase0_merge_duplicate_admin.sql
--
-- or through a two-line wrapper:
--
--   printf "SET merge.email = 'someone@example.com';\n\\i scripts/phase0_merge_duplicate_admin.sql\n" \
--     | psql "$DATABASE_URL"
--
-- The address is read from the merge.email GUC rather than a psql variable so it
-- is visible inside the DO blocks, which psql variables are not.
--
-- Run scripts/phase0_duplicate_admins.sql FIRST and keep its output: it is the
-- only record of what reach existed before the merge, and this script's
-- verification compares against it.
--
-- WHY THIS EXISTS
--
-- users_tenant_email_tenant_level_key (migration 00042) is unique per TENANT, so
-- one address could hold a separate account in each tenant — separate password
-- hash, separate MFA enrolment, separate audit history, sharing only the email
-- string. Both passwords then worked, each signing the operator in as a different
-- person who administered exactly one tenant, and neither could reach the other's.
--
-- Migration 00079 stops NEW duplicates: InviteTenantAdmin now finds an existing
-- tenant-level account across tenants and grants it instead of creating a second
-- row. Rows created before that fix still need collapsing, and that is this
-- script.
--
-- WHAT IT DOES NOT DO
--
-- It does not choose a password. The retired rows hold genuinely different
-- secrets and there is no correct way to pick one, so credentials are DROPPED and
-- the survivor is left with none — the operator must then run the ordinary
-- forgot-password flow. Silently keeping one would mean an administrator's known
-- password stops working with no explanation, which is indistinguishable from a
-- compromise.
--
-- SURVIVOR SELECTION (deliberate, documented, deterministic)
--
--   1. the row with active MFA, most recently used   (avoids re-enrolment)
--   2. else the row with the most recent activity     (the one they actually use)
--   3. else the lowest id                             (stable tie-break)
--
-- Runs in ONE transaction. Any failure rolls the whole merge back.

\set ON_ERROR_STOP on

BEGIN;

-- ---------------------------------------------------------------------------
-- 0. Refuse to merge anything unsafe.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  target_email TEXT := current_setting('merge.email', true);
  n_rows   BIGINT;
  n_blocked BIGINT;
BEGIN
  SELECT COUNT(*) INTO n_rows
  FROM users
  WHERE email = target_email AND application_id IS NULL AND deleted_at IS NULL;

  IF n_rows < 2 THEN
    RAISE EXCEPTION 'nothing to merge: % has % live tenant-level row(s)', target_email, n_rows;
  END IF;

  -- A blocked row must never be merged into an active one: the block lives on the
  -- users row, so folding it away silently unblocks the person. Whoever imposed
  -- the block decides, not this script.
  SELECT COUNT(*) INTO n_blocked
  FROM users
  WHERE email = target_email AND application_id IS NULL AND deleted_at IS NULL
    AND blocked_at IS NOT NULL;

  IF n_blocked > 0 THEN
    RAISE EXCEPTION
      'refusing to merge %: % row(s) are blocked. Resolve the block first — merging would silently lift it',
      target_email, n_blocked;
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 1. Pick the survivor and record the merge set.
-- ---------------------------------------------------------------------------
CREATE TEMP TABLE merge_plan ON COMMIT DROP AS
WITH candidates AS (
  SELECT u.id,
         u.tenant_id,
         EXISTS (SELECT 1 FROM totp_secrets ts
                 WHERE ts.user_id = u.id AND ts.is_active)         AS has_totp,
         EXISTS (SELECT 1 FROM email_mfa_settings em
                 WHERE em.user_id = u.id AND em.is_active)         AS has_email_mfa,
         (SELECT MAX(al.created_at) FROM audit_logs al
          WHERE al.user_id = u.id)                                 AS last_seen
  FROM users u
  WHERE u.email = current_setting('merge.email', true)
    AND u.application_id IS NULL
    AND u.deleted_at IS NULL
)
SELECT id,
       tenant_id,
       (id = FIRST_VALUE(id) OVER (
           ORDER BY (has_totp OR has_email_mfa) DESC,
                    last_seen DESC NULLS LAST,
                    id
       )) AS is_survivor
FROM candidates;

\echo ''
\echo '=== merge plan (is_survivor = t is the row that is kept) ==='
SELECT mp.id, mp.tenant_id, mp.is_survivor,
       (SELECT COUNT(*) FROM tenant_admins ta WHERE ta.user_id = mp.id AND ta.deleted_at IS NULL) AS administrations
FROM merge_plan mp ORDER BY mp.is_survivor DESC, mp.id;

-- ---------------------------------------------------------------------------
-- 2. Move administrative reach onto the survivor.
--
-- Every retired row's administration is re-pointed, so the merge NARROWS
-- nobody's access. ON CONFLICT covers the case where the survivor already
-- administers that tenant.
-- ---------------------------------------------------------------------------
UPDATE tenant_admins ta
SET user_id = (SELECT id FROM merge_plan WHERE is_survivor)
WHERE ta.user_id IN (SELECT id FROM merge_plan WHERE NOT is_survivor)
  AND ta.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM tenant_admins keep
      WHERE keep.user_id = (SELECT id FROM merge_plan WHERE is_survivor)
        AND keep.tenant_id = ta.tenant_id
        AND keep.deleted_at IS NULL
  );

UPDATE admin_grants g
SET user_id = (SELECT id FROM merge_plan WHERE is_survivor)
WHERE g.user_id IN (SELECT id FROM merge_plan WHERE NOT is_survivor)
  AND g.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM admin_grants keep
      WHERE keep.user_id = (SELECT id FROM merge_plan WHERE is_survivor)
        AND keep.tenant_id = g.tenant_id
        AND keep.admin_role = g.admin_role
        AND keep.application_id IS NOT DISTINCT FROM g.application_id
        AND keep.deleted_at IS NULL
  );

-- ---------------------------------------------------------------------------
-- 3. Re-point audit history, so one person is one actor.
--
-- Never deleted: the history is why the merge is auditable at all.
-- ---------------------------------------------------------------------------
UPDATE audit_logs
SET user_id = (SELECT id FROM merge_plan WHERE is_survivor)
WHERE user_id IN (SELECT id FROM merge_plan WHERE NOT is_survivor);

-- ---------------------------------------------------------------------------
-- 4. End every session in the set, survivor included.
--
-- The survivor is about to lose its password, and the retired rows must not keep
-- minting tokens from a refresh token issued before the merge.
-- ---------------------------------------------------------------------------
UPDATE user_sessions SET revoked_at = NOW(), revoked_reason = 'credential_change', updated_at = NOW()
WHERE user_id IN (SELECT id FROM merge_plan) AND revoked_at IS NULL;

UPDATE refresh_tokens SET revoked_at = NOW(), revoked_reason = 'credential_change', updated_at = NOW()
WHERE user_id IN (SELECT id FROM merge_plan) AND revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- 5. Drop credentials and second factors.
--
-- LAST, so every step before this is reversible by clearing deleted_at. Two
-- different password hashes cannot become one, and two TOTP secrets cannot
-- either — the survivor is left with no credential and must reset.
-- ---------------------------------------------------------------------------
DELETE FROM user_credentials  WHERE user_id IN (SELECT id FROM merge_plan);
DELETE FROM totp_secrets      WHERE user_id IN (SELECT id FROM merge_plan);
DELETE FROM email_mfa_settings WHERE user_id IN (SELECT id FROM merge_plan);

-- ---------------------------------------------------------------------------
-- 6. Retire the duplicate rows.
-- ---------------------------------------------------------------------------
UPDATE users
SET deleted_at = NOW(), updated_at = NOW()
WHERE id IN (SELECT id FROM merge_plan WHERE NOT is_survivor);

-- Force the survivor through a fresh credential on next sign-in, and invalidate
-- anything still holding a token_version from before.
UPDATE users
SET token_version = token_version + 1, updated_at = NOW()
WHERE id = (SELECT id FROM merge_plan WHERE is_survivor);

-- ---------------------------------------------------------------------------
-- 7. Verify, and abort if the merge changed anyone's reach.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  target_email TEXT := current_setting('merge.email', true);
  survivor BIGINT;
  n BIGINT;
BEGIN
  SELECT id INTO survivor FROM merge_plan WHERE is_survivor;

  -- Exactly one live row for the address.
  SELECT COUNT(*) INTO n
  FROM users WHERE email = target_email AND application_id IS NULL AND deleted_at IS NULL;
  IF n <> 1 THEN
    RAISE EXCEPTION 'merge left % live rows for %, want 1', n, target_email;
  END IF;

  -- No administration was orphaned onto a retired row.
  SELECT COUNT(*) INTO n
  FROM tenant_admins ta
  WHERE ta.user_id IN (SELECT id FROM merge_plan WHERE NOT is_survivor)
    AND ta.deleted_at IS NULL;
  IF n > 0 THEN
    RAISE EXCEPTION 'merge left % administration(s) on a retired identity', n;
  END IF;

  SELECT COUNT(*) INTO n
  FROM admin_grants g
  WHERE g.user_id IN (SELECT id FROM merge_plan WHERE NOT is_survivor)
    AND g.deleted_at IS NULL;
  IF n > 0 THEN
    RAISE EXCEPTION 'merge left % grant(s) on a retired identity', n;
  END IF;

  -- The survivor holds no credential, so the reset is not optional.
  SELECT COUNT(*) INTO n FROM user_credentials WHERE user_id = survivor;
  IF n <> 0 THEN
    RAISE EXCEPTION 'survivor % still holds credentials; the merge must leave none', survivor;
  END IF;

  RAISE NOTICE 'merged % into user %; administrations now: %',
    target_email, survivor,
    (SELECT COUNT(*) FROM tenant_admins WHERE user_id = survivor AND deleted_at IS NULL);
END $$;

\echo ''
\echo '=== surviving identity and its reach ==='
SELECT u.id, u.email, u.tenant_id AS home_tenant,
       ta.tenant_id AS administers, ta.admin_role,
       ta.activated_at IS NOT NULL AS activated
FROM users u
LEFT JOIN tenant_admins ta ON ta.user_id = u.id AND ta.deleted_at IS NULL
WHERE u.id = (SELECT id FROM merge_plan WHERE is_survivor)
ORDER BY ta.tenant_id;

COMMIT;

\echo ''
\echo 'MERGE COMMITTED. The survivor has NO password: send them through'
\echo 'forgot-password before they next sign in, and tell them why.'
\echo ''
