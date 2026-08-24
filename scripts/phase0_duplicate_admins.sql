-- Phase 0 inventory: duplicate tenant-level administrator identities.
--
-- READ-ONLY. Run this against production BEFORE migration 00071 and keep the
-- output — it is the only record of what administrative reach existed before the
-- merge, and 00071's verification queries use it as their reference.
--
--   psql "$DATABASE_URL" -f scripts/phase0_duplicate_admins.sql
--
-- Why this exists: users_tenant_email_tenant_level_key (migration 00042) is
-- UNIQUE on (tenant_id, email), so the same address may hold SEPARATE accounts
-- with SEPARATE passwords in different tenants. Multi-tenant administration
-- requires one identity per human, so those rows must be merged first — see
-- docs/plans/multi-tenant-admin-grants.md §5 for the procedure and the
-- survivor-selection rules.
--
-- If section 1 returns no rows, Phase 0 is a no-op and 00071 may proceed.

\echo ''
\echo '=== 1. Duplicate tenant-level emails (each row is one merge set) ==='
SELECT u.email,
       COUNT(*)                                   AS row_count,
       array_agg(u.tenant_id ORDER BY u.tenant_id) AS tenants,
       array_agg(u.id        ORDER BY u.id)        AS user_ids
FROM users u
WHERE u.application_id IS NULL
  AND u.deleted_at IS NULL
GROUP BY u.email
HAVING COUNT(*) > 1
ORDER BY COUNT(*) DESC, u.email;

\echo ''
\echo '=== 2. What each duplicate row carries (drives survivor selection) ==='
-- Survivor order per plan §5: active MFA first (avoids re-enrolment), then most
-- recent activity, then lowest id. MFA and blocked_at are the two columns that
-- decide whether a set can be merged automatically at all.
SELECT u.id,
       u.email,
       u.tenant_id,
       u.is_active,
       u.blocked_at IS NOT NULL AS blocked,
       u.email_verified,
       EXISTS (SELECT 1 FROM totp_secrets ts
               WHERE ts.user_id = u.id AND ts.is_active)        AS totp,
       EXISTS (SELECT 1 FROM email_mfa_settings em
               WHERE em.user_id = u.id AND em.is_active)        AS email_mfa,
       (SELECT COUNT(*)      FROM audit_logs al WHERE al.user_id = u.id) AS audit_rows,
       (SELECT MAX(al.created_at) FROM audit_logs al WHERE al.user_id = u.id) AS last_seen,
       (SELECT COUNT(*) FROM refresh_tokens rt
        WHERE rt.user_id = u.id AND rt.revoked_at IS NULL)      AS live_refresh_tokens
FROM users u
WHERE u.application_id IS NULL
  AND u.deleted_at IS NULL
  AND u.email IN (
      SELECT email FROM users
      WHERE application_id IS NULL AND deleted_at IS NULL
      GROUP BY email HAVING COUNT(*) > 1)
ORDER BY u.email, u.tenant_id;

\echo ''
\echo '=== 3. Administrative reach that must survive the merge ==='
-- Captured from the 00062 model, because Phase 0 runs before 00071 exists.
-- Every row here must reappear as an admin_grants row pointing at the survivor.
SELECT u.email,
       u.id            AS user_id,
       ta.tenant_id,
       ta.admin_role,
       ta.activated_at IS NOT NULL AS activated,
       COALESCE((SELECT array_agg(sc.application_id ORDER BY sc.application_id)
                 FROM tenant_admin_app_scopes sc
                 WHERE sc.admin_id = ta.id), '{}') AS granted_applications
FROM tenant_admins ta
JOIN users u ON u.id = ta.user_id
WHERE ta.deleted_at IS NULL
  AND u.deleted_at IS NULL
  AND u.email IN (
      SELECT email FROM users
      WHERE application_id IS NULL AND deleted_at IS NULL
      GROUP BY email HAVING COUNT(*) > 1)
ORDER BY u.email, ta.tenant_id;

\echo ''
\echo '=== 4. BLOCKED duplicates — escalate, do not merge ==='
-- Merging a blocked identity into an active one silently unblocks it. Resolve
-- the block by hand before the set is merged (plan §5).
SELECT u.id, u.email, u.tenant_id, u.blocked_at
FROM users u
WHERE u.application_id IS NULL
  AND u.deleted_at IS NULL
  AND u.blocked_at IS NOT NULL
  AND u.email IN (
      SELECT email FROM users
      WHERE application_id IS NULL AND deleted_at IS NULL
      GROUP BY email HAVING COUNT(*) > 1)
ORDER BY u.email;

\echo ''
\echo '=== 5. Summary ==='
SELECT (SELECT COUNT(*) FROM (
          SELECT email FROM users
          WHERE application_id IS NULL AND deleted_at IS NULL
          GROUP BY email HAVING COUNT(*) > 1) d)          AS merge_sets,
       (SELECT COUNT(*) FROM users u
        WHERE u.application_id IS NULL AND u.deleted_at IS NULL
          AND u.email IN (SELECT email FROM users
                          WHERE application_id IS NULL AND deleted_at IS NULL
                          GROUP BY email HAVING COUNT(*) > 1)) AS rows_involved,
       (SELECT COUNT(*) FROM users u
        WHERE u.application_id IS NULL AND u.deleted_at IS NULL
          AND u.blocked_at IS NOT NULL
          AND u.email IN (SELECT email FROM users
                          WHERE application_id IS NULL AND deleted_at IS NULL
                          GROUP BY email HAVING COUNT(*) > 1)) AS blocked_rows_needing_escalation;
\echo ''
\echo 'If merge_sets = 0, Phase 0 is a no-op and migration 00071 may proceed.'
\echo 'Otherwise: follow docs/plans/multi-tenant-admin-grants.md section 5.'
\echo ''
