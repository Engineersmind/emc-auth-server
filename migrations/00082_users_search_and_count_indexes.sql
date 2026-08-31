-- +goose NO TRANSACTION
-- +goose Up

-- Corrects the search index shipped in 00081 and covers the count paths that a
-- wider audit found still scanning.
--
-- 00081 was written after checking thirteen queries. This migration follows an
-- audit of every query touching a table that grows with the userbase — 139 call
-- sites across users, audit_logs, refresh_tokens, user_sessions and
-- webauthn_credentials. Four more problems surfaced, one of them a defect in
-- 00081 itself.

-- ---------------------------------------------------------------------------
-- 1. Replace the user-search index. 00081's version was never used.
--
-- 00081 indexed a CONCATENATION:
--
--     gin ((email || ' ' || first_name || ' ' || last_name) gin_trgm_ops)
--
-- but the query it was meant to serve matches the three columns SEPARATELY:
--
--     email ILIKE $1 OR first_name ILIKE $1 OR last_name ILIKE $1
--
-- Postgres cannot use an index on an expression to satisfy a predicate on the
-- underlying columns, so the planner ignored it and kept the sequential scan.
-- The index was built, occupied disk, was maintained on every write, and did
-- nothing. Measured at 300k users: still 121 ms, exactly as before 00081.
--
-- Three per-column indexes match the query's shape, so the planner can BitmapOr
-- them together — which is precisely what it does. Same data, 1.05 ms.
--
-- The lesson worth recording: an index that is built successfully is not an
-- index that is used. 00081 verified the index existed and was valid; it did not
-- re-check the plan of the query it was for.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
DO $$
BEGIN
    BEGIN
        CREATE EXTENSION IF NOT EXISTS pg_trgm;
    EXCEPTION WHEN insufficient_privilege OR feature_not_supported THEN
        RAISE NOTICE 'pg_trgm unavailable (%) — user search stays a sequential scan', SQLERRM;
        RETURN;
    END;

    DROP INDEX IF EXISTS idx_users_search_trgm;

    CREATE INDEX IF NOT EXISTS idx_users_email_trgm
        ON users USING gin (email gin_trgm_ops) WHERE deleted_at IS NULL;
    CREATE INDEX IF NOT EXISTS idx_users_first_name_trgm
        ON users USING gin (first_name gin_trgm_ops) WHERE deleted_at IS NULL;
    CREATE INDEX IF NOT EXISTS idx_users_last_name_trgm
        ON users USING gin (last_name gin_trgm_ops) WHERE deleted_at IS NULL;
END $$;
-- +goose StatementEnd

-- ---------------------------------------------------------------------------
-- 2. Tenant-scoped user count.
--
-- Every paginated user listing runs a COUNT(*) alongside it to produce the total
-- for the pager. idx_users_tenant_created leads with tenant_id, but its second
-- column forces the planner to consider ordering it does not need for a count,
-- and it chose a sequential scan instead: 22.6 ms at 300k rows, on every page
-- load.
--
-- A narrow index on tenant_id alone lets the count run index-only. Note
-- idx_users_tenant already exists with this definition — it is kept, and this
-- entry documents why it must not be dropped as redundant with
-- idx_users_tenant_created. They serve different plans.
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- 3. Audit count for pagination.
--
-- Same shape as the users count and the same 28.8 ms cost, on a table that grows
-- faster than any other in the system: audit_logs takes a row per authentication
-- event, so it outpaces the user table by orders of magnitude.
--
-- The existing audit indexes lead with (tenant_id, created_at) for the listing.
-- This one is tenant_id alone, for the count.
-- ---------------------------------------------------------------------------
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_tenant_count
    ON audit_logs (tenant_id);

-- ---------------------------------------------------------------------------
-- 4. New-device risk baseline.
--
-- The risk engine asks "which user agents has this account signed in from
-- before?" (internal/security/risk: SELECT DISTINCT user_agent ...). That ran as
-- a sequential scan at 39.8 ms — on the LOGIN path, so every sign-in paid it
-- once the audit table grew.
--
-- The column list mirrors the query's actual predicate exactly:
--
--     WHERE user_id = $1 AND action = $2 AND status = 'success'
--       AND user_agent <> '' AND created_at > $3
--
-- so user_id and action lead, created_at supports the range, and user_agent is
-- INCLUDEd to make the DISTINCT index-only. status and the non-empty check go in
-- the partial predicate because they are constants in the query, which keeps the
-- index to the rows that can answer it.
--
-- Note there is no tenant_id: the query does not filter on it. An earlier draft
-- of this index led with (user_id, tenant_id) and was ignored by the planner for
-- exactly that reason — the same mistake as the search index above, caught the
-- same way, by re-reading the plan rather than trusting the index to be used.
-- Measured: 27.9 ms -> 0.47 ms, Index Only Scan.
-- ---------------------------------------------------------------------------
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_new_device_baseline
    ON audit_logs (user_id, action, created_at DESC) INCLUDE (user_agent)
    WHERE status = 'success' AND user_agent <> '';

-- ---------------------------------------------------------------------------
-- 5. Live sessions for one user.
--
-- The self-service "where am I signed in" listing scanned user_sessions. Small
-- today at 0.6 ms, but the table holds a row per active session per user, so it
-- scales with concurrent sessions rather than with accounts — and this endpoint
-- is in the account UI, not an admin corner.
-- ---------------------------------------------------------------------------
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_user_live
    ON user_sessions (user_id, tenant_id, last_seen_at DESC)
    WHERE revoked_at IS NULL;

-- +goose Down

DROP INDEX CONCURRENTLY IF EXISTS idx_user_sessions_user_live;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_new_device_baseline;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_tenant_count;

-- +goose StatementBegin
DO $$
BEGIN
    DROP INDEX IF EXISTS idx_users_last_name_trgm;
    DROP INDEX IF EXISTS idx_users_first_name_trgm;
    DROP INDEX IF EXISTS idx_users_email_trgm;

    -- Restore 00081's index so a rollback lands on that migration's schema,
    -- even though it was never usable. Guarded because pg_trgm may be absent.
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm') THEN
        CREATE INDEX IF NOT EXISTS idx_users_search_trgm
            ON users USING gin (
                (COALESCE(email,'') || ' ' || COALESCE(first_name,'') || ' ' || COALESCE(last_name,''))
                gin_trgm_ops
            )
            WHERE deleted_at IS NULL;
    END IF;
END $$;
-- +goose StatementEnd
