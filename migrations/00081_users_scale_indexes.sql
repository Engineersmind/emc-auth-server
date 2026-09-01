-- +goose NO TRANSACTION
-- +goose Up

-- Indexes the users table needs once a tenant holds more than a few thousand
-- accounts.
--
-- Found by loading 500,000 users into a single tenant and re-running the query
-- set. At the 22 rows a development database carries, every plan below looked
-- fine: Postgres reads the whole table either way and no index can beat that.
-- The regression only appears with real volume, which is why it reached this
-- point unnoticed.
--
-- Measured before, at 500k rows in one tenant:
--
--   ListUsers page 1                       52.6 ms   Seq Scan + top-N sort
--   ListUsers deep offset                  44.4 ms   Seq Scan + top-N sort
--   ListUsers with search                 119.6 ms   Seq Scan
--   Login lookup by email (tenant-level)   23.5 ms   Seq Scan
--   stats: users_this_month                68.2 ms   Seq Scan
--
-- Through the API that was 14 req/s on the user list and 7.5 req/s on the stats
-- card, against 614 and 2053 at 22 rows. The admin console becomes unusable long
-- before login does — login itself was unaffected, because Argon2id dominates it
-- and the seeded admin happened to match another index.
--
-- CONCURRENTLY, and therefore NO TRANSACTION, because users is the hottest table
-- in the system: a plain CREATE INDEX takes ACCESS EXCLUSIVE and blocks every
-- write — including logins — for the duration of the build. On a large table
-- that is an outage. The cost is that a failed build leaves an INVALID index
-- behind rather than rolling back; see the Down section for how to clear one.

-- ---------------------------------------------------------------------------
-- 1. Tenant-scoped listing, newest first.
--
-- ListUsers is ORDER BY created_at DESC LIMIT n. idx_users_tenant covers
-- tenant_id alone, so Postgres could find the tenant's rows but then had to sort
-- all of them to take 25. Leading with tenant_id and carrying created_at in the
-- index lets it walk the index backwards and stop at the limit.
--
-- DESC in the index definition matches the query's direction. Postgres can scan
-- an ASC index backwards, so this is not strictly required, but stating it keeps
-- the intent legible and avoids a backward scan on the hot path.
--
-- The partial predicate matches the query's own WHERE clause. Every read of this
-- table filters deleted_at IS NULL, so indexing soft-deleted rows would enlarge
-- the index for rows no query ever wants.
-- ---------------------------------------------------------------------------
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_tenant_created
    ON users (tenant_id, created_at DESC)
    WHERE deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- 2. Login by email with no tenant.
--
-- The tenant-level login path searches by email ALONE — it cannot name a tenant,
-- because finding which tenant the account lives in is the point of the lookup
-- (see AuthService.Login). idx_users_login_covering leads with
-- (tenant_id, email, ...), and a b-tree cannot serve a predicate that skips its
-- leading column, so that index was unusable here and the planner fell back to a
-- parallel sequential scan.
--
-- It did not show up as slow in practice only because the seeded admin account
-- is matched by another index first. Any account further into the table paid the
-- full scan: 23.5 ms measured, growing linearly with the table.
--
-- Partial on application_id IS NULL for the same reason the query is: an
-- application-scoped account is never a candidate for tenant-level login, and
-- excluding them keeps this index proportional to the administrator population
-- rather than to every end user in the system.
-- ---------------------------------------------------------------------------
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email_tenant_level
    ON users (email)
    WHERE application_id IS NULL AND deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- 3. Platform-wide creation-date reporting.
--
-- The dashboard's month-over-month figures filter on
-- DATE_TRUNC('month', created_at) across the whole table with no tenant
-- predicate, so index 1 does not apply. This one is created_at alone.
--
-- Note the query as written is not sargable — DATE_TRUNC on the column prevents
-- a range scan — so this index helps by being narrower to scan than the table,
-- not by seeking. Rewriting the predicate as a half-open range would let it seek
-- properly, but that is a code change and this migration deliberately only adds
-- indexes. Worth doing separately.
-- ---------------------------------------------------------------------------
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_created_at
    ON users (created_at)
    WHERE deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- 4. Search across name and email.
--
-- ListUsers offers a search box that runs
-- email ILIKE '%term%' OR first_name ILIKE '%term%' OR last_name ILIKE '%term%'.
-- A leading wildcard defeats a b-tree entirely, which is why the search path was
-- the slowest measured at 119.6 ms.
--
-- pg_trgm's GIN index is the standard answer: it indexes character trigrams, so
-- an infix match becomes a lookup rather than a scan. gin_trgm_ops on a
-- concatenation covers all three columns in one index, matching the OR the query
-- actually writes.
--
-- Created only if the extension is available. pg_trgm ships with PostgreSQL in
-- every mainstream distribution and on RDS, but it needs CREATE EXTENSION, which
-- requires elevated privileges some managed environments withhold. Rather than
-- fail the migration there, the block skips the index and logs — search stays as
-- slow as it is today, and nothing else in this migration is lost.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
DO $$
BEGIN
    BEGIN
        CREATE EXTENSION IF NOT EXISTS pg_trgm;
    EXCEPTION WHEN insufficient_privilege OR feature_not_supported THEN
        RAISE NOTICE 'pg_trgm unavailable (%) — skipping user-search index; '
                     'search remains a sequential scan', SQLERRM;
        RETURN;
    END;

    -- Not CONCURRENTLY: CREATE INDEX CONCURRENTLY cannot run inside a DO block,
    -- which is itself a transaction. This index is the optional one, so taking a
    -- brief lock is the acceptable trade for having it at all. On a table large
    -- enough for the lock to matter, create it by hand outside the migration.
    CREATE INDEX IF NOT EXISTS idx_users_search_trgm
        ON users USING gin (
            (COALESCE(email,'') || ' ' || COALESCE(first_name,'') || ' ' || COALESCE(last_name,''))
            gin_trgm_ops
        )
        WHERE deleted_at IS NULL;
END $$;
-- +goose StatementEnd

-- +goose Down

-- DROP INDEX CONCURRENTLY for the same reason the creates are concurrent: a
-- plain DROP takes ACCESS EXCLUSIVE on users.
--
-- IF EXISTS covers both an ordinary rollback and the case where a CONCURRENTLY
-- build failed and left an INVALID index: the name is present either way, and
-- dropping it is exactly how an invalid index is cleared before retrying.
DROP INDEX CONCURRENTLY IF EXISTS idx_users_search_trgm;
DROP INDEX CONCURRENTLY IF EXISTS idx_users_created_at;
DROP INDEX CONCURRENTLY IF EXISTS idx_users_email_tenant_level;
DROP INDEX CONCURRENTLY IF EXISTS idx_users_tenant_created;

-- pg_trgm is deliberately NOT dropped. Another migration or a DBA may have
-- created it, and an extension is a database-wide object: removing it here would
-- break anything else relying on it.
