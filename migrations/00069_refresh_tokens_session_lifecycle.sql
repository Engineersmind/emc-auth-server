-- +goose NO TRANSACTION
--
-- Runs outside a transaction on purpose. Two statements below require it:
--   * the batched backfill COMMITs between batches, which is only legal when
--     goose is not already holding an outer transaction;
--   * CREATE INDEX CONCURRENTLY cannot run inside a transaction block at all.
--
-- refresh_tokens is the largest table in a long-lived deployment (one row per
-- token rotation, and nothing has ever deleted from it), so the naive form of
-- this migration — an unqualified UPDATE followed by SET NOT NULL — would rewrite
-- the whole table under an ACCESS EXCLUSIVE lock and take auth down for the
-- duration. Every step here is either metadata-only or chunked.

-- +goose Up
-- +goose StatementBegin

-- Step 1 — add the columns. Metadata-only in PostgreSQL 11+: a non-volatile
-- DEFAULT is recorded in the catalogue rather than written to every existing row,
-- so this is fast regardless of table size.
ALTER TABLE refresh_tokens
    -- Idle clock. NULL means "written by a binary that predates this column".
    -- NULL is treated as "no idle limit" by the liveness predicate rather than
    -- as "expired": during a rolling deploy the old binary is still inserting
    -- rows with NULL here, and failing those closed would sign out every user
    -- mid-deploy. The backfill below drains the legacy rows; the NULL branch is
    -- transitional, not a permanent second meaning.
    ADD COLUMN IF NOT EXISTS idle_expires_at     TIMESTAMPTZ,

    -- The session family's hard deadline, measured from first authentication and
    -- copied forward UNCHANGED on every rotation. Without it, rotation that sets
    -- expires_at = NOW() + ttl lets a session refreshing once a day live
    -- forever, which is the sliding-window bug that makes an absolute cap
    -- meaningless. Same NULL semantics as above.
    ADD COLUMN IF NOT EXISTS absolute_expires_at TIMESTAMPTZ,

    -- False = the user did not ask to be remembered (shared/public machine), so
    -- the shorter non-persistent idle clock applies.
    ADD COLUMN IF NOT EXISTS is_persistent       BOOLEAN NOT NULL DEFAULT false,

    -- When the user actually authenticated, carried forward across rotations.
    -- Distinct from created_at, which on a rotated row is when the TOKEN was
    -- minted, not when the human proved who they were. Required to answer OIDC
    -- max_age / prompt=login and to gate step-up ("re-authenticate for this
    -- action"). Recorded now even though nothing reads it yet: authentication
    -- context that was never captured cannot be backfilled later.
    ADD COLUMN IF NOT EXISTS auth_time           TIMESTAMPTZ,

    -- OIDC "amr" — which methods were used (password, totp, email_otp, …).
    ADD COLUMN IF NOT EXISTS amr                 TEXT[] NOT NULL DEFAULT '{}',

    -- Why the session ended. Makes "show me every session terminated by policy"
    -- a query rather than an inference from timestamps; compliance reviewers ask
    -- for exactly that.
    ADD COLUMN IF NOT EXISTS revoked_reason      TEXT;

-- +goose StatementEnd

-- +goose StatementBegin

-- Step 2 — batched backfill.
--
-- A PROCEDURE rather than a DO block because only a procedure may COMMIT, and
-- committing between batches is the entire point: it releases row locks as it
-- goes instead of holding every row until one giant transaction ends.
--
-- Legacy rows get an idle deadline derived from their own last activity, so a
-- session that has genuinely been idle for a month is already past its idle
-- deadline the moment this lands and will not be listed as active. That is the
-- intended effect — those sessions are what the 400-plus session lists are made
-- of — and it is why the platform-default idle TTL is seeded generously at 7
-- days in migration 00067.
CREATE OR REPLACE PROCEDURE emc_backfill_refresh_token_lifecycle()
LANGUAGE plpgsql AS $$
DECLARE
    batch_size CONSTANT INTEGER := 10000;
    touched    INTEGER;
BEGIN
    LOOP
        WITH batch AS (
            SELECT id FROM refresh_tokens
            WHERE idle_expires_at IS NULL OR absolute_expires_at IS NULL
            LIMIT batch_size
            FOR UPDATE SKIP LOCKED
        )
        UPDATE refresh_tokens rt
           SET idle_expires_at =
                   COALESCE(rt.idle_expires_at,
                            COALESCE(rt.last_used_at, rt.created_at) + INTERVAL '7 days'),
               absolute_expires_at =
                   -- The family's deadline, not this row's: the oldest row in the
                   -- family is the one that carries the real first-authentication
                   -- time, and every row in the family must agree on the cap or
                   -- rotation would keep picking a later one.
                   COALESCE(rt.absolute_expires_at,
                            (SELECT MIN(f.created_at) FROM refresh_tokens f
                              WHERE f.session_family_id = rt.session_family_id
                                AND f.user_id = rt.user_id
                                AND f.tenant_id = rt.tenant_id) + INTERVAL '30 days'),
               auth_time = COALESCE(rt.auth_time, rt.created_at)
          FROM batch
         WHERE rt.id = batch.id;

        GET DIAGNOSTICS touched = ROW_COUNT;
        COMMIT;
        EXIT WHEN touched = 0;
    END LOOP;
END $$;

-- +goose StatementEnd

-- +goose StatementBegin

CALL emc_backfill_refresh_token_lifecycle();

-- +goose StatementEnd

-- +goose StatementBegin

DROP PROCEDURE IF EXISTS emc_backfill_refresh_token_lifecycle();

-- +goose StatementEnd

-- +goose StatementBegin

-- Step 3 — repair legacy session_family_id = 0 rows.
--
-- Migration 00026 backfilled NULL family ids, but a later single-statement CTE in
-- issueTokenPair left family_id at 0 on every fresh login until it was fixed
-- (see the comment in internal/auth/service.go). Those rows are dangerous rather
-- than merely wrong: family 0 is shared across users and tenants, so a
-- replay-triggered family revoke on one user's family-0 token would revoke
-- family 0 for EVERY user, and the grace-window lookup could return a different
-- user's identity. The Go side is now scoped by user_id + tenant_id as well,
-- which closes the hole independently; this repairs the data so the sessions are
-- also listed and revocable individually.
--
-- Each row becomes its own family. The true grouping is unrecoverable — every
-- affected row was written with the same id 0, so which rotation belonged to
-- which login is not recorded anywhere. Splitting them is the honest outcome:
-- it over-counts sessions rather than silently collapsing unrelated ones into a
-- single revocable unit.
UPDATE refresh_tokens SET session_family_id = id WHERE session_family_id = 0;

-- +goose StatementEnd

-- +goose StatementBegin

-- Step 4 — index the liveness predicate the application now filters on.
-- CONCURRENTLY so it does not block writes on a large table.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_refresh_tokens_live
    ON refresh_tokens (user_id, tenant_id, session_family_id)
    WHERE revoked_at IS NULL AND deleted_at IS NULL;

-- +goose StatementEnd

-- +goose StatementBegin

-- Serves the reaper, which deletes by whichever deadline fell last.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_refresh_tokens_reap
    ON refresh_tokens (expires_at)
    WHERE deleted_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX CONCURRENTLY IF EXISTS idx_refresh_tokens_reap;

-- +goose StatementEnd

-- +goose StatementBegin

DROP INDEX CONCURRENTLY IF EXISTS idx_refresh_tokens_live;

-- +goose StatementEnd

-- +goose StatementBegin

-- Does not restore session_family_id = 0: that state was a bug, and the rows it
-- affected are indistinguishable from each other, so there is nothing to restore
-- them to. Dropping the lifecycle columns reverts every session to the old
-- single-clock 30-day behaviour.
ALTER TABLE refresh_tokens
    DROP COLUMN IF EXISTS revoked_reason,
    DROP COLUMN IF EXISTS amr,
    DROP COLUMN IF EXISTS auth_time,
    DROP COLUMN IF EXISTS is_persistent,
    DROP COLUMN IF EXISTS absolute_expires_at,
    DROP COLUMN IF EXISTS idle_expires_at;

-- +goose StatementEnd
