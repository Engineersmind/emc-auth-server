-- +goose NO TRANSACTION
-- +goose Up

-- The admin user listing was taking fourteen seconds per page.
--
-- Found by auditing every read against a growth table at 970k users across a
-- skewed tenant distribution (one 700k tenant, six at 45k). The listing query
-- itself was fine — 0.19 ms, index-backed by 00081. What was slow is what runs
-- ALONGSIDE each returned row.
--
-- userEnrichmentColumns attaches four correlated subqueries to every row: last
-- login, login count, whether a password exists, and federated providers. At the
-- API's maximum page size of 100 that is 400 subqueries per request, and two of
-- them hit audit_logs — the fastest-growing table in the system.
--
-- Measured before, one page of 100:
--
--   full enrichment                        14155 ms
--     of which MAX(created_at) IN (...)     12038 ms
--     COUNT(*) action='auth.login'              2.1 ms
--     refresh_tokens MAX                        0.9 ms
--
-- Through the API that was a 60-second timeout on any page past the first, and
-- "context canceled" in the server log. The page-1 case looked healthy, which is
-- why it survived: the enrichment cost is per row, so it only becomes visible
-- once the table behind the subqueries is large.
--
-- Why the MAX was the expensive one, and why column ORDER fixes it.
--
-- An earlier attempt indexed (user_id, tenant_id, action) INCLUDE (created_at).
-- That made each subquery an Index Only Scan and the COUNT dropped to 2 ms — but
-- the MAX stayed at twelve seconds. Matching the WHERE clause is not enough for
-- an aggregate: to answer MAX the planner still had to read every matching row
-- and compare, because the index gave it no ordering to stop on.
--
-- Leading with (user_id, tenant_id, created_at DESC) and carrying action as an
-- INCLUDE column inverts that. The rows for one user arrive newest-first, so MAX
-- is the first entry that satisfies the action filter and the scan stops there.
-- The IN list is checked from the index payload without touching the heap.
--
-- 12038 ms -> 0.4 ms for that subquery; 14155 ms -> 2.9 ms for the whole
-- enrichment.
--
-- This is the third index in this series where matching the predicate was not
-- sufficient — 00082 records the other two. The pattern worth carrying forward:
-- an index that makes a query use an index is not the same as an index that
-- makes it fast, and only the plan says which one you have.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_user_recent
    ON audit_logs (user_id, tenant_id, created_at DESC) INCLUDE (action);

-- +goose Down

DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_user_recent;
