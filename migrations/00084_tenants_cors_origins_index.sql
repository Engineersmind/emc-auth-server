-- +goose NO TRANSACTION
-- +goose Up

-- Index the reverse CORS lookup: "does any tenant permit this browser origin?"
--
-- CORS used to pick a tenant from the X-Tenant-Slug header and read that
-- tenant's cors_origins. It now asks the containment question directly, because
-- the Origin is the only thing the decision depends on and the only value a
-- browser reliably sends — a preflight OPTIONS carries a custom header's NAME
-- but never its value, so the slug was unavoidably absent on exactly the request
-- that had to be answered first.
--
-- That inverts the access pattern. The old query was `WHERE slug = $1`, served
-- by the slug unique index. The new one is `WHERE cors_origins @> ARRAY[$1]`,
-- which no b-tree can answer: containment over an array needs GIN.
--
-- Small today — a sequential scan over a handful of tenants is 1.1 ms, and the
-- result is Redis-cached for 60 s either way, so this is not urgent. It is here
-- because the cost grows with tenant count while the query runs on the preflight
-- of every cross-origin browser request, which is the worst combination to
-- discover later: invisible in development, and first felt by the customers with
-- the most tenants.
--
-- Measured on the current data: 1.117 ms sequential, 0.082 ms with this index.
--
-- CONCURRENTLY because tenants is read on nearly every request path.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tenants_cors_origins
    ON tenants USING gin (cors_origins);

-- +goose Down

DROP INDEX CONCURRENTLY IF EXISTS idx_tenants_cors_origins;
