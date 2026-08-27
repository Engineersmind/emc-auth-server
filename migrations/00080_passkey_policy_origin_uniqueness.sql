-- +goose Up
-- +goose StatementBegin

-- One origin may only be claimed along a single resolution chain — issue #116.
--
-- THE BUG THIS CLOSES
--
-- /auth/passkey/login/begin takes no identifier at all, deliberately: that is
-- what stops it being used to probe which accounts exist. So the ONLY thing
-- available to decide which relying party the ceremony runs as is the Origin
-- header, resolved by PasskeyPolicyService.loadByOrigin:
--
--     WHERE $1 = ANY(origins)
--     ORDER BY application_id NULLS LAST, tenant_id NULLS LAST
--     LIMIT 1
--
-- Nothing in migration 00072 stopped two unrelated scopes from listing the same
-- origin, and LIMIT 1 then picked between them by lowest application_id — which
-- is to say arbitrarily. It could not leak across tenants (the chosen row's
-- rp_id decides the relying party, and a browser only offers credentials bound
-- to that exact rp_id, so the other claimant's credentials are never presented;
-- LoginComplete then re-resolves policy from the credential's own tenant and
-- re-checks it). But it failed silently at every layer: the user clicks "sign in
-- with a passkey", their authenticator offers nothing, and the server logs a
-- generic verification failure.
--
-- WHY A TRIGGER AND NOT A CONSTRAINT
--
-- The natural expression is an exclusion constraint —
-- EXCLUDE USING gist (origins WITH &&) — and it is not available. Postgres ships
-- no GiST operator class for TEXT[] (btree_gist does not cover arrays, intarray
-- is integer-only), and GIN, which does implement &&, cannot back an exclusion
-- constraint because it has no amgettuple. A partial unique index cannot express
-- it either: the uniqueness is over the UNNESTED array, and an index expression
-- must be single-valued.
--
-- So: a trigger. It is enforced for every writer including psql, which is the
-- requirement — the Go-level check in SetPolicy gives an operator a readable
-- sentence, and this makes the invariant true regardless of who writes.
--
-- WHAT COUNTS AS A CONFLICT
--
-- Resolution walks application -> tenant -> platform default, so an ancestor and
-- its descendant sharing an origin is meaningful and stays legal: an application
-- overriding its own tenant's origin is precisely what most-specific-wins is
-- for. What has no interpretation is two scopes on DIFFERENT chains claiming one
-- origin. Refused:
--
--     (t1, NULL) vs (t2, NULL)     two tenants
--     (t,  a1)   vs (t,  a2)       two applications of one tenant
--     (t1, a)    vs (t2, NULL)     one tenant's application vs another tenant
--
-- Allowed:
--
--     (NULL, NULL) vs anything     the platform row is every chain's ancestor
--     (t, NULL)    vs (t, a)       a tenant and its own application
--
-- Note that last pair is why this is stated as "different chains" rather than
-- "same specificity": the third refused case is a genuine collision between two
-- rows of DIFFERENT specificity, which a same-specificity rule would admit.
CREATE OR REPLACE FUNCTION passkey_policies_reject_origin_overlap()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    conflict_tenant BIGINT;
    conflict_app    BIGINT;
    overlap         TEXT[];
BEGIN
    -- No origins, nothing to claim. Also the common case for the platform row
    -- and for every tenant that inherits the server's relying party, so it is
    -- worth returning before the query.
    IF NEW.origins IS NULL OR cardinality(NEW.origins) = 0 THEN
        RETURN NEW;
    END IF;

    -- The platform row is the ancestor of every chain and cannot conflict with
    -- anything. Left explicit rather than relying on the NULL comparison below
    -- doing the right thing by accident.
    IF NEW.tenant_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT p.tenant_id, p.application_id,
           ARRAY(SELECT unnest(p.origins) INTERSECT SELECT unnest(NEW.origins))
      INTO conflict_tenant, conflict_app, overlap
      FROM passkey_policies p
     WHERE p.origins && NEW.origins
       AND p.tenant_id IS NOT NULL
       -- Exclude the row being written. On UPDATE the row is already in the
       -- table, so without this every UPDATE that keeps its own origins would
       -- conflict with itself.
       AND p.id IS DISTINCT FROM NEW.id
       -- NOT on the same chain: shares this tenant, and either row is the
       -- tenant-level one (making one the other's ancestor) or both name the
       -- same application.
       AND NOT (p.tenant_id = NEW.tenant_id
                AND (p.application_id IS NULL
                     OR NEW.application_id IS NULL
                     OR p.application_id = NEW.application_id))
     ORDER BY p.tenant_id, p.application_id NULLS FIRST
     LIMIT 1;

    IF conflict_tenant IS NOT NULL THEN
        -- Scope rendered the same way checkOriginConflicts renders it in Go
        -- (scopeDescription), so an operator sees one sentence whichever layer
        -- refused the write.
        RAISE EXCEPTION
            'passkey origin conflict: origin % is already claimed by the % passkey policy',
            array_to_string(overlap, ', '),
            CASE WHEN conflict_app IS NULL
                 THEN format('tenant %s', conflict_tenant)
                 ELSE format('application %s (tenant %s)', conflict_app, conflict_tenant)
            END
            -- exclusion_violation, deliberately NOT unique_violation: this IS
            -- semantically an exclusion constraint (overlapping arrays), and
            -- SetPolicy already reads a unique violation on this table as "another
            -- writer created the row between our UPDATE and our INSERT" and tells
            -- the caller to retry. Sharing that code would answer an origin
            -- conflict with "please retry" — advice for a write that can never
            -- succeed.
            USING ERRCODE = 'exclusion_violation',
                  HINT = 'two scopes on different resolution chains cannot claim one origin; remove it from the other scope first';
    END IF;

    RETURN NEW;
END;
$$;

-- +goose StatementEnd

-- +goose StatementBegin

-- Fail the migration rather than install a trigger over data that already
-- violates it — a constraint that was true only for future writes would read as
-- an invariant while not being one.
--
-- Expected to be vacuous: passkeys ship disabled, and 00072's
-- passkey_policies_origins_need_rp_id means a row can only hold origins once a
-- tenant has set its own rp_id, which no deployment has done yet.
DO $$
DECLARE
    n INTEGER;
BEGIN
    SELECT count(*) INTO n
      FROM passkey_policies a
      JOIN passkey_policies b ON b.id > a.id AND b.origins && a.origins
     WHERE a.tenant_id IS NOT NULL AND b.tenant_id IS NOT NULL
       AND NOT (a.tenant_id = b.tenant_id
                AND (a.application_id IS NULL
                     OR b.application_id IS NULL
                     OR a.application_id = b.application_id));
    IF n > 0 THEN
        RAISE EXCEPTION
            'cannot enforce passkey origin uniqueness: % pre-existing conflicting pair(s)', n
            USING HINT = 'resolve the overlapping origins by hand, then re-run this migration';
    END IF;
END $$;

-- +goose StatementEnd

-- +goose StatementBegin

CREATE TRIGGER passkey_policies_origin_overlap
    BEFORE INSERT OR UPDATE OF tenant_id, application_id, origins
    ON passkey_policies
    FOR EACH ROW
    EXECUTE FUNCTION passkey_policies_reject_origin_overlap();

-- +goose StatementEnd

-- +goose StatementBegin

-- Supports both the trigger's lookup and loadByOrigin's own WHERE
-- $1 = ANY(origins). GIN over the array is the index that can serve a
-- containment test; without it every ceremony start is a sequential scan of the
-- table, which is small today and is on the login path.
CREATE INDEX IF NOT EXISTS passkey_policies_origins_gin
    ON passkey_policies USING GIN (origins);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS passkey_policies_origins_gin;
DROP TRIGGER IF EXISTS passkey_policies_origin_overlap ON passkey_policies;
DROP FUNCTION IF EXISTS passkey_policies_reject_origin_overlap();

-- +goose StatementEnd
