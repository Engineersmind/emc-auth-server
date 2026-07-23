-- +goose Up
-- +goose StatementBegin
-- Re-key per-app rate limits on the numeric oauth_clients.id (the identifier
-- carried by the JWT `app_id` claim and the /applications/:appID admin routes),
-- replacing the free-form TEXT app_id that was matched against the now-retired
-- X-App-ID request header.
--
-- Fresh start: existing rows are keyed on stale header strings with no reliable
-- mapping to an oauth_clients row, so they are discarded rather than backfilled.
--
-- This is a deliberate, non-reversible data loss: any tenant that had hardened a
-- per-app limit (e.g. 5 req/min on a sensitive app) reverts to the server
-- default (60 req/min) until reconfigured. Emit a NOTICE with the row count so
-- the loss is visible in deploy logs and operators know to reconfigure limits.
DO $$
DECLARE
  n bigint;
BEGIN
  SELECT COUNT(*) INTO n FROM app_rate_limits;
  IF n > 0 THEN
    RAISE NOTICE 'app_rate_limits: deleting % existing per-app limit row(s) — these were keyed on the retired X-App-ID header and cannot be backfilled. Reconfigure per-app limits after migration; affected apps fall back to the % req/min default meanwhile.', n, 60;
  END IF;
END $$;

DELETE FROM app_rate_limits;

-- Drop the old text-keyed unique index and column.
DROP INDEX IF EXISTS idx_app_limits_tenant_app;
ALTER TABLE app_rate_limits DROP COLUMN app_id;

-- Numeric FK to the application. The table is now empty, so NOT NULL is safe.
ALTER TABLE app_rate_limits
    ADD COLUMN application_id BIGINT NOT NULL
    REFERENCES oauth_clients(id) ON DELETE CASCADE;

-- One live limit per (tenant, application).
CREATE UNIQUE INDEX idx_app_limits_tenant_app
    ON app_rate_limits (tenant_id, application_id)
    WHERE deleted_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_app_limits_tenant_app;
ALTER TABLE app_rate_limits DROP COLUMN application_id;
ALTER TABLE app_rate_limits ADD COLUMN app_id TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX idx_app_limits_tenant_app
    ON app_rate_limits (tenant_id, app_id)
    WHERE deleted_at IS NULL;
-- +goose StatementEnd
