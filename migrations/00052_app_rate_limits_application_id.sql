-- +goose Up
-- +goose StatementBegin
-- Re-key per-app rate limits on the numeric oauth_clients.id (the identifier
-- carried by the JWT `app_id` claim and the /applications/:appID admin routes),
-- replacing the free-form TEXT app_id that was matched against the now-retired
-- X-App-ID request header.
--
-- Fresh start: existing rows are keyed on stale header strings with no reliable
-- mapping to an oauth_clients row, so they are discarded rather than backfilled.
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
