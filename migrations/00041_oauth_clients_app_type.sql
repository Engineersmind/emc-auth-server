-- +goose Up
-- +goose StatementBegin
-- Application type drives the FE creation wizard and list filters (EMC-004).
--   web    — server-side web app (confidential client)
--   spa    — single-page app (public client)
--   m2m    — machine-to-machine service (client_credentials only)
--   native — mobile / desktop app
ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS app_type TEXT NOT NULL DEFAULT 'web'
    CHECK (app_type IN ('web', 'spa', 'm2m', 'native'));

CREATE INDEX IF NOT EXISTS idx_oauth_clients_tenant_type
    ON oauth_clients (tenant_id, app_type)
    WHERE deleted_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_oauth_clients_tenant_type;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS app_type;
-- +goose StatementEnd
