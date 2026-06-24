-- +goose Up
-- +goose StatementBegin
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '';

CREATE UNIQUE INDEX idx_oauth_clients_tenant_name
    ON oauth_clients (tenant_id, name)
    WHERE deleted_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_oauth_clients_tenant_name;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS name;
-- +goose StatementEnd
