-- +goose Up
-- +goose StatementBegin
-- Add name as nullable first so existing rows are not immediately constrained.
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS name TEXT;

-- Backfill: use client_id as a unique deterministic value per row.
UPDATE oauth_clients SET name = client_id WHERE name IS NULL OR name = '';

-- Now enforce NOT NULL.
ALTER TABLE oauth_clients ALTER COLUMN name SET NOT NULL;

-- Create unique index (IF NOT EXISTS is safe on re-runs).
CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_clients_tenant_name
    ON oauth_clients (tenant_id, name)
    WHERE deleted_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_oauth_clients_tenant_name;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS name;
-- +goose StatementEnd
