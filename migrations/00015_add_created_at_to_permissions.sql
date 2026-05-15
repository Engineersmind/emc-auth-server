-- +goose Up
-- +goose StatementBegin
-- Add created_at to permissions (missed in original schema).
ALTER TABLE permissions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE permissions DROP COLUMN IF EXISTS created_at;
-- +goose StatementEnd
