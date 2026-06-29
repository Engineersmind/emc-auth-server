-- +goose Up
-- +goose StatementBegin
ALTER TABLE user_credentials
    ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE user_credentials DROP COLUMN IF EXISTS password_changed_at;
-- +goose StatementEnd
