-- +goose Up
-- +goose StatementBegin
ALTER TABLE tenants               ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE users                 ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE user_credentials      ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE roles                 ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE permissions           ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE refresh_tokens        ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE api_keys              ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE password_reset_tokens ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE totp_secrets          ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE app_rate_limits       ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE tenants               DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE users                 DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE user_credentials      DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE roles                 DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE permissions           DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE refresh_tokens        DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE api_keys              DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE password_reset_tokens DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE totp_secrets          DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE app_rate_limits       DROP COLUMN IF EXISTS deleted_at;
-- +goose StatementEnd
