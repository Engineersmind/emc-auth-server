-- +goose Up
-- +goose StatementBegin
CREATE TABLE totp_secrets (
    user_id      BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    tenant_id    BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    secret_enc   TEXT NOT NULL,
    is_active    BOOLEAN NOT NULL DEFAULT false,
    backup_codes TEXT[] NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS totp_secrets;
-- +goose StatementEnd
