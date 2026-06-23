-- +goose Up
-- +goose StatementBegin
CREATE TABLE email_verification_tokens (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    tenant_id  UUID        NOT NULL REFERENCES tenants(id)  ON DELETE CASCADE,
    token_hash TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_evt_hash        ON email_verification_tokens (token_hash);
CREATE INDEX        brin_evt_created    ON email_verification_tokens USING BRIN (created_at);
CREATE INDEX        idx_evt_user_tenant ON email_verification_tokens (user_id, tenant_id)
    WHERE used_at IS NULL AND deleted_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS email_verification_tokens;
-- +goose StatementEnd

