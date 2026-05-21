-- +goose Up
-- +goose StatementBegin
ALTER TABLE tenants
    ADD COLUMN cors_origins TEXT[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN tenants.cors_origins IS
    'Allowed CORS origins for this tenant, e.g. {"https://app.example.com","https://admin.example.com"}. Empty array means no CORS headers are set.';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE tenants DROP COLUMN IF EXISTS cors_origins;
-- +goose StatementEnd
