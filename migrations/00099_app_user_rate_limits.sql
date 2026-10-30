-- +goose Up
-- +goose StatementBegin

-- Per-application overrides of the per-user rate limits (S2S rate limiting).
--
-- The application end-user routes limit each end user separately (login per
-- email, password-reset mail per email, token redemption per end-user IP, ...).
-- The server-wide defaults come from RATE_LIMIT_APP_* configuration; this table
-- lets an administrator raise or lower them for one application, within the
-- ceilings auth.UserLimitDefs enforces.
--
-- limits maps a limit key (auth.UserLimitDefs) to requests per minute. A key
-- that is absent uses the server default, so an application without a row —
-- every application today — behaves exactly as before.
CREATE TABLE IF NOT EXISTS app_user_rate_limits (
    application_id BIGINT      PRIMARY KEY REFERENCES oauth_clients(id) ON DELETE CASCADE,
    tenant_id      BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    limits         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_app_user_rate_limits_tenant
    ON app_user_rate_limits (tenant_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS app_user_rate_limits;
-- +goose StatementEnd
