-- +goose Up
-- +goose StatementBegin

-- Per-scope email branding + explicit TLS mode for white-label senders.
-- These let a tenant or application control the sender identity (display name,
-- reply-to) and message branding (product name, logo, subject prefix) shown in
-- transactional emails, and pin the SMTP TLS mode instead of deriving it from
-- the port. All default to empty so existing rows keep today's behaviour
-- (server defaults / port-derived TLS).
ALTER TABLE email_sender_settings
    ADD COLUMN IF NOT EXISTS from_name      TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS reply_to       TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS product_name   TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS logo_url       TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS subject_prefix TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS tls_mode       TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE email_sender_settings
    DROP COLUMN IF EXISTS from_name,
    DROP COLUMN IF EXISTS reply_to,
    DROP COLUMN IF EXISTS product_name,
    DROP COLUMN IF EXISTS logo_url,
    DROP COLUMN IF EXISTS subject_prefix,
    DROP COLUMN IF EXISTS tls_mode;

-- +goose StatementEnd
