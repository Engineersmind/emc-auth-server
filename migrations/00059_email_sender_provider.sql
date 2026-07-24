-- +goose Up
-- +goose StatementBegin

-- Multi-provider senders: a per-scope sender may now dispatch via SendGrid's
-- Web API instead of an SMTP relay. `provider` selects the transport; SendGrid
-- rows store an AES-256-GCM encrypted API key in `api_key_enc` (never returned)
-- and leave the smtp_* columns empty. Existing rows default to 'smtp', so the
-- change is backward compatible.

ALTER TABLE email_sender_settings
    ADD COLUMN IF NOT EXISTS provider    TEXT NOT NULL DEFAULT 'smtp'
        CHECK (provider IN ('smtp', 'sendgrid')),
    ADD COLUMN IF NOT EXISTS api_key_enc TEXT NOT NULL DEFAULT '';

-- SendGrid rows have no SMTP host; allow smtp_host to be empty. App-level
-- validation enforces the correct fields per provider.
ALTER TABLE email_sender_settings
    ALTER COLUMN smtp_host DROP NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE email_sender_settings
    ALTER COLUMN smtp_host SET NOT NULL;

ALTER TABLE email_sender_settings
    DROP COLUMN IF EXISTS api_key_enc,
    DROP COLUMN IF EXISTS provider;

-- +goose StatementEnd
