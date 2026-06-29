-- +goose Up
-- +goose StatementBegin
-- Change ip_address from TEXT NOT NULL DEFAULT '' to INET NULL.
--
-- Safety: NULLIF only handles exact empty-string rows. Any row containing a
-- non-IP string such as "unknown", "localhost", or "N/A" would cause
-- `invalid input syntax for type inet` and abort the migration.
--
-- Guard: the regex whitelist accepts only valid IPv4/IPv6 characters
-- ([0-9a-fA-F.:] plus an optional /prefix). Everything else becomes NULL,
-- which is the correct sentinel for "IP address unavailable".
ALTER TABLE audit_logs
    ALTER COLUMN ip_address DROP DEFAULT,
    ALTER COLUMN ip_address DROP NOT NULL,
    ALTER COLUMN ip_address TYPE INET
        USING CASE
            WHEN ip_address ~ '^[0-9a-fA-F.:]+(/[0-9]{1,3})?$' THEN ip_address::INET
            ELSE NULL
        END;

-- Replace the B-tree index on created_at with a BRIN (append-only table,
-- ~100x smaller, still excellent for time-range scans).
DROP INDEX IF EXISTS idx_audit_logs_created_at;
CREATE INDEX brin_audit_created ON audit_logs USING BRIN (created_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS brin_audit_created;
CREATE INDEX idx_audit_logs_created_at ON audit_logs (created_at DESC);
ALTER TABLE audit_logs
    ALTER COLUMN ip_address TYPE TEXT USING COALESCE(ip_address::TEXT, ''),
    ALTER COLUMN ip_address SET NOT NULL,
    ALTER COLUMN ip_address SET DEFAULT '';
-- +goose StatementEnd
