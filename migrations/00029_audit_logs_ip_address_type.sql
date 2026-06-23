-- +goose Up
-- +goose StatementBegin
-- Change ip_address from TEXT NOT NULL DEFAULT '' to INET NULL.
-- Empty strings in existing rows become NULL (NULLIF handles the cast safely).
ALTER TABLE audit_logs
    ALTER COLUMN ip_address DROP DEFAULT,
    ALTER COLUMN ip_address DROP NOT NULL,
    ALTER COLUMN ip_address TYPE INET USING NULLIF(ip_address, '')::INET;

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
