-- +goose Up
-- +goose StatementBegin

-- Add dashboard metadata columns to the tenants table.
-- All columns are nullable / have defaults so existing rows are unaffected.
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS display_name TEXT,
    ADD COLUMN IF NOT EXISTS domain       TEXT,
    ADD COLUMN IF NOT EXISTS region       TEXT,
    ADD COLUMN IF NOT EXISTS description  TEXT,
    ADD COLUMN IF NOT EXISTS plan         TEXT NOT NULL DEFAULT 'free';

-- Support filtered list queries on region and plan.
CREATE INDEX IF NOT EXISTS idx_tenants_region ON tenants (region);
CREATE INDEX IF NOT EXISTS idx_tenants_plan   ON tenants (plan);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_tenants_region;
DROP INDEX IF EXISTS idx_tenants_plan;

ALTER TABLE tenants
    DROP COLUMN IF EXISTS display_name,
    DROP COLUMN IF EXISTS domain,
    DROP COLUMN IF EXISTS region,
    DROP COLUMN IF EXISTS description,
    DROP COLUMN IF EXISTS plan;

-- +goose StatementEnd
