-- +goose Up
-- +goose StatementBegin

-- Drop tenants.description.
--
-- The column was write-only for its whole life. The create-tenant form collected
-- it, CreateTenant/UpdateTenant persisted it, and every tenant read selected it
-- into TenantResult.Description — but nothing ever displayed it: not the tenant
-- table, not the tenant detail page, and it was excluded from the ILIKE search
-- that covers name, display_name and domain. All six existing tenants have it
-- NULL or empty, which is the observable proof that nobody could enter a value
-- worth keeping.
--
-- Removed rather than left in place because a field that is collected and stored
-- but never shown is worse than no field: it asks an operator for information,
-- implies it will be used somewhere, and silently discards the effort.
--
-- Data loss is real but empty: this drops a column whose every row is
-- NULL/''. Down re-adds it nullable, so the schema is restorable even though the
-- (absent) content is not.
--
-- Distinct from permissions.description and app_rate_limits.description, which
-- ARE read and displayed and are untouched here.

ALTER TABLE tenants DROP COLUMN IF EXISTS description;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS description text;

-- +goose StatementEnd
