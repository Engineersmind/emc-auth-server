-- +goose Up
-- +goose StatementBegin

-- Migration 00031 replaced the plain UNIQUE constraint on tenants.slug with a
-- partial unique index (WHERE deleted_at IS NULL). PostgreSQL only allows
-- ON CONFLICT (slug) DO NOTHING when a plain named constraint exists; a partial
-- index requires the full predicate in the ON CONFLICT clause.
-- Re-add the plain constraint so seed and upsert code can use the simpler form.
ALTER TABLE tenants ADD CONSTRAINT tenants_slug_key UNIQUE (slug);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_slug_key;
-- +goose StatementEnd
