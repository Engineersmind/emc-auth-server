-- +goose Up
-- +goose StatementBegin

-- Make the one-default-per-application index soft-delete aware — issue #146.
--
-- 00043 created roles_one_default_per_app before anything soft-deleted a role,
-- so its predicate never needed a deleted_at clause:
--
--     ON roles (tenant_id, application_id)
--     WHERE is_default = true AND application_id IS NOT NULL
--
-- 00044 later taught the two NAME-uniqueness indexes about deleted_at, but left
-- this one behind. That asymmetry is invisible while DeleteRole issues a real
-- DELETE — the row leaves the table, so it leaves every index with it.
--
-- #146 converts DeleteRole to a soft delete, and the row then STAYS. A deleted
-- role still carrying is_default = true goes on occupying the (tenant_id,
-- application_id) slot forever, and the next SetDefaultRole for that
-- application fails with 23505 against an index row the operator cannot see
-- and has no statement to clear. The application can never have a default role
-- again, which silently turns off role assignment at registration for every
-- user who signs up afterwards.
--
-- Landed as its own migration, and deliberately BEFORE the code change: nothing
-- writes roles.deleted_at yet, so on current data this rebuild is a no-op — the
-- new predicate selects exactly the rows the old one did. That makes it safe to
-- deploy on its own and keeps the risky half of #146 out of a migration that
-- would otherwise have to run against live data.
--
-- DeleteRole also clears is_default in the same UPDATE. Both are kept: the
-- index is the durable guarantee for rows written by any future path, and the
-- explicit clear keeps the flag honest for anything that reads the column
-- rather than the index.
DROP INDEX IF EXISTS roles_one_default_per_app;

CREATE UNIQUE INDEX IF NOT EXISTS roles_one_default_per_app
    ON roles (tenant_id, application_id)
    WHERE is_default = true AND application_id IS NOT NULL AND deleted_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Restores 00043's predicate. This can fail where Up succeeded: if a
-- soft-deleted role and a live one both hold is_default = true for the same
-- application, the narrower index permits it and the original does not. That is
-- precisely the state this migration exists to allow, so clear the flag on the
-- deleted rows before rolling back:
--
--     UPDATE roles SET is_default = false
--      WHERE deleted_at IS NOT NULL AND is_default = true;
DROP INDEX IF EXISTS roles_one_default_per_app;

CREATE UNIQUE INDEX IF NOT EXISTS roles_one_default_per_app
    ON roles (tenant_id, application_id)
    WHERE is_default = true AND application_id IS NOT NULL;

-- +goose StatementEnd
