-- +goose Up
-- +goose StatementBegin

-- Give an application a display name distinct from its name.
--
-- oauth_clients has only `name`, which serves two jobs that pull apart: the
-- identifier an operator recognises in the applications table, and the label an
-- end user should see. Renaming for the second breaks the first.
--
-- Nullable with no default, matching tenants.display_name: NULL and '' both mean
-- "not set", and every read falls back with
-- COALESCE(NULLIF(display_name, ''), name). Nothing has to be backfilled, and
-- every existing application keeps rendering exactly as it does today.
--
-- No unique constraint. Two applications may legitimately show the same label to
-- their users; uniqueness lives on client_id, which is what actually identifies
-- a client. Adding one here would reject a reasonable configuration.
--
-- No CHECK on length either — the API caps it (200 chars, mirroring the
-- tenants.name bound) so the error is a 400 with a message rather than a
-- constraint violation surfacing as a 500.

ALTER TABLE oauth_clients
  ADD COLUMN IF NOT EXISTS display_name text;

COMMENT ON COLUMN oauth_clients.display_name IS
  'Optional end-user-facing label. NULL/empty means fall back to name, which '
  'every read does via COALESCE(NULLIF(display_name, ''''), name). Distinct from '
  'name, the operator-facing identifier shown in the applications directory.';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE oauth_clients DROP COLUMN IF EXISTS display_name;

-- +goose StatementEnd
