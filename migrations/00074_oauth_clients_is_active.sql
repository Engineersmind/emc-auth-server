-- +goose Up
-- +goose StatementBegin

-- Give an application a suspended state that is distinct from deletion.
--
-- Until now "is_active" was not stored anywhere. Every read computed it as
--
--     (deleted_at IS NULL) AS is_active
--
-- so the only way to make an application inactive was to delete it. That
-- conflates two operations an operator needs to keep apart: revoking a
-- compromised integration's ability to get tokens (reversible, keeps the row,
-- keeps the audit trail, keeps the client_id so nothing has to be re-registered)
-- and removing the application (not reversible from the UI).
--
-- The column is the authority for one rule: an inactive application's client
-- credentials do not authenticate. Enforcement lives in the three lookups that
-- gate token issuance -- AuthenticateClient (client_credentials), LookupClient
-- (/oauth/authorize), and the social-login application resolve in oauthflow.go.
--
-- Two other lookups deliberately do NOT filter on it:
--
--   * ResolveClient (application.go) attributes audit events, including
--     failures. Filtering there would drop the tenant/application from the audit
--     record of the very request being refused -- so a suspended application's
--     rejected token attempts would become untraceable, which is the opposite of
--     what suspending it is for.
--   * the per-application rate-limit resolve (applimit.go). A suspended client
--     that keeps hammering the token endpoint must still be rate limited; going
--     unkeyed there would exempt it from limits precisely when it is
--     misbehaving.
--
-- DEFAULT true, NOT NULL: every existing application stays active, so this
-- migration changes no live behaviour on its own. It is safe to apply ahead of
-- the code that reads it -- the added predicate is true for every current row.

ALTER TABLE oauth_clients
  ADD COLUMN IF NOT EXISTS is_active boolean NOT NULL DEFAULT true;

COMMENT ON COLUMN oauth_clients.is_active IS
  'False suspends the application: its client credentials stop authenticating '
  '(client_credentials, /oauth/authorize, social login) while the row, its '
  'client_id and its audit history are preserved. Distinct from deleted_at, '
  'which removes the application. Audit attribution and rate limiting '
  'deliberately ignore this flag so a suspended client is still traceable and '
  'still throttled.';

-- Partial index over the active-and-not-deleted set. Every hot lookup is
-- "client_id = $1 AND deleted_at IS NULL AND is_active", and the existing
-- unique index on client_id cannot serve the added predicates from the index
-- alone. Not UNIQUE: idx_oauth_clients_client_id already guarantees uniqueness
-- across all rows, and duplicating it here would wrongly permit two rows
-- sharing a client_id once one of them is suspended.
CREATE INDEX IF NOT EXISTS idx_oauth_clients_client_id_active
  ON oauth_clients (client_id)
  WHERE deleted_at IS NULL AND is_active;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_oauth_clients_client_id_active;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS is_active;

-- +goose StatementEnd
