-- +goose Up
-- +goose StatementBegin

-- Issue #6 — EMC becomes an OAuth 2.0 authorization server.
--
-- Everything here is additive with safe defaults: an existing deployment that
-- applies this migration and keeps running the old binary behaves exactly as
-- before, because every new column's default reproduces current behaviour.

------------------------------------------------------------------------------
-- oauth_authorization_codes
------------------------------------------------------------------------------

-- grant_kind separates two DIFFERENT credentials that share this table.
--
--   login_code         — the 60s hand-back code minted by createLoginCode()
--                        after a social (Google/GitHub) login, redeemed at
--                        POST /auth/oauth/exchange with the public client_id
--                        alone. No PKCE. Predates this migration.
--   authorization_code — an RFC 6749 §4.1 code minted by GET /oauth/authorize
--                        and redeemed at POST /oauth/token, mandatorily bound
--                        to a PKCE code_challenge.
--
-- Without this discriminator the two are indistinguishable, and ExchangeLoginCode
-- — which matches on (code_hash, client_id) and checks NO code_challenge —
-- would happily redeem a PKCE-protected authorization code using nothing but the
-- public client_id. That is a silent, total PKCE bypass. Both consumers filter
-- on this column; neither is optional.
--
-- DEFAULT 'login_code' backfills every pre-existing row correctly: everything in
-- this table today was written by createLoginCode.
ALTER TABLE oauth_authorization_codes
    ADD COLUMN IF NOT EXISTS grant_kind TEXT NOT NULL DEFAULT 'login_code'
    CHECK (grant_kind IN ('login_code', 'authorization_code'));

-- OIDC nonce (OIDC Core §3.1.2.1). Carried from the authorize request to the ID
-- token so a client can bind the token to its own session and detect replay.
-- Security audit 2026-08-07 FED-3 names this a required control before an
-- inbound authorize endpoint exists. NULL = not supplied, which is legal for a
-- plain OAuth 2.0 (non-OIDC) request.
ALTER TABLE oauth_authorization_codes
    ADD COLUMN IF NOT EXISTS nonce TEXT;

-- The authorize request's granted scopes already live in the existing `scopes`
-- column. What is missing is which user-agent the code was issued to, so the
-- token exchange can refuse a code lifted from another browser.
ALTER TABLE oauth_authorization_codes
    ADD COLUMN IF NOT EXISTS auth_time TIMESTAMPTZ;

-- Security audit DATA-12: this table has a unique index on code_hash and a BRIN
-- on created_at, and nothing else. Both lookups below are on the hot path.
CREATE INDEX IF NOT EXISTS idx_oauth_codes_tenant_client
    ON oauth_authorization_codes (tenant_id, client_id);

-- Also DATA-12: no cleanup job deletes expired rows today, and when one is
-- written it would sequential-scan without this.
CREATE INDEX IF NOT EXISTS idx_oauth_codes_expires
    ON oauth_authorization_codes (expires_at);

------------------------------------------------------------------------------
-- oauth_clients
------------------------------------------------------------------------------

-- PKCE is mandatory for every client type, confidential included (OAuth 2.1).
-- A confidential client that leaks a code still loses it to whoever holds the
-- code unless a verifier is required. The column exists so a future integration
-- that genuinely cannot do PKCE can be exempted deliberately and visibly,
-- rather than by weakening the check for everyone.
ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS require_pkce BOOLEAN NOT NULL DEFAULT true;

-- first_party drives the consent decision.
--
--   true  — the client belongs to the same tenant as the user's account, so a
--           consent screen would be nonsense ("do you allow Acme's app to
--           access your Acme account?"). Auth0 skips consent here too.
--   false — a genuinely third-party client. A consent screen is REQUIRED before
--           issuing a code, and no consent screen exists yet, so /oauth/authorize
--           refuses with error=consent_required.
--
-- DEFAULT true is correct for every row that exists today: every oauth_clients
-- record is created by a tenant admin for that tenant's own applications, and
-- there is no path for an outsider to register one.
--
-- The refusal branch is deliberate. Defaulting a third-party client to
-- "skip consent" would silently hand a stranger's application a token for a
-- user who was never told — the exact harm consent exists to prevent. Failing
-- closed makes the missing screen impossible to ship past by accident.
ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS first_party BOOLEAN NOT NULL DEFAULT true;

-- redirect_uris already exists (migration 00032) but has never been written or
-- read by any code path. Issue #6 activates it as the authoritative exact-match
-- allow-list for /oauth/authorize. No DDL needed — recorded here because the
-- column changing from dead to load-bearing is the kind of thing a reader of
-- this migration history needs to know.
--
-- It is NOT the same list as identity_provider_configs.redirect_allow, which is
-- per social provider and governs where a login_code is handed back. Different
-- flow, different column, deliberately kept separate.

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_oauth_codes_expires;
DROP INDEX IF EXISTS idx_oauth_codes_tenant_client;

ALTER TABLE oauth_clients DROP COLUMN IF EXISTS first_party;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS require_pkce;

ALTER TABLE oauth_authorization_codes DROP COLUMN IF EXISTS auth_time;
ALTER TABLE oauth_authorization_codes DROP COLUMN IF EXISTS nonce;
ALTER TABLE oauth_authorization_codes DROP COLUMN IF EXISTS grant_kind;

-- +goose StatementEnd
