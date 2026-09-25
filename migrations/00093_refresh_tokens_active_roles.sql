-- +goose Up
-- +goose StatementBegin

-- Persist a session's role scope across refresh rotation — issue #146, phase 4.
--
-- A client may narrow a session to a subset of the roles its user holds. The
-- narrowing is recorded in the access token's active_roles claim, but an access
-- token lives fifteen minutes and a session lives days: without somewhere
-- durable to keep it, the first refresh would mint a token carrying the user's
-- FULL permission set and the scope would evaporate.
--
-- That is not a cosmetic loss. It makes the feature a security hazard rather
-- than a security control: a client could ask for a support-scoped session,
-- rotate once, and silently come back holding everything the account can do —
-- a privilege escalation reachable by waiting. Narrowing has to be a property of
-- the SESSION, and the refresh-token chain is what carries session state here.
--
-- NULL means an unscoped session — the normal case, and what every existing row
-- gets. An empty array is deliberately NOT the same thing: it would mean "scoped
-- to no roles at all", a session whose role half resolves to nothing. Only NULL
-- means "no narrowing was requested".
ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS active_roles TEXT[];

COMMENT ON COLUMN refresh_tokens.active_roles IS
    'Role names this session was narrowed to at login (#146). NULL = unscoped, the full union of the user''s roles. Rotation copies it forward; widening requires a fresh login.';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Dropping this widens every scoped session still in flight to its user's full
-- role set on the next rotation. That is the pre-#146 behaviour and is safe only
-- because a scoped session can never hold MORE than its account does.
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS active_roles;

-- +goose StatementEnd
