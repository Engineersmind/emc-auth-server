package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// Authorization-server half of issue #6: EMC issuing its own authorization
// codes, as opposed to oauthflow.go where EMC consumes someone else's.
//
// The two are deliberately separate types over the same table. See GrantKind.

// GrantKind discriminates the two different credentials stored in
// oauth_authorization_codes (migration 00067).
//
// They are not interchangeable and must never be redeemable at each other's
// endpoint: a login_code is redeemable with the public client_id alone, while
// an authorization_code is bound to a PKCE verifier. If /auth/oauth/exchange
// could consume an authorization_code, PKCE would be bypassable by anyone who
// captured the code — the protection would be decorative.
const (
	GrantKindLoginCode = "login_code"
	GrantKindAuthzCode = "authorization_code"
)

// AuthorizationCodeTTL is how long an issued code may sit unredeemed.
//
// 60s matches loginCodeTTL and is well inside the "maximum of 10 minutes"
// RFC 6749 §4.1.2 allows. A code is exchanged by a server-to-server call made
// immediately on redirect; anything longer is dead time in which a leaked code
// is still live.
const AuthorizationCodeTTL = 60 * time.Second

var (
	// ErrClientNotFound is returned when a client_id matches no live client.
	ErrClientNotFound = errors.New("oauth: unknown client_id")

	// ErrRedirectURINotRegistered is returned when the requested redirect_uri
	// is not an exact match for one of the client's registered URIs.
	//
	// This error must NEVER be reported by redirecting to the requested URI —
	// see RFC 6749 §4.1.2.1. Doing so would turn the authorize endpoint into an
	// open redirector that reflects an attacker-chosen destination.
	ErrRedirectURINotRegistered = errors.New("oauth: redirect_uri is not registered for this client")

	// ErrNoRedirectURIsRegistered distinguishes "this client cannot do the
	// authorization code flow at all" from "wrong URI". Common for m2m clients.
	ErrNoRedirectURIsRegistered = errors.New("oauth: client has no registered redirect_uris")

	// ErrConsentRequired is returned for a client with first_party = false.
	// The consent screen is not built yet (issue #6 plan §3), so such a client
	// is refused outright rather than silently skipping consent.
	ErrConsentRequired = errors.New("oauth: consent is required for third-party clients and is not yet implemented")

	// ErrGrantTypeNotAllowed is returned when a client requests a grant its
	// registration does not list.
	ErrGrantTypeNotAllowed = errors.New("oauth: grant_type is not allowed for this client")

	// ErrInvalidAuthorizationCode covers unknown, expired, already-used and
	// wrong-client codes with a single sentinel: all four map to RFC 6749
	// §5.2 invalid_grant, and telling them apart would confirm to an attacker
	// that a guessed code existed.
	ErrInvalidAuthorizationCode = errors.New("oauth: invalid or expired authorization code")

	// ErrAuthorizationCodeReplayed is returned when a code that was already
	// consumed is presented again. Distinct from ErrInvalidAuthorizationCode
	// because it is an attack signal worth auditing and counting separately —
	// the caller still reports invalid_grant to the client.
	ErrAuthorizationCodeReplayed = errors.New("oauth: authorization code replay detected")
)

// AuthzClient is the authorization-server view of an oauth_clients row: only
// the fields the authorize and token endpoints actually decide on.
type AuthzClient struct {
	RowID        int64
	TenantID     int64
	ClientID     string
	Name         string
	AppType      string
	RedirectURIs []string
	Scopes       []string
	GrantTypes   []string
	RequirePKCE  bool
	FirstParty   bool
	// Confidential reports whether the client holds a secret. Derived from
	// client_secret_hash being non-empty rather than from app_type, because
	// app_type is a UI hint an admin can change without rotating credentials,
	// and the token endpoint must key off what the client actually has.
	Confidential bool
}

// AuthorizationServer issues and redeems this server's own authorization codes.
type AuthorizationServer struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger
}

// NewAuthorizationServer constructs an AuthorizationServer.
func NewAuthorizationServer(pool *pgxpool.Pool, logger zerolog.Logger) *AuthorizationServer {
	return &AuthorizationServer{pool: pool, logger: logger}
}

// LookupClient resolves a client_id to its authorization-server record.
//
// By client_id alone, with no tenant parameter: the client_id is globally
// unique (idx_oauth_clients_client_id) and at the authorize endpoint there is
// no authenticated caller to take a tenant from. The tenant comes OUT of this
// lookup and is authoritative from then on — it is never read from the request.
func (s *AuthorizationServer) LookupClient(ctx context.Context, clientID string) (*AuthzClient, error) {
	if clientID == "" {
		return nil, ErrClientNotFound
	}
	var c AuthzClient
	var secretHash *string
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, client_id, name, app_type,
		       redirect_uris, scopes, grant_types, require_pkce, first_party,
		       client_secret_hash
		FROM   oauth_clients
		WHERE  client_id = $1 AND deleted_at IS NULL
	`, clientID).Scan(&c.RowID, &c.TenantID, &c.ClientID, &c.Name, &c.AppType,
		&c.RedirectURIs, &c.Scopes, &c.GrantTypes, &c.RequirePKCE, &c.FirstParty,
		&secretHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		return nil, fmt.Errorf("lookup oauth client: %w", err)
	}
	c.Confidential = secretHash != nil && *secretHash != ""
	return &c, nil
}

// ResolveRedirectURI returns the requested URI if — and only if — it is an
// exact byte-for-byte match for one of the client's registered URIs.
//
// Exact match, deliberately: no prefix matching, no wildcards, no
// scheme/host-only comparison, no normalisation. RFC 6749 §3.1.2.3 requires it,
// and every historical redirect_uri bypass has come from a relaxed comparison —
// `https://app.com` prefix-matching `https://app.com.evil.test`, or a
// normalising parser disagreeing with the browser about what the URL means.
//
// If the client registered exactly one URI, an omitted redirect_uri defaults to
// it (§3.1.2.3 permits this). An omitted URI with several registered is an
// error: guessing which one the client meant is how codes get delivered to the
// wrong place.
func ResolveRedirectURI(c *AuthzClient, requested string) (string, error) {
	if len(c.RedirectURIs) == 0 {
		return "", ErrNoRedirectURIsRegistered
	}
	if requested == "" {
		if len(c.RedirectURIs) == 1 {
			return c.RedirectURIs[0], nil
		}
		return "", ErrRedirectURINotRegistered
	}
	for _, registered := range c.RedirectURIs {
		if registered == requested {
			return registered, nil
		}
	}
	return "", ErrRedirectURINotRegistered
}

// AllowsGrant reports whether the client's registration permits a grant type.
//
// grant_types has been a column since migration 00032 with the default
// '{authorization_code,refresh_token}', but nothing has ever read it. Issue #6
// starts enforcing it, which is why the empty case below is permissive: a row
// written before enforcement should not lose access to a grant it was already
// using. The column default means fresh rows are constrained normally.
func AllowsGrant(c *AuthzClient, grantType string) bool {
	if len(c.GrantTypes) == 0 {
		return true
	}
	for _, g := range c.GrantTypes {
		if g == grantType {
			return true
		}
	}
	return false
}

// FilterScopes intersects the requested scopes with the client's registered
// set, preserving the requested order and dropping duplicates.
//
// Silently dropping rather than erroring on an unregistered scope is what
// RFC 6749 §3.3 specifies, and the token response echoes the granted set so a
// client can see what it actually received. Erroring instead would break the
// common case of a client asking for a superset across environments.
//
// A client with no registered scopes is granted nothing — the fail-closed
// reading. It is not "unrestricted": that would make a forgotten registration
// field the most permissive possible configuration.
func FilterScopes(requested, registered []string) []string {
	allowed := make(map[string]bool, len(registered))
	for _, s := range registered {
		allowed[s] = true
	}
	granted := make([]string, 0, len(requested))
	seen := make(map[string]bool, len(requested))
	for _, s := range requested {
		if s == "" || seen[s] || !allowed[s] {
			continue
		}
		seen[s] = true
		granted = append(granted, s)
	}
	return granted
}

// ParseScopeParam splits an RFC 6749 space-delimited scope parameter.
func ParseScopeParam(raw string) []string {
	return strings.Fields(raw)
}

// HasScope reports whether a granted scope set contains a scope.
func HasScope(granted []string, scope string) bool {
	for _, s := range granted {
		if s == scope {
			return true
		}
	}
	return false
}

// IssueAuthorizationCodeParams carries everything bound into a code at issue
// time. Every field here is re-checked at redemption; nothing about the
// exchange is taken from the token request except the verifier.
type IssueAuthorizationCodeParams struct {
	TenantID      int64
	ClientID      string
	UserID        int64
	RedirectURI   string
	Scopes        []string
	CodeChallenge string
	Nonce         string
	AuthTime      time.Time
}

// IssueAuthorizationCode mints a code and persists only its SHA-256 hash.
//
// The raw value is returned to the caller once and never stored, matching the
// policy already applied to refresh tokens, reset tokens, API keys and login
// codes. A database read must not yield anything redeemable.
func (s *AuthorizationServer) IssueAuthorizationCode(ctx context.Context, p IssueAuthorizationCodeParams) (string, error) {
	// 32 bytes of crypto/rand, hex-encoded — the same generator and entropy as
	// refresh tokens and login codes.
	raw, err := GenerateRefreshToken()
	if err != nil {
		return "", fmt.Errorf("generate authorization code: %w", err)
	}
	scopes := p.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	authTime := p.AuthTime
	if authTime.IsZero() {
		authTime = time.Now().UTC()
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO oauth_authorization_codes
		    (tenant_id, client_id, user_id, code_hash, code_challenge,
		     code_challenge_method, redirect_uri, scopes, nonce, auth_time,
		     grant_kind, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`, p.TenantID, p.ClientID, p.UserID, HashToken(raw), p.CodeChallenge,
		PKCEMethodS256, p.RedirectURI, scopes, nullIfEmpty(p.Nonce), authTime,
		GrantKindAuthzCode, time.Now().UTC().Add(AuthorizationCodeTTL))
	if err != nil {
		return "", fmt.Errorf("persist authorization code: %w", err)
	}
	return raw, nil
}

// nullIfEmpty maps "" to a NULL nonce. A supplied-but-empty nonce and an absent
// nonce mean the same thing, and storing "" would put an empty nonce claim into
// the ID token, which OIDC clients compare against their stored value and
// reject.
func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// RedeemedCode is the result of a successful exchange.
type RedeemedCode struct {
	TenantID    int64
	UserID      int64
	ClientID    string
	RedirectURI string
	Scopes      []string
	Nonce       string
	AuthTime    time.Time
}

// RedeemAuthorizationCode consumes a code and returns what it was bound to.
//
// Single-use is enforced by the database, not by a read-then-write in Go: the
// UPDATE ... WHERE used_at IS NULL ... RETURNING is atomic, so two concurrent
// exchanges of the same code cannot both succeed. This mirrors
// ExchangeLoginCode and is the only correct shape — a SELECT followed by an
// UPDATE has a window in which both callers see an unused code.
//
// grant_kind = 'authorization_code' is part of the WHERE clause. Without it
// this endpoint would also consume login_code rows, which carry no
// code_challenge, and the PKCE check below would have nothing to verify
// against. That is one half of the trap described in migration 00067; the other
// half is the matching filter in ExchangeLoginCode.
//
// PKCE is verified AFTER consumption, deliberately. A code presented with a
// wrong verifier has been handled by someone who should not have it, so burning
// it is correct: leaving it live would let an attacker brute-force the verifier
// against a code that stays valid for the full 60 seconds.
func (s *AuthorizationServer) RedeemAuthorizationCode(ctx context.Context, clientID, rawCode, redirectURI, verifier string) (*RedeemedCode, error) {
	if clientID == "" || rawCode == "" {
		return nil, ErrInvalidAuthorizationCode
	}
	codeHash := HashToken(rawCode)

	var r RedeemedCode
	var challenge, method *string
	var nonce *string
	var authTime *time.Time
	err := s.pool.QueryRow(ctx, `
		UPDATE oauth_authorization_codes
		SET    used_at = NOW()
		WHERE  code_hash = $1
		  AND  client_id = $2
		  AND  grant_kind = $3
		  AND  used_at IS NULL
		  AND  expires_at > NOW()
		RETURNING tenant_id, user_id, redirect_uri, scopes,
		          code_challenge, code_challenge_method, nonce, auth_time
	`, codeHash, clientID, GrantKindAuthzCode).Scan(
		&r.TenantID, &r.UserID, &r.RedirectURI, &r.Scopes,
		&challenge, &method, &nonce, &authTime)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Distinguish replay from unknown/expired for the audit trail. This
			// is a second query on the failure path only, and it reads a hash,
			// never anything redeemable. The caller still returns invalid_grant
			// either way — the difference is what gets logged and counted.
			if s.wasAlreadyUsed(ctx, codeHash) {
				return nil, ErrAuthorizationCodeReplayed
			}
			return nil, ErrInvalidAuthorizationCode
		}
		return nil, fmt.Errorf("redeem authorization code: %w", err)
	}

	// redirect_uri must match the one the code was issued against (RFC 6749
	// §4.1.3). Without this, a code intercepted at one registered URI could be
	// redeemed as though it had been delivered to another.
	//
	// The comparison is UNCONDITIONAL — there is deliberately no "omitted means
	// skip the check" branch. Every code this server mints carries a resolved,
	// non-empty redirect_uri (ResolveRedirectURI runs before the code is
	// issued), so treating an absent parameter as "nothing to compare" would
	// turn the one binding that ties a code to its delivery address into an
	// opt-out an attacker controls: a code lifted from one registered URI could
	// be redeemed by simply not mentioning a URI at all. A client that reaches
	// this endpoint without redirect_uri gets invalid_grant, which is the
	// stricter reading of §4.1.3's REQUIRED and is safe here because every code
	// was issued against a known URI.
	if redirectURI != r.RedirectURI {
		return nil, ErrInvalidAuthorizationCode
	}

	storedChallenge := ""
	if challenge != nil {
		storedChallenge = *challenge
	}
	storedMethod := ""
	if method != nil {
		storedMethod = *method
	}
	if storedChallenge == "" {
		// A code minted by this server always carries a challenge; reaching
		// here means the row was written by something else or by a future code
		// path that forgot. Refuse rather than treat "no challenge" as "no
		// check required" — that is the fail-open reading.
		return nil, ErrInvalidAuthorizationCode
	}
	if err := VerifyPKCE(storedChallenge, storedMethod, verifier); err != nil {
		return nil, ErrInvalidCodeVerifier
	}

	if nonce != nil {
		r.Nonce = *nonce
	}
	if authTime != nil {
		r.AuthTime = *authTime
	}
	if r.Scopes == nil {
		r.Scopes = []string{}
	}
	r.ClientID = clientID
	return &r, nil
}

// wasAlreadyUsed reports whether a code hash exists but has been consumed —
// the replay signal. Scoped to authorization_code rows so a login_code with a
// colliding hash (impossible in practice, but the query should say what it
// means) is not reported as a replay of something else.
func (s *AuthorizationServer) wasAlreadyUsed(ctx context.Context, codeHash string) bool {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM oauth_authorization_codes
			WHERE code_hash = $1 AND grant_kind = $2 AND used_at IS NOT NULL
		)
	`, codeHash, GrantKindAuthzCode).Scan(&exists)
	return err == nil && exists
}
