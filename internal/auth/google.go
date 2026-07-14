package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
)

// googleIssuer is Google's OIDC issuer; discovery resolves the endpoints and
// JWKS from here — nothing is hand-rolled (issue #64).
const googleIssuer = "https://accounts.google.com"

// oauthStateTTL bounds how long a login attempt may sit between the redirect
// to Google and the callback. States are single-use regardless of TTL.
const oauthStateTTL = 10 * time.Minute

// loginCodeTTL is the lifetime of the one-time login code handed back to the
// tenant application on the final redirect. Deliberately short — the app
// exchanges it immediately via POST /api/v1/auth/oauth/exchange.
const loginCodeTTL = 60 * time.Second

// ErrOAuthStateInvalid is returned when the state parameter is missing,
// expired, or already consumed (single-use replay).
var ErrOAuthStateInvalid = errors.New("invalid or expired oauth state")

// ErrOAuthEmailNotVerified is returned when the provider reports the account
// email as unverified. No account is created or linked — ever.
var ErrOAuthEmailNotVerified = errors.New("provider account email is not verified")

// ErrOAuthLinkConflict is returned when the provider email matches an existing
// local account that has not verified its email — auto-linking such an account
// would let whoever registered it capture the provider identity (issue #64
// account-takeover gate).
var ErrOAuthLinkConflict = errors.New("an account with this email already exists but is not verified")

// ErrInvalidLoginCode is returned when a login code is unknown, expired,
// already used, or bound to a different client_id.
var ErrInvalidLoginCode = errors.New("invalid or expired login code")

// OAuthLoginService drives the backend Authorization Code + PKCE flow for
// social login providers. Only Google is implemented; the state, resolution,
// and login-code layers are provider-agnostic by design.
type OAuthLoginService struct {
	pool     *pgxpool.Pool
	redisCli *redis.Client
	idpSvc   *IdentityProviderService
	authSvc  *AuthService
	baseURL  string
	logger   zerolog.Logger

	// issuer is the OIDC issuer URL for discovery. Always googleIssuer in
	// production; overridden only by tests via WithIssuer to point at an
	// httptest-stubbed provider.
	issuer string

	// mu guards the lazily-initialised OIDC provider (one discovery + JWKS
	// fetch per process, then cached and auto-refreshed by go-oidc).
	mu             sync.Mutex
	googleProvider *oidc.Provider
}

// NewOAuthLoginService constructs an OAuthLoginService. baseURL is the
// server's public base URL (APP_BASE_URL) — the provider callback is always
// baseURL + "/oauth/<provider>/callback".
func NewOAuthLoginService(pool *pgxpool.Pool, redisCli *redis.Client, idpSvc *IdentityProviderService, authSvc *AuthService, baseURL string, logger zerolog.Logger) *OAuthLoginService {
	return &OAuthLoginService{
		pool:     pool,
		redisCli: redisCli,
		idpSvc:   idpSvc,
		authSvc:  authSvc,
		baseURL:  baseURL,
		issuer:   googleIssuer,
		logger:   logger,
	}
}

// WithIssuer overrides the OIDC issuer for discovery. TEST HOOK ONLY — lets
// integration tests point the flow at an httptest-stubbed provider instead of
// the live Google endpoints. Production wiring never calls this.
func (s *OAuthLoginService) WithIssuer(issuer string) *OAuthLoginService {
	s.issuer = issuer
	return s
}

// oauthState is the server-side per-login-attempt record. It is the ONLY
// source of tenant/application/redirect context at callback time — nothing
// security-relevant is ever read from callback query parameters.
type OAuthState struct {
	TenantID int64  `json:"tenant_id"`
	AppRowID int64  `json:"app_row_id"`
	ClientID string `json:"client_id"` // EMC application client_id (oauth_clients.client_id)
	Provider string `json:"provider"`
	Verifier string `json:"verifier"` // PKCE code verifier (S256)
	Redirect string `json:"redirect"` // validated against redirect_allow at initiation
}

func oauthStateKey(state string) string {
	return "oauth:state:" + HashToken(state)
}

// oidcProvider returns the cached Google OIDC provider, performing discovery
// on first use.
func (s *OAuthLoginService) oidcProvider(ctx context.Context) (*oidc.Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.googleProvider != nil {
		return s.googleProvider, nil
	}
	p, err := oidc.NewProvider(ctx, s.issuer)
	if err != nil {
		return nil, fmt.Errorf("google oidc discovery: %w", err)
	}
	s.googleProvider = p
	return p, nil
}

// oauth2Config assembles the golang.org/x/oauth2 config for one application's
// Google credentials.
func (s *OAuthLoginService) oauth2Config(provider *oidc.Provider, cfg *flowConfig, providerName string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  s.baseURL + "/oauth/" + providerName + "/callback",
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
}

// BuildAuthURL starts a login attempt: validates the application + provider
// config + redirect target, generates state and a PKCE S256 challenge, stores
// the attempt in Redis, and returns the provider authorization URL to
// redirect the browser to.
func (s *OAuthLoginService) BuildAuthURL(ctx context.Context, providerName, clientID, requestedRedirect string) (string, error) {
	if !supportedProviders[providerName] {
		return "", ErrProviderNotSupported
	}
	if clientID == "" {
		return "", ErrInvalidClient
	}

	var appRowID, tenantID int64
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id FROM oauth_clients
		WHERE client_id = $1 AND deleted_at IS NULL
	`, clientID).Scan(&appRowID, &tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrInvalidClient
		}
		return "", fmt.Errorf("resolve application: %w", err)
	}

	cfg, err := s.idpSvc.getFlowConfig(ctx, appRowID, providerName)
	if err != nil {
		return "", err
	}

	redirect, err := resolveRedirect(requestedRedirect, cfg.RedirectAllow)
	if err != nil {
		return "", err
	}

	provider, err := s.oidcProvider(ctx)
	if err != nil {
		return "", err
	}

	state, err := GenerateRefreshToken() // 32 random bytes, hex — same entropy as refresh tokens
	if err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}
	verifier := oauth2.GenerateVerifier()

	payload, err := json.Marshal(OAuthState{
		TenantID: tenantID,
		AppRowID: appRowID,
		ClientID: clientID,
		Provider: providerName,
		Verifier: verifier,
		Redirect: redirect,
	})
	if err != nil {
		return "", fmt.Errorf("marshal oauth state: %w", err)
	}
	if err := s.redisCli.Set(ctx, oauthStateKey(state), payload, oauthStateTTL).Err(); err != nil {
		return "", fmt.Errorf("store oauth state: %w", err)
	}

	conf := s.oauth2Config(provider, cfg, providerName)
	return conf.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), nil
}

// ConsumeState atomically consumes (GETDEL) the state record. A second call
// with the same state always fails — single-use is enforced at the Redis
// layer, not by TTL alone. Exposed to the handler so provider error callbacks
// (e.g. consent denied) can still recover the validated redirect target.
func (s *OAuthLoginService) ConsumeState(ctx context.Context, providerName, state string) (*OAuthState, error) {
	if state == "" {
		return nil, ErrOAuthStateInvalid
	}
	data, err := s.redisCli.GetDel(ctx, oauthStateKey(state)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrOAuthStateInvalid
		}
		return nil, fmt.Errorf("consume oauth state: %w", err)
	}
	var st OAuthState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("decode oauth state: %w", err)
	}
	if st.Provider != providerName {
		return nil, ErrOAuthStateInvalid
	}
	return &st, nil
}

// CallbackResult is returned by HandleCallback for the handler to complete
// the redirect and write audit entries.
type CallbackResult struct {
	// RedirectURI is the allow-listed target with login_code appended.
	RedirectURI string
	// Outcome is one of "login", "linked", "provisioned" — drives audit events.
	Outcome  string
	UserID   int64
	TenantID int64
	Email    string
}

// googleIDClaims is the subset of Google ID token claims the flow consumes.
type googleIDClaims struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
}

// HandleCallback completes a login attempt whose state has ALREADY been
// consumed by the handler (via ConsumeState): exchanges the code with PKCE,
// verifies the ID token against Google's JWKS, applies the email-verification
// gate, resolves the local user, and issues a one-time login code.
//
// Google's tokens live only in local variables inside this call — they are
// never persisted or logged (issue #64 non-negotiable).
func (s *OAuthLoginService) HandleCallback(ctx context.Context, st *OAuthState, code string) (*CallbackResult, error) {
	if code == "" {
		return nil, ErrOAuthStateInvalid
	}

	// Re-load the provider config — if the tenant disabled the provider while
	// the user sat on Google's consent screen, the attempt fails here.
	cfg, err := s.idpSvc.getFlowConfig(ctx, st.AppRowID, st.Provider)
	if err != nil {
		return nil, err
	}
	provider, err := s.oidcProvider(ctx)
	if err != nil {
		return nil, err
	}

	conf := s.oauth2Config(provider, cfg, st.Provider)
	token, err := conf.Exchange(ctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return nil, fmt.Errorf("exchange authorization code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("provider token response missing id_token")
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", err)
	}

	var claims googleIDClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode id_token claims: %w", err)
	}
	if claims.Sub == "" || claims.Email == "" {
		return nil, fmt.Errorf("id_token missing sub or email claim")
	}
	// Email-verification gate — rejected outright, no fallback path that
	// creates or links an account anyway.
	if !claims.EmailVerified {
		return nil, ErrOAuthEmailNotVerified
	}

	userID, outcome, err := s.resolveUser(ctx, st, claims)
	if isUniqueViolation(err) {
		// Two concurrent first-logins raced on the users/user_identities
		// unique indexes; the loser re-resolves against the winner's rows
		// (now an existing-identity or auto-link hit).
		userID, outcome, err = s.resolveUser(ctx, st, claims)
	}
	if err != nil {
		return nil, err
	}

	loginCode, err := s.createLoginCode(ctx, st, userID)
	if err != nil {
		return nil, err
	}

	redirectURI, err := appendLoginCode(st.Redirect, loginCode)
	if err != nil {
		return nil, err
	}
	return &CallbackResult{
		RedirectURI: redirectURI,
		Outcome:     outcome,
		UserID:      userID,
		TenantID:    st.TenantID,
		Email:       claims.Email,
	}, nil
}

// isUniqueViolation reports whether err is a PostgreSQL unique-index
// violation (SQLSTATE 23505) — the signature of two concurrent logins racing
// to create the same user or identity link.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// resolveUser maps a verified provider identity onto a local app-scoped user:
//
//  1. Existing user_identities link → that user ("login").
//  2. Verified provider email matches an existing app-scoped user whose OWN
//     email_verified is true → attach the identity ("linked"). An unverified
//     local match is rejected — auto-linking it would hand the account to
//     whoever pre-registered that email (takeover gate).
//  3. No match → JIT-provision with the application's default role, no
//     user_credentials row ("provisioned").
//
// Every query pins BOTH tenant_id and application_id from the server-stored
// state — tenant-level users (application_id IS NULL) are never candidates.
func (s *OAuthLoginService) resolveUser(ctx context.Context, st *OAuthState, claims googleIDClaims) (userID int64, outcome string, err error) {
	// 1. Existing identity link.
	err = s.pool.QueryRow(ctx, `
		SELECT u.id
		FROM   user_identities ui
		JOIN   users u ON u.id = ui.user_id
		WHERE  ui.tenant_id = $1 AND ui.application_id = $2
		  AND  ui.provider = $3 AND ui.provider_sub = $4
		  AND  u.is_active = true AND u.deleted_at IS NULL
	`, st.TenantID, st.AppRowID, st.Provider, claims.Sub).Scan(&userID)
	if err == nil {
		return userID, "login", nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, "", fmt.Errorf("lookup identity: %w", err)
	}

	// 2. Auto-link by verified email — app-scoped users only.
	var emailVerified bool
	err = s.pool.QueryRow(ctx, `
		SELECT id, email_verified
		FROM   users
		WHERE  tenant_id = $1 AND application_id = $2 AND email = $3
		  AND  is_active = true AND deleted_at IS NULL
	`, st.TenantID, st.AppRowID, claims.Email).Scan(&userID, &emailVerified)
	if err == nil {
		if !emailVerified {
			return 0, "", ErrOAuthLinkConflict
		}
		// ON CONFLICT DO NOTHING makes the link idempotent under concurrent
		// callbacks for the same account: both requests resolve to the same
		// user above; whichever INSERT lands second is a no-op instead of a
		// unique-index violation, and that request is a plain login.
		tag, err := s.pool.Exec(ctx, `
			INSERT INTO user_identities
			    (user_id, tenant_id, application_id, provider, provider_sub, provider_email)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT DO NOTHING
		`, userID, st.TenantID, st.AppRowID, st.Provider, claims.Sub, claims.Email)
		if err != nil {
			return 0, "", fmt.Errorf("link identity: %w", err)
		}
		if tag.RowsAffected() == 0 {
			// A concurrent request linked this identity first.
			return userID, "login", nil
		}
		return userID, "linked", nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, "", fmt.Errorf("lookup user by email: %w", err)
	}

	// 3. JIT provision — same default-role query as application Register.
	var roleID *int64
	var tempRoleID int64
	err = s.pool.QueryRow(ctx, `
		SELECT id FROM roles
		WHERE tenant_id = $1 AND application_id = $2 AND is_default = true AND is_system = false
	`, st.TenantID, st.AppRowID).Scan(&tempRoleID)
	if err == nil {
		roleID = &tempRoleID
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return 0, "", fmt.Errorf("fetch default role: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, "", fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// email_verified=true: Google attested the address. No user_credentials
	// row — password login is structurally impossible for this account.
	err = tx.QueryRow(ctx, `
		INSERT INTO users (tenant_id, email, first_name, last_name, role_id, application_id, is_active, email_verified)
		VALUES ($1, $2, $3, $4, $5, $6, true, true)
		RETURNING id
	`, st.TenantID, claims.Email, claims.GivenName, claims.FamilyName, roleID, st.AppRowID).Scan(&userID)
	if err != nil {
		return 0, "", fmt.Errorf("insert JIT user: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO user_identities
		    (user_id, tenant_id, application_id, provider, provider_sub, provider_email)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, userID, st.TenantID, st.AppRowID, st.Provider, claims.Sub, claims.Email)
	if err != nil {
		return 0, "", fmt.Errorf("insert JIT identity: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, "", fmt.Errorf("commit JIT provision: %w", err)
	}
	return userID, "provisioned", nil
}

// createLoginCode mints the one-time handoff code, persisting only its
// SHA-256 hash in oauth_authorization_codes (single-use via used_at,
// client-bound via client_id, 60s TTL).
func (s *OAuthLoginService) createLoginCode(ctx context.Context, st *OAuthState, userID int64) (string, error) {
	raw, err := GenerateRefreshToken()
	if err != nil {
		return "", fmt.Errorf("generate login code: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO oauth_authorization_codes
		    (tenant_id, client_id, user_id, code_hash, redirect_uri, scopes, expires_at)
		VALUES ($1, $2, $3, $4, $5, '{}', $6)
	`, st.TenantID, st.ClientID, userID, HashToken(raw), st.Redirect, time.Now().UTC().Add(loginCodeTTL))
	if err != nil {
		return "", fmt.Errorf("persist login code: %w", err)
	}
	return raw, nil
}

// appendLoginCode adds login_code as a query parameter to the validated
// redirect target, preserving any existing query string.
func appendLoginCode(redirect, code string) (string, error) {
	u, err := url.Parse(redirect)
	if err != nil {
		return "", fmt.Errorf("parse redirect: %w", err)
	}
	q := u.Query()
	q.Set("login_code", code)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// AppendLoginError adds a generic error code to the validated redirect target
// for user-facing failure states (consent denied, unverified email, ...).
// Only ever called with an allow-listed redirect from consumed state.
func AppendLoginError(redirect, errCode string) string {
	u, err := url.Parse(redirect)
	if err != nil {
		return redirect
	}
	q := u.Query()
	q.Set("error", errCode)
	u.RawQuery = q.Encode()
	return u.String()
}

// ExchangeLoginCode swaps a one-time login code for the standard access +
// refresh token pair. The code must be unused, unexpired, and bound to the
// presented client_id. Consumption is a single atomic UPDATE — two concurrent
// exchanges of the same code cannot both succeed.
func (s *OAuthLoginService) ExchangeLoginCode(ctx context.Context, clientID, rawCode string) (*AuthResult, error) {
	if clientID == "" || rawCode == "" {
		return nil, ErrInvalidLoginCode
	}

	var tenantID, userID int64
	err := s.pool.QueryRow(ctx, `
		UPDATE oauth_authorization_codes
		SET    used_at = NOW()
		WHERE  code_hash = $1 AND client_id = $2
		  AND  used_at IS NULL AND expires_at > NOW()
		RETURNING tenant_id, user_id
	`, HashToken(rawCode), clientID).Scan(&tenantID, &userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidLoginCode
		}
		return nil, fmt.Errorf("consume login code: %w", err)
	}

	// Fresh user load — role/active status are read at exchange time, not
	// frozen at callback time.
	var email, roleName string
	var appRowID int64
	err = s.pool.QueryRow(ctx, `
		SELECT u.email, COALESCE(r.name, ''), oc.id
		FROM   users u
		JOIN   oauth_clients oc ON oc.client_id = $3 AND oc.tenant_id = $2 AND oc.deleted_at IS NULL
		LEFT   JOIN roles r ON r.id = u.role_id
		WHERE  u.id = $1 AND u.tenant_id = $2
		  AND  u.is_active = true AND u.deleted_at IS NULL
	`, userID, tenantID, clientID).Scan(&email, &roleName, &appRowID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidLoginCode
		}
		return nil, fmt.Errorf("load user for exchange: %w", err)
	}

	perms, err := s.authSvc.loadPermissions(ctx, userID, tenantID)
	if err != nil {
		s.logger.Warn().Err(err).Msg("oauth exchange: failed to load permissions, continuing with empty set")
		perms = []string{}
	}

	// Same choke point as password/OTP login — no parallel token minting.
	return s.authSvc.issueTokenPair(ctx, userID, tenantID, email, roleName, perms, nil, strconv.FormatInt(appRowID, 10))
}
