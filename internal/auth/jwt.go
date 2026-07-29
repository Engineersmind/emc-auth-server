package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Claims is the full JWT payload for emc-auth tokens.
// It embeds jwt.RegisteredClaims for standard fields (iss, aud, exp, sub, iat).
//
// AppID is set when the token was issued through a registered application
// (X-Client-ID on login/register, or the client_credentials grant).
// It is omitted from the JSON payload when empty so existing tokens without
// it remain valid — the Verify path ignores missing optional claims.
type Claims struct {
	UserID      string   `json:"user_id"`
	TenantID    string   `json:"tenant_id"`
	AppID       string   `json:"app_id,omitempty"`
	Email       string   `json:"email"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	jwt.RegisteredClaims
}

// AgentClaims is the JWT payload for machine-to-machine agent tokens (08-01).
type AgentClaims struct {
	AgentID      string   `json:"agent_id"`
	TenantID     string   `json:"tenant_id"`
	AgentType    string   `json:"agent_type"`
	Capabilities []string `json:"capabilities"`
	jwt.RegisteredClaims
}

// AgentTokenTTL is the lifetime of an agent access token.
const AgentTokenTTL = 1 * time.Hour

// Token audiences. The "aud" claim is this server's token-type discriminator:
// it records which flow minted a token so verification can refuse a token that
// was issued for a different purpose (issue #84). Every token is signed with
// exactly one audience.
//
// Audience alone is not authorization — permissions/role still gate what a
// caller may do. Audience answers the prior question: "is this kind of token
// even accepted on this route?"
const (
	// AudienceAPI marks human/end-user session tokens: password login,
	// registration, refresh rotation, MFA completion, magic link, social
	// (OAuth/OIDC) callback, and SAML JIT login.
	AudienceAPI = "emc-auth-api"

	// AudienceM2M marks client_credentials service tokens (no user behind
	// them; Role is "service" and Permissions come from oauth_clients.scopes).
	AudienceM2M = "emc-auth-m2m"

	// AudienceManagement marks short-lived tokens exchanged from an API key
	// via POST /auth/management-token.
	AudienceManagement = "emc-auth-management"

	// AudienceAgent marks agent tokens minted by SignAgent. No verification
	// path consumes these yet — see SignAgent.
	AudienceAgent = "emc-auth-agent"
)

// ErrUnexpectedAudience is returned when a token is well-formed and correctly
// signed but was minted for a different audience than the caller accepts —
// e.g. a service (M2M) token presented on a user self-service route. This is a
// token-confusion / replay signal, not an ordinary expiry, so it is a distinct
// sentinel that middleware can count and log separately.
var ErrUnexpectedAudience = errors.New("jwt: unexpected audience")

// ErrNoAudienceAllowed guards against a programming error: calling
// VerifyForAudience with an empty allow-list would otherwise silently accept
// every audience, defeating the check.
var ErrNoAudienceAllowed = errors.New("jwt: no allowed audience specified")

// JWTService signs and verifies JWTs using a per-tenant HS256 secret.
type JWTService struct {
	pool *pgxpool.Pool
	// issuer is the value placed in the "iss" claim.
	issuer string
}

// NewJWTService creates a JWTService backed by the given pool.
// issuer should be the server's base URL, e.g. "https://auth.emc.local".
func NewJWTService(pool *pgxpool.Pool, issuer string) *JWTService {
	return &JWTService{pool: pool, issuer: issuer}
}

// tenantSecret fetches the jwt_secret for the given tenant from the DB.
func (s *JWTService) tenantSecret(ctx context.Context, tenantID int64) (string, error) {
	var secret string
	err := s.pool.QueryRow(ctx,
		`SELECT jwt_secret FROM tenants WHERE id = $1 AND is_active = true`,
		tenantID,
	).Scan(&secret)
	if err != nil {
		return "", fmt.Errorf("fetch tenant jwt_secret: %w", err)
	}
	if secret == "" {
		return "", errors.New("tenant jwt_secret is empty")
	}
	return secret, nil
}

// AccessTokenTTL is the lifetime of an access token (AUTH-06).
// 15 minutes matches the API contract; transparent middleware renewal keeps
// browser sessions alive without client-side retry logic.
const AccessTokenTTL = 15 * time.Minute

// RefreshTokenTTL is the lifetime of a refresh token (AUTH-06).
const RefreshTokenTTL = 30 * 24 * time.Hour

// ManagementTokenTTL is the lifetime of an API-key-derived management token.
// Short-lived by design — callers must re-exchange the API key to get a new one.
const ManagementTokenTTL = 15 * time.Minute

// Sign creates and signs a JWT for the given claims using the tenant's HS256 secret.
func (s *JWTService) Sign(ctx context.Context, tenantID int64, audience string, c *Claims) (string, error) {
	secret, err := s.tenantSecret(ctx, tenantID)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	c.RegisteredClaims = jwt.RegisteredClaims{
		ID:        uuid.New().String(),
		Issuer:    s.issuer,
		Audience:  jwt.ClaimStrings{audience},
		Subject:   c.UserID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(AccessTokenTTL)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return signed, nil
}

// SignManagement issues a short-lived management JWT from an API key identity.
// The token carries the API key's permissions so it can call /admin/* endpoints
// for the key's tenant — equivalent to Auth0's client_credentials management token.
func (s *JWTService) SignManagement(ctx context.Context, identity *APIKeyIdentity) (string, error) {
	secret, err := s.tenantSecret(ctx, identity.TenantID)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	claims := &Claims{
		UserID:      "key:" + strconv.FormatInt(identity.KeyID, 10),
		TenantID:    strconv.FormatInt(identity.TenantID, 10),
		Email:       identity.Name + "@apikey",
		Role:        "api_key",
		Permissions: identity.Permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    s.issuer,
			Audience:  jwt.ClaimStrings{AudienceManagement},
			Subject:   "key:" + strconv.FormatInt(identity.KeyID, 10),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ManagementTokenTTL)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("sign management token: %w", err)
	}
	return signed, nil
}

// SignAgent creates and signs a JWT for an authenticated agent identity.
// Uses the tenant's HS256 secret — same trust boundary as user JWTs.
//
// NOTE: nothing in this server verifies these tokens yet — there is no
// VerifyAgent and no middleware consuming AudienceAgent (Phase 8 "AI/Agent
// Security" is still partial). Because tokens are minted with AudienceAgent and
// no verify path allows that audience, an agent token cannot be replayed
// against user, management, or M2M routes. Wiring agent-token verification is
// tracked separately from issue #84.
func (s *JWTService) SignAgent(ctx context.Context, identity *AgentIdentity) (string, error) {
	secret, err := s.tenantSecret(ctx, identity.TenantID)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	claims := &AgentClaims{
		AgentID:      identity.AgentID.String(),
		TenantID:     strconv.FormatInt(identity.TenantID, 10),
		AgentType:    identity.AgentType,
		Capabilities: identity.Capabilities,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Audience:  jwt.ClaimStrings{AudienceAgent},
			Subject:   identity.AgentID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(AgentTokenTTL)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("sign agent jwt: %w", err)
	}
	return signed, nil
}

// Verify parses and validates a user/session JWT (AudienceAPI only).
//
// It is the strict default: tokens minted for any other audience — M2M service
// tokens, API-key management tokens, agent tokens — are rejected with
// ErrUnexpectedAudience. Routes that legitimately accept more than one token
// type must say so explicitly via VerifyForAudience.
func (s *JWTService) Verify(ctx context.Context, tokenString string) (*Claims, error) {
	return s.VerifyForAudience(ctx, tokenString, AudienceAPI)
}

// VerifyM2M parses and validates a client_credentials service token
// (AudienceM2M only), rejecting user, management, and agent tokens.
func (s *JWTService) VerifyM2M(ctx context.Context, tokenString string) (*Claims, error) {
	return s.VerifyForAudience(ctx, tokenString, AudienceM2M)
}

// VerifyForAudience parses and validates a JWT string, accepting it only if its
// "aud" claim is one of allowed. It fetches the tenant's secret from the DB
// using the tenant_id embedded in the unverified claims first pass, then
// verifies signature, algorithm, issuer, expiry, and audience.
//
// Audience is checked only after the signature is proven, so an attacker cannot
// use the audience result to learn anything about an unsigned token.
//
// Callers pass the set of token types a route accepts, e.g. admin routes accept
// {AudienceAPI, AudienceManagement, AudienceM2M} because a human operator, an
// API-key integration, and a machine client are all legitimate admin callers,
// whereas user self-service routes accept {AudienceAPI} alone.
// Passing no audience is a programming error (ErrNoAudienceAllowed) rather than
// a silent "allow everything".
func (s *JWTService) VerifyForAudience(ctx context.Context, tokenString string, allowed ...string) (*Claims, error) {
	if len(allowed) == 0 {
		return nil, ErrNoAudienceAllowed
	}

	// First pass: extract tenant_id from unverified claims to look up the secret.
	unverified, _, err := jwt.NewParser().ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return nil, fmt.Errorf("parse unverified jwt: %w", err)
	}
	unverifiedClaims, ok := unverified.Claims.(*Claims)
	if !ok || unverifiedClaims.TenantID == "" {
		return nil, errors.New("jwt missing tenant_id claim")
	}

	tenantID, err := strconv.ParseInt(unverifiedClaims.TenantID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant_id in jwt: %w", err)
	}

	secret, err := s.tenantSecret(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Second pass: full parse + signature verification.
	// WithValidMethods pins the exact algorithm (the keyfunc below only checks
	// the HMAC family), closing off alg-substitution attempts.
	opts := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	}
	// Every token we mint carries iss = s.issuer; enforce it when configured.
	if s.issuer != "" {
		opts = append(opts, jwt.WithIssuer(s.issuer))
	}

	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	}, opts...)
	if err != nil {
		return nil, fmt.Errorf("verify jwt: %w", err)
	}
	if !parsed.Valid {
		return nil, errors.New("jwt is not valid")
	}

	// Audience check runs last — the signature is proven at this point, so the
	// token really was minted by us and its aud claim can be trusted.
	if !audienceAllowed(claims.Audience, allowed) {
		return nil, fmt.Errorf("verify jwt: got %v, want one of %v: %w",
			[]string(claims.Audience), allowed, ErrUnexpectedAudience)
	}
	return claims, nil
}

// audienceAllowed reports whether aud names exactly one audience and that
// audience is in allowed.
//
// The single-value requirement is deliberate: every Sign* method in this package
// mints exactly one audience, so a multi-valued aud did not come from a current
// code path and must not be able to satisfy a route by carrying one acceptable
// value alongside others.
func audienceAllowed(aud jwt.ClaimStrings, allowed []string) bool {
	if len(aud) != 1 {
		return false
	}
	for _, want := range allowed {
		if aud[0] == want {
			return true
		}
	}
	return false
}
