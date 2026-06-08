package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Claims is the full JWT payload for emc-auth tokens.
// It embeds jwt.RegisteredClaims for standard fields (iss, aud, exp, sub, iat).
type Claims struct {
	UserID      string   `json:"user_id"`
	TenantID    string   `json:"tenant_id"`
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
// Result is NOT cached here — callers should use a short-lived context.
func (s *JWTService) tenantSecret(ctx context.Context, tenantID uuid.UUID) (string, error) {
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
const AccessTokenTTL = 1 * time.Hour

// RefreshTokenTTL is the lifetime of a refresh token (AUTH-06).
const RefreshTokenTTL = 30 * 24 * time.Hour

// ManagementTokenTTL is the lifetime of an API-key-derived management token.
// Short-lived by design — callers must re-exchange the API key to get a new one.
const ManagementTokenTTL = 15 * time.Minute

// Sign creates and signs a JWT for the given claims using the tenant's HS256 secret.
// The caller must populate all domain fields (UserID, TenantID, Email, Role, Permissions).
// Sign fills in iss, aud, exp, iat, and sub automatically.
func (s *JWTService) Sign(ctx context.Context, tenantID uuid.UUID, audience string, c *Claims) (string, error) {
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
		UserID:      "key:" + identity.KeyID.String(),
		TenantID:    identity.TenantID.String(),
		Email:       identity.Name + "@apikey",
		Role:        "api_key",
		Permissions: identity.Permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    s.issuer,
			Audience:  jwt.ClaimStrings{"emc-auth-management"},
			Subject:   "key:" + identity.KeyID.String(),
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
func (s *JWTService) SignAgent(ctx context.Context, identity *AgentIdentity) (string, error) {
	secret, err := s.tenantSecret(ctx, identity.TenantID)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	claims := &AgentClaims{
		AgentID:      identity.AgentID.String(),
		TenantID:     identity.TenantID.String(),
		AgentType:    identity.AgentType,
		Capabilities: identity.Capabilities,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Audience:  jwt.ClaimStrings{"emc-auth-agent"},
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

// Verify parses and validates a JWT string. It fetches the tenant's secret from
// the DB using the tenant_id embedded in the unverified claims first pass.
// Returns the validated *Claims on success.
func (s *JWTService) Verify(ctx context.Context, tokenString string) (*Claims, error) {
	// First pass: extract tenant_id from unverified claims to look up the secret.
	unverified, _, err := jwt.NewParser().ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return nil, fmt.Errorf("parse unverified jwt: %w", err)
	}
	unverifiedClaims, ok := unverified.Claims.(*Claims)
	if !ok || unverifiedClaims.TenantID == "" {
		return nil, errors.New("jwt missing tenant_id claim")
	}

	tenantUUID, err := uuid.Parse(unverifiedClaims.TenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant_id in jwt: %w", err)
	}

	secret, err := s.tenantSecret(ctx, tenantUUID)
	if err != nil {
		return nil, err
	}

	// Second pass: full parse + signature verification.
	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	}, jwt.WithExpirationRequired())
	if err != nil {
		return nil, fmt.Errorf("verify jwt: %w", err)
	}
	if !parsed.Valid {
		return nil, errors.New("jwt is not valid")
	}
	return claims, nil
}
