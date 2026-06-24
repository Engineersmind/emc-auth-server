package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

// Sign creates and signs a JWT for the given claims using the tenant's HS256 secret.
func (s *JWTService) Sign(ctx context.Context, tenantID int64, audience string, c *Claims) (string, error) {
	secret, err := s.tenantSecret(ctx, tenantID)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	c.RegisteredClaims = jwt.RegisteredClaims{
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

	tenantID, err := strconv.ParseInt(unverifiedClaims.TenantID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant_id in jwt: %w", err)
	}

	secret, err := s.tenantSecret(ctx, tenantID)
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
