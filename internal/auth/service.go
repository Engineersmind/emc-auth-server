package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

// BcryptCost is the work factor for password hashing (AUTH-02).
const BcryptCost = 12

// AuthService implements the business logic for registration, login, and profile lookup.
type AuthService struct {
	pool   *pgxpool.Pool
	jwtSvc *JWTService
	logger zerolog.Logger
}

// NewAuthService creates an AuthService.
func NewAuthService(pool *pgxpool.Pool, jwtSvc *JWTService, logger zerolog.Logger) *AuthService {
	return &AuthService{pool: pool, jwtSvc: jwtSvc, logger: logger}
}

// RegisterInput is the payload for creating a new user.
type RegisterInput struct {
	TenantSlug string
	Email      string
	Password   string
	FirstName  string
	LastName   string
}

// LoginInput is the payload for authenticating an existing user.
type LoginInput struct {
	TenantSlug string
	Email      string
	Password   string
}

// AuthResult is returned by both Register and Login.
type AuthResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"` // seconds
}

// MeResult is returned by GET /api/v1/auth/me.
type MeResult struct {
	UserID      string   `json:"user_id"`
	TenantID    string   `json:"tenant_id"`
	Email       string   `json:"email"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

// resolveTenant fetches the tenant row by slug. Returns pgx.ErrNoRows if not found.
func (s *AuthService) resolveTenant(ctx context.Context, slug string) (id uuid.UUID, jwtSecret string, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT id, jwt_secret FROM tenants WHERE slug = $1 AND is_active = true`,
		slug,
	).Scan(&id, &jwtSecret)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("resolve tenant %q: %w", slug, err)
	}
	return id, jwtSecret, nil
}

// loadPermissions returns the list of permission names for a given user.
// It unions role-based permissions and direct user permissions.
func (s *AuthService) loadPermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT p.name
		FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		JOIN users u ON u.role_id = rp.role_id
		WHERE u.id = $1 AND u.tenant_id = $2
		UNION
		SELECT DISTINCT p.name
		FROM permissions p
		JOIN user_permissions up ON up.permission_id = p.id
		WHERE up.user_id = $1 AND up.tenant_id = $2
		ORDER BY 1
	`, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load permissions: %w", err)
	}
	defer rows.Close()

	var perms []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		perms = append(perms, name)
	}
	if perms == nil {
		perms = []string{} // never return nil — JSON encodes as [] not null
	}
	return perms, rows.Err()
}

// issueTokenPair signs a JWT access token and generates a refresh token, persisting
// the refresh token hash in the refresh_tokens table.
func (s *AuthService) issueTokenPair(ctx context.Context, userID, tenantID uuid.UUID, email, role string, perms []string) (*AuthResult, error) {
	claims := &Claims{
		UserID:      userID.String(),
		TenantID:    tenantID.String(),
		Email:       email,
		Role:        role,
		Permissions: perms,
	}

	accessToken, err := s.jwtSvc.Sign(ctx, tenantID, "emc-auth-server", claims)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	rawRefresh, err := GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}
	refreshHash := HashToken(rawRefresh)

	_, err = s.pool.Exec(ctx, `
		INSERT INTO refresh_tokens (id, user_id, tenant_id, token_hash, expires_at)
		VALUES (gen_random_uuid(), $1, $2, $3, $4)
	`, userID, tenantID, refreshHash, time.Now().UTC().Add(RefreshTokenTTL))
	if err != nil {
		return nil, fmt.Errorf("persist refresh token: %w", err)
	}

	return &AuthResult{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(AccessTokenTTL.Seconds()),
	}, nil
}

// Register creates a new user in the given tenant.
// Returns AUTH-01 / AUTH-02 compliant token pair on success.
func (s *AuthService) Register(ctx context.Context, in RegisterInput) (*AuthResult, error) {
	tenantID, _, err := s.resolveTenant(ctx, in.TenantSlug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("tenant not found")
		}
		return nil, err
	}

	// Hash password at cost 12 (AUTH-02).
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	// Fetch the default role for this tenant (first non-system role by name asc, or null).
	var roleID *uuid.UUID
	var roleName string
	err = s.pool.QueryRow(ctx,
		`SELECT id, name FROM roles WHERE tenant_id = $1 AND is_system = false ORDER BY name LIMIT 1`,
		tenantID,
	).Scan(&roleID, &roleName)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("fetch default role: %w", err)
	}
	// If no non-system role found, assign no role (roleID stays nil).

	// Insert user and credentials in a transaction.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var userID uuid.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO users (id, tenant_id, email, first_name, last_name, role_id, is_active)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, true)
		RETURNING id
	`, tenantID, in.Email, in.FirstName, in.LastName, roleID).Scan(&userID)
	if err != nil {
		return nil, fmt.Errorf("insert user: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO user_credentials (user_id, tenant_id, password_hash)
		VALUES ($1, $2, $3)
	`, userID, tenantID, string(hash))
	if err != nil {
		return nil, fmt.Errorf("insert credentials: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit register: %w", err)
	}

	perms, err := s.loadPermissions(ctx, userID, tenantID)
	if err != nil {
		s.logger.Warn().Err(err).Msg("register: failed to load permissions, continuing with empty set")
		perms = []string{}
	}

	return s.issueTokenPair(ctx, userID, tenantID, in.Email, roleName, perms)
}

// Login authenticates an existing user by email and password.
// Returns AUTH-01 compliant token pair on success.
func (s *AuthService) Login(ctx context.Context, in LoginInput) (*AuthResult, error) {
	tenantID, _, err := s.resolveTenant(ctx, in.TenantSlug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("invalid credentials")
		}
		return nil, err
	}

	// Fetch user + role + password hash in a single JOIN.
	var userID uuid.UUID
	var email, passwordHash string
	var roleName string
	var roleID *uuid.UUID
	err = s.pool.QueryRow(ctx, `
		SELECT u.id, u.email, uc.password_hash, COALESCE(r.name, ''), u.role_id
		FROM users u
		JOIN user_credentials uc ON uc.user_id = u.id
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.tenant_id = $1 AND u.email = $2 AND u.is_active = true AND u.is_deleted = false
	`, tenantID, in.Email).Scan(&userID, &email, &passwordHash, &roleName, &roleID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("invalid credentials")
		}
		return nil, fmt.Errorf("fetch user: %w", err)
	}

	// Constant-time password comparison (bcrypt).
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(in.Password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	perms, err := s.loadPermissions(ctx, userID, tenantID)
	if err != nil {
		s.logger.Warn().Err(err).Msg("login: failed to load permissions, continuing with empty set")
		perms = []string{}
	}

	return s.issueTokenPair(ctx, userID, tenantID, email, roleName, perms)
}

// Me returns profile information derived from JWT claims.
// The claims are injected by the JWTRequired middleware (added in Plan 02-02).
func (s *AuthService) Me(claims *Claims) *MeResult {
	return &MeResult{
		UserID:      claims.UserID,
		TenantID:    claims.TenantID,
		Email:       claims.Email,
		Role:        claims.Role,
		Permissions: claims.Permissions,
	}
}

// ErrInvalidRefreshToken is returned when a refresh token is invalid, expired, or already used.
var ErrInvalidRefreshToken = errors.New("invalid or expired refresh token")

// Refresh rotates a refresh token pair (AUTH-03).
//
// Algorithm:
//  1. Hash the raw incoming refresh token.
//  2. Look up the hash in refresh_tokens WHERE revoked_at IS NULL AND expires_at > NOW().
//     - Not found → return ErrInvalidRefreshToken (401).
//     - Found but revoked → return ErrInvalidRefreshToken (401). Replay attack blocked.
//  3. Mark old token revoked (SET revoked_at = NOW()).
//  4. Load user + role + permissions from DB.
//  5. Issue new access token + new refresh token (persisted).
//  6. Return new AuthResult.
//
// This is atomic: the old token is revoked BEFORE the new one is issued.
// If step 5 fails, the old token is already revoked — user must log in again.
func (s *AuthService) Refresh(ctx context.Context, rawRefreshToken string) (*AuthResult, error) {
	hash := HashToken(rawRefreshToken)

	// Look up token — must be active (revoked_at IS NULL) and not expired.
	var tokenID, userID, tenantID uuid.UUID
	err := s.pool.QueryRow(ctx, `
		SELECT id, user_id, tenant_id
		FROM refresh_tokens
		WHERE token_hash = $1
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
	`, hash).Scan(&tokenID, &userID, &tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, fmt.Errorf("lookup refresh token: %w", err)
	}

	// Revoke the old token immediately.
	_, err = s.pool.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1
	`, tokenID)
	if err != nil {
		return nil, fmt.Errorf("revoke old refresh token: %w", err)
	}

	// Load user details for the new JWT.
	var email, roleName string
	var roleID *uuid.UUID
	err = s.pool.QueryRow(ctx, `
		SELECT u.email, COALESCE(r.name, ''), u.role_id
		FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.id = $1 AND u.tenant_id = $2 AND u.is_active = true AND u.is_deleted = false
	`, userID, tenantID).Scan(&email, &roleName, &roleID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user not found or inactive")
		}
		return nil, fmt.Errorf("fetch user for refresh: %w", err)
	}

	perms, err := s.loadPermissions(ctx, userID, tenantID)
	if err != nil {
		s.logger.Warn().Err(err).Msg("refresh: failed to load permissions, continuing with empty set")
		perms = []string{}
	}

	return s.issueTokenPair(ctx, userID, tenantID, email, roleName, perms)
}

// Logout revokes a refresh token (AUTH-04).
// The raw refresh token is hashed and the matching DB row is marked revoked.
// If the token is already revoked or not found, Logout returns nil (idempotent).
func (s *AuthService) Logout(ctx context.Context, rawRefreshToken string) error {
	hash := HashToken(rawRefreshToken)
	_, err := s.pool.Exec(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = NOW()
		WHERE token_hash = $1 AND revoked_at IS NULL
	`, hash)
	if err != nil {
		return fmt.Errorf("revoke refresh token on logout: %w", err)
	}
	return nil
}
