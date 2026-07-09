package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

// BcryptCost is the work factor for password hashing (AUTH-02).
const BcryptCost = 12

// AuthService implements the business logic for registration, login, and profile lookup.
type AuthService struct {
	pool     *pgxpool.Pool
	jwtSvc   *JWTService
	totpSvc  *TOTPService        // nil when TOTP not configured
	redisCli *redis.Client       // used for OTP session storage
	appSvc   *ApplicationService // nil when application context is not needed
	logger   zerolog.Logger
}

// NewAuthService creates an AuthService.
func NewAuthService(pool *pgxpool.Pool, jwtSvc *JWTService, logger zerolog.Logger) *AuthService {
	return &AuthService{pool: pool, jwtSvc: jwtSvc, logger: logger}
}

// WithTOTP attaches a TOTPService and Redis client so the auth service can enforce
// TOTP on login. Call this after NewAuthService when TOTP is enabled.
func (s *AuthService) WithTOTP(totpSvc *TOTPService, redisCli *redis.Client) *AuthService {
	s.totpSvc = totpSvc
	s.redisCli = redisCli
	return s
}

// WithApplications attaches an ApplicationService so the auth service can
// validate X-Client-ID on login and register and stamp app_id into JWTs.
func (s *AuthService) WithApplications(appSvc *ApplicationService) *AuthService {
	s.appSvc = appSvc
	return s
}

// RegisterInput is the payload for creating a new user.
//
// Two application-identification modes are supported:
//   - ClientID + ClientSecret (server-to-server integrations): the application
//     is fully AUTHENTICATED — the secret is verified against its hash and the
//     tenant is derived from the application, so TenantSlug becomes optional.
//   - ClientID alone (legacy X-Client-ID header): the id is only validated to
//     exist within the slug-resolved tenant and stamped into the JWT for audit.
type RegisterInput struct {
	// TenantSlug is required unless ClientSecret is provided (the tenant is
	// then derived from the authenticated application). When both are present
	// the slug must resolve to the application's own tenant.
	TenantSlug string
	// ClientID is the application identifier (body field for integrations, or
	// the legacy X-Client-ID header). See the struct comment for the two modes.
	ClientID string
	// ClientSecret, when non-empty, upgrades ClientID validation to full
	// application authentication (hash-verified, active applications only).
	ClientSecret string
	Email        string
	Password     string
	FirstName    string
	LastName     string
}

// LoginInput is the payload for authenticating an existing user. Without
// application credentials the tenant is resolved by matching Email/Password
// against every tenant's users (the same email may own accounts in multiple
// tenants). With ClientID + ClientSecret the application is authenticated
// first and the candidate search is pinned to that application's tenant.
type LoginInput struct {
	// ClientID / ClientSecret follow the same two modes as RegisterInput.
	ClientID     string
	ClientSecret string
	Email        string
	Password     string
}

// AuthResult is returned by both Register and Login (when TOTP is not required).
type AuthResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"` // seconds until access token expires
	ExpiresAt    int64  `json:"expires_at"` // UTC unix timestamp when access token expires
	// Clients should schedule a proactive refresh at (ExpiresAt - 60) seconds.
	// On a 401 with code="token_expired", refresh once then retry the original request.
	// On a 401 with code="token_invalid" or if refresh fails, redirect to login.
}

// OTPChallenge is returned by Login when the user has active TOTP.
type OTPChallenge struct {
	RequiresOTP     bool   `json:"requires_otp"`
	OTPSessionToken string `json:"otp_session_token"`
	ExpiresIn       int    `json:"expires_in"`
}

// LoginResult wraps either a full token pair or an OTP challenge.
type LoginResult struct {
	Token        *AuthResult
	OTPChallenge *OTPChallenge
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
func (s *AuthService) resolveTenant(ctx context.Context, slug string) (id int64, jwtSecret string, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT id, jwt_secret FROM tenants WHERE slug = $1 AND is_active = true`,
		slug,
	).Scan(&id, &jwtSecret)
	if err != nil {
		return 0, "", fmt.Errorf("resolve tenant %q: %w", slug, err)
	}
	return id, jwtSecret, nil
}

// loadPermissions returns the list of permission names for a given user.
func (s *AuthService) loadPermissions(ctx context.Context, userID, tenantID int64) ([]string, error) {
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
		perms = []string{}
	}
	return perms, rows.Err()
}

// issueTokenPair signs a JWT access token and generates a refresh token.
// sessionFamilyID is nil for new logins (the new token becomes its own family root);
// for token rotation it carries the existing family id forward.
// appID is the string-encoded oauth_clients.id when the token is issued through a
// registered application; pass "" when no application context is present.
func (s *AuthService) issueTokenPair(ctx context.Context, userID, tenantID int64, email, role string, perms []string, sessionFamilyID *int64, appID string) (*AuthResult, error) {
	claims := &Claims{
		UserID:      strconv.FormatInt(userID, 10),
		TenantID:    strconv.FormatInt(tenantID, 10),
		AppID:       appID,
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

	if sessionFamilyID != nil {
		// Token rotation: inherit the existing session family.
		_, err = s.pool.Exec(ctx, `
			INSERT INTO refresh_tokens (user_id, tenant_id, token_hash, expires_at, session_family_id)
			VALUES ($1, $2, $3, $4, $5)
		`, userID, tenantID, refreshHash, time.Now().UTC().Add(RefreshTokenTTL), *sessionFamilyID)
	} else {
		// New login: insert with session_family_id=0, then immediately set it to
		// the row's own id using a single CTE.  Both operations execute in one
		// round-trip and one implicit transaction — no window where family_id=0
		// can leak or be caught by a concurrent revokeFamily(0) sweep.
		_, err = s.pool.Exec(ctx, `
			WITH ins AS (
				INSERT INTO refresh_tokens (user_id, tenant_id, token_hash, expires_at, session_family_id)
				VALUES ($1, $2, $3, $4, 0)
				RETURNING id
			)
			UPDATE refresh_tokens
			SET    session_family_id = ins.id
			FROM   ins
			WHERE  refresh_tokens.id = ins.id
		`, userID, tenantID, refreshHash, time.Now().UTC().Add(RefreshTokenTTL))
	}
	if err != nil {
		return nil, fmt.Errorf("persist refresh token: %w", err)
	}

	return &AuthResult{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(AccessTokenTTL.Seconds()),
		ExpiresAt:    time.Now().UTC().Add(AccessTokenTTL).Unix(),
	}, nil
}

// authenticateApp verifies client_id + client_secret against the stored hash
// and returns the application's owning tenant and its row id. Deactivated
// applications are rejected. Returns ErrInvalidClient on credential mismatch.
func (s *AuthService) authenticateApp(ctx context.Context, clientID, clientSecret string) (tenantID, appRowID int64, err error) {
	if s.appSvc == nil {
		return 0, 0, fmt.Errorf("application service not configured")
	}
	if clientID == "" {
		return 0, 0, ErrInvalidClient
	}
	return s.appSvc.AuthenticateClient(ctx, clientID, clientSecret)
}

// Register creates a new user. The target tenant comes either from an
// authenticated application (ClientID + ClientSecret) or from TenantSlug.
func (s *AuthService) Register(ctx context.Context, in RegisterInput) (*AuthResult, error) {
	var tenantID int64
	appID := ""
	// appRowID is non-nil only for application-authenticated registration —
	// the created user then BELONGS to that application (isolated user base),
	// not just the tenant. Legacy X-Client-ID tagging does not scope the user.
	var appRowID *int64

	if in.ClientSecret != "" {
		// Application-authenticated registration: the app proves itself and
		// pins the tenant — integrators never need to know a tenant slug.
		tid, aid, err := s.authenticateApp(ctx, in.ClientID, in.ClientSecret)
		if err != nil {
			return nil, err
		}
		// A slug supplied alongside app credentials must agree with the
		// application's own tenant (confused-deputy guard). Same error as a
		// bad secret so responses don't map app credentials to tenants.
		if in.TenantSlug != "" {
			slugTenantID, _, err := s.resolveTenant(ctx, in.TenantSlug)
			if err != nil || slugTenantID != tid {
				return nil, ErrInvalidClient
			}
		}
		tenantID, appRowID = tid, &aid
		appID = strconv.FormatInt(aid, 10)
	} else {
		tid, _, err := s.resolveTenant(ctx, in.TenantSlug)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, fmt.Errorf("tenant not found")
			}
			return nil, err
		}
		tenantID = tid

		// Legacy tagging mode: validate the client before any writes — a bad
		// client_id must not orphan a committed user row.
		if in.ClientID != "" && s.appSvc != nil {
			id, err := s.appSvc.ValidateClientID(ctx, tenantID, in.ClientID)
			if err != nil {
				return nil, fmt.Errorf("invalid client_id")
			}
			appID = strconv.FormatInt(id, 10)
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	var roleID *int64
	var roleName string
	err = s.pool.QueryRow(ctx,
		`SELECT id, name FROM roles WHERE tenant_id = $1 AND is_system = false ORDER BY name LIMIT 1`,
		tenantID,
	).Scan(&roleID, &roleName)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("fetch default role: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var userID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO users (tenant_id, email, first_name, last_name, role_id, application_id, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, true)
		RETURNING id
	`, tenantID, in.Email, in.FirstName, in.LastName, roleID, appRowID).Scan(&userID)
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

	return s.issueTokenPair(ctx, userID, tenantID, in.Email, roleName, perms, nil, appID)
}

// dummyPasswordHash has no known matching plaintext. Login pads every attempt
// with compares against this hash up to loginCompareFloor, so "zero candidate
// accounts" and "a handful of candidate accounts" take roughly the same time —
// otherwise response latency alone would reveal whether an email exists, and
// (since bcrypt compares scale with candidate count) roughly how many tenants
// it belongs to. This bounds the leak up to the floor; an email with more real
// candidates than the floor still takes proportionally longer.
var dummyPasswordHash = []byte("$2a$12$CwTycUXWue0Thq9StjUM0uJ8fVWy9j9G2sQm.a5S0KgP4Us0Qwv2u")

// loginCompareFloor is the minimum number of bcrypt comparisons Login performs
// per attempt, real candidates plus dummy padding, to reduce how precisely
// response timing can reveal an email's tenant-account count for the common case.
const loginCompareFloor = 5

// loginCandidate is one (tenant, user) row whose email matches a login attempt.
type loginCandidate struct {
	userID       int64
	tenantID     int64
	email        string
	passwordHash string
	roleName     string
}

// Login authenticates a user by email and password. Without application
// credentials the caller never specifies a tenant — the same email may have
// separate accounts (separate passwords) in multiple tenants, so Login fetches
// every active account matching the email and checks the password against each
// one to find the single tenant it belongs to. With ClientID + ClientSecret
// the application is authenticated first and the search is pinned to its tenant.
func (s *AuthService) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	// Application-authenticated mode: verify the app before touching any user
	// data so bad app credentials fail fast and identically regardless of the
	// submitted email.
	appID := ""
	var appTenantID, appRowID int64
	if in.ClientSecret != "" {
		tid, aid, err := s.authenticateApp(ctx, in.ClientID, in.ClientSecret)
		if err != nil {
			return nil, err
		}
		appTenantID, appRowID = tid, aid
		appID = strconv.FormatInt(aid, 10)
	}

	// User-base isolation: app-authenticated logins only see that application's
	// own users; generic logins only see tenant-level users (application_id IS
	// NULL) — an app-scoped account can never authenticate outside its app.
	candidateQuery := `
		SELECT u.id, u.tenant_id, u.email, uc.password_hash, COALESCE(r.name, '')
		FROM users u
		JOIN user_credentials uc ON uc.user_id = u.id
		JOIN tenants t ON t.id = u.tenant_id
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.email = $1 AND u.is_active = true AND u.deleted_at IS NULL AND t.is_active = true
	`
	args := []any{in.Email}
	if appRowID != 0 {
		candidateQuery += ` AND u.tenant_id = $2 AND u.application_id = $3`
		args = append(args, appTenantID, appRowID)
	} else {
		candidateQuery += ` AND u.application_id IS NULL`
	}
	rows, err := s.pool.Query(ctx, candidateQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("fetch login candidates: %w", err)
	}

	var candidates []loginCandidate
	for rows.Next() {
		var c loginCandidate
		if err := rows.Scan(&c.userID, &c.tenantID, &c.email, &c.passwordHash, &c.roleName); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan login candidate: %w", err)
		}
		candidates = append(candidates, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate login candidates: %w", err)
	}

	if len(candidates) == 0 {
		for i := 0; i < loginCompareFloor; i++ {
			_ = bcrypt.CompareHashAndPassword(dummyPasswordHash, []byte(in.Password))
		}
		return nil, fmt.Errorf("invalid credentials")
	}

	var matched *loginCandidate
	matchCount := 0
	for i := range candidates {
		if bcrypt.CompareHashAndPassword([]byte(candidates[i].passwordHash), []byte(in.Password)) == nil {
			matchCount++
			matched = &candidates[i]
		}
	}
	for i := len(candidates); i < loginCompareFloor; i++ {
		_ = bcrypt.CompareHashAndPassword(dummyPasswordHash, []byte(in.Password))
	}

	if matchCount == 0 {
		return nil, fmt.Errorf("invalid credentials")
	}
	if matchCount > 1 {
		// Same password happens to be valid for more than one of this email's
		// tenant accounts. Return the same generic error as any other failure —
		// a distinct message here would tell an attacker "this password is
		// valid for 2+ accounts", a stronger signal than plain match/no-match.
		// The fix (differing passwords per tenant) is documented on CreateTenant,
		// not surfaced here, to avoid using a login failure as the guidance channel.
		return nil, fmt.Errorf("invalid credentials")
	}

	userID, tenantID, email, roleName := matched.userID, matched.tenantID, matched.email, matched.roleName

	perms, err := s.loadPermissions(ctx, userID, tenantID)
	if err != nil {
		s.logger.Warn().Err(err).Msg("login: failed to load permissions, continuing with empty set")
		perms = []string{}
	}

	if s.totpSvc != nil && s.redisCli != nil {
		active, err := s.totpSvc.IsActive(ctx, userID)
		if err != nil {
			s.logger.Warn().Err(err).Msg("login: failed to check TOTP status, skipping TOTP step")
		} else if active {
			challenge, err := s.createOTPSession(ctx, userID, tenantID, email, roleName, perms)
			if err != nil {
				return nil, fmt.Errorf("create OTP session: %w", err)
			}
			return &LoginResult{OTPChallenge: challenge}, nil
		}
	}

	// Legacy tagging mode (ClientID without a secret): validate the id exists
	// in the matched tenant. Skipped when the app already authenticated above.
	if appID == "" && in.ClientID != "" && s.appSvc != nil {
		id, err := s.appSvc.ValidateClientID(ctx, tenantID, in.ClientID)
		if err != nil {
			return nil, fmt.Errorf("invalid client_id")
		}
		appID = strconv.FormatInt(id, 10)
	}

	tokens, err := s.issueTokenPair(ctx, userID, tenantID, email, roleName, perms, nil, appID)
	if err != nil {
		return nil, err
	}
	return &LoginResult{Token: tokens}, nil
}

// LoginOTPInput is the payload for completing a TOTP-gated login.
type LoginOTPInput struct {
	OTPSessionToken string
	Code            string
}

// LoginOTP completes a TOTP-gated login.
func (s *AuthService) LoginOTP(ctx context.Context, in LoginOTPInput) (*AuthResult, error) {
	if s.totpSvc == nil || s.redisCli == nil {
		return nil, fmt.Errorf("TOTP not configured on this server")
	}

	session, err := s.loadOTPSession(ctx, in.OTPSessionToken)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired OTP session")
	}

	err = s.totpSvc.Verify(ctx, session.UserID, in.Code)
	if err != nil {
		err2 := s.totpSvc.VerifyBackupCode(ctx, session.UserID, in.Code)
		if err2 != nil {
			return nil, fmt.Errorf("invalid TOTP code")
		}
	}

	s.redisCli.Del(ctx, otpSessionKey(in.OTPSessionToken)) //nolint:errcheck

	return s.issueTokenPair(ctx, session.UserID, session.TenantID, session.Email, session.RoleName, session.Perms, nil, "")
}

// createOTPSession stores pre-auth user state in Redis and returns a challenge token.
func (s *AuthService) createOTPSession(ctx context.Context, userID, tenantID int64, email, roleName string, perms []string) (*OTPChallenge, error) {
	raw, err := GenerateRefreshToken()
	if err != nil {
		return nil, err
	}
	sessionToken := raw

	payload, err := json.Marshal(OTPSession{
		UserID:   userID,
		TenantID: tenantID,
		Email:    email,
		RoleName: roleName,
		Perms:    perms,
	})
	if err != nil {
		return nil, err
	}

	if err := s.redisCli.Set(ctx, otpSessionKey(sessionToken), payload, OTPSessionTTL).Err(); err != nil {
		return nil, fmt.Errorf("store OTP session: %w", err)
	}

	return &OTPChallenge{
		RequiresOTP:     true,
		OTPSessionToken: sessionToken,
		ExpiresIn:       int(OTPSessionTTL.Seconds()),
	}, nil
}

// loadOTPSession retrieves and decodes the pre-auth session from Redis.
func (s *AuthService) loadOTPSession(ctx context.Context, token string) (*OTPSession, error) {
	data, err := s.redisCli.Get(ctx, otpSessionKey(token)).Bytes()
	if err != nil {
		return nil, fmt.Errorf("OTP session not found or expired: %w", err)
	}
	var sess OTPSession
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("decode OTP session: %w", err)
	}
	return &sess, nil
}

func otpSessionKey(token string) string {
	return "otp:session:" + HashToken(token)
}

// Me returns profile information derived from JWT claims.
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

// ErrTokenReplay is returned when a previously-rotated refresh token is presented again.
// The entire session family is revoked. The caller must clear cookies and force re-login.
var ErrTokenReplay = errors.New("token replay detected — session family revoked")

// ErrServiceUnavailable is returned when a required backing service (e.g. Redis) is
// unreachable and proceeding without it would violate a security invariant.
var ErrServiceUnavailable = errors.New("service temporarily unavailable")

// GraceResult is returned by RefreshWithLock when a concurrent request already rotated
// this token family within the last 10 seconds. The middleware should attach these claims
// to the context and continue the request without issuing new cookies — the other
// concurrent request's response already carries the fresh cookies.
type GraceResult struct {
	UserID      int64
	TenantID    int64
	Email       string
	Role        string
	Permissions []string
}

// Refresh rotates a refresh token pair (AUTH-03).
func (s *AuthService) Refresh(ctx context.Context, rawRefreshToken string) (*AuthResult, error) {
	hash := HashToken(rawRefreshToken)

	var tokenID, userID, tenantID, sessionFamilyID int64
	err := s.pool.QueryRow(ctx, `
		SELECT id, user_id, tenant_id, session_family_id
		FROM refresh_tokens
		WHERE token_hash = $1
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
	`, hash).Scan(&tokenID, &userID, &tenantID, &sessionFamilyID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, fmt.Errorf("lookup refresh token: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1
	`, tokenID)
	if err != nil {
		return nil, fmt.Errorf("revoke old refresh token: %w", err)
	}

	var email, roleName string
	var roleID *int64
	err = s.pool.QueryRow(ctx, `
		SELECT u.email, COALESCE(r.name, ''), u.role_id
		FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.id = $1 AND u.tenant_id = $2 AND u.is_active = true AND u.deleted_at IS NULL
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

	return s.issueTokenPair(ctx, userID, tenantID, email, roleName, perms, &sessionFamilyID, "")
}

// gracePeriod is the window in which a concurrent rotation is not treated as a replay.
const gracePeriod = 10 // seconds

// revokeFamily marks every non-revoked token in a session family as revoked.
// Called on replay detection to terminate all tokens an attacker might hold.
func (s *AuthService) revokeFamily(ctx context.Context, familyID int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = NOW()
		WHERE session_family_id = $1 AND revoked_at IS NULL
	`, familyID)
	return err
}

// checkGraceWindow looks for a valid token in the given family that was issued
// within the last gracePeriod seconds. Used when concurrent requests arrive on
// the same expiring access token — one rotates, the other hits the grace path.
func (s *AuthService) checkGraceWindow(ctx context.Context, familyID int64) (*GraceResult, error) {
	var userID, tenantID int64
	err := s.pool.QueryRow(ctx, `
		SELECT user_id, tenant_id
		FROM refresh_tokens
		WHERE session_family_id = $1
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
		  AND created_at > NOW() - make_interval(secs => $2)
		ORDER BY created_at DESC
		LIMIT 1
	`, familyID, gracePeriod).Scan(&userID, &tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, fmt.Errorf("grace window query: %w", err)
	}

	var email, roleName string
	var roleID *int64
	err = s.pool.QueryRow(ctx, `
		SELECT u.email, COALESCE(r.name, ''), u.role_id
		FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.id = $1 AND u.tenant_id = $2 AND u.is_active = true AND u.deleted_at IS NULL
	`, userID, tenantID).Scan(&email, &roleName, &roleID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user not found or inactive")
		}
		return nil, fmt.Errorf("fetch user for grace window: %w", err)
	}

	perms, err := s.loadPermissions(ctx, userID, tenantID)
	if err != nil {
		s.logger.Warn().Err(err).Msg("grace window: failed to load permissions")
		perms = []string{}
	}

	return &GraceResult{
		UserID:      userID,
		TenantID:    tenantID,
		Email:       email,
		Role:        roleName,
		Permissions: perms,
	}, nil
}

// RefreshWithLock rotates a refresh token with a distributed Redis lock.
//
// Compared with Refresh, it adds three safety layers:
//  1. Per-family Redis lock (SET NX PX 5000) prevents concurrent double-rotation.
//  2. Replay detection: if the presented token is already revoked and the family
//     was not rotated within the grace window, the entire family is revoked and
//     ErrTokenReplay is returned.
//  3. Grace window: if the lock is held by another concurrent request that already
//     rotated this family, the second request returns a GraceResult instead of
//     issuing new tokens — the browser gets fresh cookies from the first response.
//
// Returns (authResult, nil, nil) on a normal rotation,
// (nil, graceResult, nil) on a concurrent-rotation grace hit,
// or (nil, nil, err) on failure.
func (s *AuthService) RefreshWithLock(ctx context.Context, rawToken string, redisCli *redis.Client) (*AuthResult, *GraceResult, error) {
	hash := HashToken(rawToken)

	// Initial read — fetch token row including revoked ones so we can detect replay.
	var tokenID, userID, tenantID, sessionFamilyID int64
	var revokedAt *time.Time
	var expiresAt time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT id, user_id, tenant_id, session_family_id, revoked_at, expires_at
		FROM refresh_tokens
		WHERE token_hash = $1
	`, hash).Scan(&tokenID, &userID, &tenantID, &sessionFamilyID, &revokedAt, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrInvalidRefreshToken
		}
		return nil, nil, fmt.Errorf("lookup refresh token: %w", err)
	}

	lockKey := fmt.Sprintf("renewal:lock:family:%d", sessionFamilyID)

	acquired := false
	if redisCli != nil {
		var lockErr error
		acquired, lockErr = redisCli.SetNX(ctx, lockKey, "1", 5*time.Second).Result()
		if lockErr != nil {
			// Redis is unavailable. Proceeding without the distributed lock would break the
			// single-use rotation invariant and could trigger mass logout on all sessions.
			s.logger.Error().Err(lockErr).Msg("renewal lock: redis unavailable, refusing to proceed without distributed lock")
			return nil, nil, ErrServiceUnavailable
		}
	} else {
		acquired = true
	}

	if !acquired {
		// Another request is currently rotating this family. Wait briefly then
		// check whether a fresh token was issued within the grace window.
		time.Sleep(300 * time.Millisecond)
		grace, err := s.checkGraceWindow(ctx, sessionFamilyID)
		return nil, grace, err
	}

	defer func() {
		if redisCli != nil {
			redisCli.Del(ctx, lockKey) //nolint:errcheck
		}
	}()

	// Re-read revoked_at from the DB now that we hold the lock.
	// The pre-lock read above could have raced with another goroutine that rotated
	// the token before we acquired the lock, leaving our local revokedAt stale.
	var currentRevoked *time.Time
	if err := s.pool.QueryRow(ctx,
		`SELECT revoked_at FROM refresh_tokens WHERE id = $1`, tokenID,
	).Scan(&currentRevoked); err != nil {
		return nil, nil, fmt.Errorf("re-read token after lock: %w", err)
	}
	if currentRevoked != nil {
		if err := s.revokeFamily(ctx, sessionFamilyID); err != nil {
			s.logger.Error().Err(err).Int64("family_id", sessionFamilyID).Msg("renewal: family revocation failed")
		}
		return nil, nil, ErrTokenReplay
	}

	if expiresAt.Before(time.Now().UTC()) {
		return nil, nil, ErrInvalidRefreshToken
	}

	// Revoke the presented token.
	_, err = s.pool.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1
	`, tokenID)
	if err != nil {
		return nil, nil, fmt.Errorf("revoke old refresh token: %w", err)
	}

	// Fresh user load from DB — catches suspensions, role changes, or email bans
	// that occurred during the access token's lifetime (key security gate).
	var email, roleName string
	var roleID *int64
	err = s.pool.QueryRow(ctx, `
		SELECT u.email, COALESCE(r.name, ''), u.role_id
		FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.id = $1 AND u.tenant_id = $2 AND u.is_active = true AND u.deleted_at IS NULL
	`, userID, tenantID).Scan(&email, &roleName, &roleID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, fmt.Errorf("user not found or inactive")
		}
		return nil, nil, fmt.Errorf("fetch user for refresh: %w", err)
	}

	perms, err := s.loadPermissions(ctx, userID, tenantID)
	if err != nil {
		s.logger.Warn().Err(err).Msg("refresh: failed to load permissions")
		perms = []string{}
	}

	result, err := s.issueTokenPair(ctx, userID, tenantID, email, roleName, perms, &sessionFamilyID, "")
	return result, nil, err
}

// IssueServiceToken signs a short-lived access token for a machine client using
// the client_credentials grant. There is no user, no refresh token, and the
// role is fixed to "service". The sub claim carries the public client_id so
// integrators can correlate tokens with their credentials; the numeric
// oauth_clients.id remains available in the app_id claim. Scopes are loaded
// from the oauth_clients.scopes column so downstream permission checks receive
// the correct grants.
func (s *AuthService) IssueServiceToken(ctx context.Context, tenantID, appID int64) (string, int, error) {
	var clientID string
	var scopes []string
	if err := s.pool.QueryRow(ctx,
		`SELECT client_id, scopes FROM oauth_clients WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`,
		appID, tenantID,
	).Scan(&clientID, &scopes); err != nil {
		return "", 0, fmt.Errorf("load app client_id and scopes: %w", err)
	}
	if scopes == nil {
		scopes = []string{}
	}

	claims := &Claims{
		UserID:      clientID,
		TenantID:    strconv.FormatInt(tenantID, 10),
		AppID:       strconv.FormatInt(appID, 10),
		Role:        "service",
		Permissions: scopes,
	}
	token, err := s.jwtSvc.Sign(ctx, tenantID, "emc-auth-server", claims)
	if err != nil {
		return "", 0, fmt.Errorf("sign service token: %w", err)
	}
	return token, int(AccessTokenTTL.Seconds()), nil
}

// Logout revokes a refresh token (AUTH-04).
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
