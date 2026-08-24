package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/emailaddr"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
	"github.com/engineersmind/emc-auth-server/internal/requestctx"
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
	totpSvc  *TOTPService         // nil when TOTP not configured
	emailSvc *EmailMFAService     // nil when email MFA not configured
	redisCli *redis.Client        // used for OTP session storage
	appSvc   *ApplicationService  // nil when application context is not needed
	verifSvc *VerificationService // nil when email verification is not configured
	blockSvc *AccountBlockService // nil when brute-force lockout is not configured
	brchSvc  *BreachService       // nil when breached-password detection is off
	// policySvc resolves per-tenant session lifetime policy. Never nil after
	// NewAuthService: a nil-safe zero value would mean every deployment that
	// forgot to wire it silently reverted to unbounded sessions, so the
	// constructor always installs one.
	policySvc *SessionPolicyService
	logger    zerolog.Logger
}

// NewAuthService creates an AuthService.
func NewAuthService(pool *pgxpool.Pool, jwtSvc *JWTService, logger zerolog.Logger) *AuthService {
	return &AuthService{
		pool:      pool,
		jwtSvc:    jwtSvc,
		policySvc: NewSessionPolicyService(pool, logger),
		logger:    logger,
	}
}

// WithSessionPolicy replaces the session policy resolver, so the process can
// share one cache between the auth service and the admin write path that
// invalidates it. Optional — NewAuthService already installs a working resolver.
func (s *AuthService) WithSessionPolicy(policySvc *SessionPolicyService) *AuthService {
	if policySvc != nil {
		s.policySvc = policySvc
	}
	return s
}

// SessionPolicy exposes the resolver so callers that must apply the same policy
// (the reaper's retention window, the admin API's validation) read it from one
// place instead of re-deriving it.
func (s *AuthService) SessionPolicy() *SessionPolicyService { return s.policySvc }

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

// WithEmailMFA attaches an EmailMFAService so login challenges can mint and
// verify emailed one-time codes for users enrolled in the email method.
func (s *AuthService) WithEmailMFA(emailSvc *EmailMFAService) *AuthService {
	s.emailSvc = emailSvc
	return s
}

// WithVerification attaches a VerificationService so self-service registration
// dispatches an email-verification link. Optional — without it, registration
// behaves as before (no verification email).
func (s *AuthService) WithVerification(verifSvc *VerificationService) *AuthService {
	s.verifSvc = verifSvc
	return s
}

// WithAccountBlocking attaches an AccountBlockService so repeated failed
// password attempts count toward a per-account lockout. Optional — without it,
// only the per-IP/per-tenant rate limiters bound guessing.
func (s *AuthService) WithAccountBlocking(blockSvc *AccountBlockService) *AuthService {
	s.blockSvc = blockSvc
	return s
}

// WithBreachDetection attaches a BreachService so a successful sign-in with a
// password known to be breached warns the user. Optional and advisory: it never
// blocks a login.
func (s *AuthService) WithBreachDetection(brchSvc *BreachService) *AuthService {
	s.brchSvc = brchSvc
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
	// Persistent is the user's "remember me" choice. It selects which idle clock
	// the tenant's session policy applies — the long one for a trusted personal
	// device, the short one otherwise — and is refused outright when the policy
	// sets allow_persistent = false.
	//
	// Defaults to false, which is the safe direction: an unset flag yields the
	// shorter session, so a client that has not been updated to send it cannot
	// accidentally opt its users into month-long sessions on shared machines.
	Persistent bool

	// VerifiedApp carries an application context that the CALLER has already
	// established from the database, bypassing the client_secret check below.
	//
	// It exists for GET /oauth/authorize (issue #6), where the application is
	// identified by client_id alone. A public client — SPA or native — holds no
	// secret by definition, so the ClientSecret != "" test above would classify
	// its login as generic and search only tenant-level users
	// (application_id IS NULL), never the application's own user base. The user
	// would be told their password was wrong for an account that exists.
	//
	// This is safe there because the authorize endpoint resolves the client
	// with AuthorizationServer.LookupClient before any user data is touched, so
	// the tenant and application row id come from an oauth_clients row, not
	// from the request.
	//
	// SECURITY: this field must never be populated from anything a caller sent.
	// It is not a credential and proves nothing on its own — it ASSERTS that
	// verification already happened. Every handler builds LoginInput field by
	// field from a separate bound request struct (see handlers/auth.go), and
	// LoginInput is never itself bound from JSON; keep it that way. Setting
	// this from a request body would let any caller name any application and
	// authenticate against its isolated user base.
	VerifiedApp *VerifiedApp
}

// VerifiedApp is an application identity the caller has already resolved from
// oauth_clients. See LoginInput.VerifiedApp for the security contract.
type VerifiedApp struct {
	TenantID int64
	AppRowID int64
}

// RegisterResult describes the account Register created.
//
// No tokens: registration does not sign the user in, so there is nothing to hand
// back but the identity of what was made. See the end of Register for why.
type RegisterResult struct {
	UserID   int64  `json:"user_id"`
	TenantID int64  `json:"tenant_id"`
	Email    string `json:"email"`
	Role     string `json:"role,omitempty"`
	// ApplicationID is set when the account belongs to one application's isolated
	// user base, nil for a tenant-level account.
	ApplicationID *int64 `json:"application_id,omitempty"`
}

// AuthResult is returned by Login (when TOTP is not required) and by token refresh.
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

// OTPChallenge is returned by Login when the user has an active second factor.
// Methods lists what the user can complete the challenge with ("totp",
// "email"); when it includes "email" a code has already been sent to the
// account's inbox (re-sendable via POST /auth/login/otp/resend).
type OTPChallenge struct {
	RequiresOTP     bool     `json:"requires_otp"`
	OTPSessionToken string   `json:"otp_session_token"`
	Methods         []string `json:"methods"`
	ExpiresIn       int      `json:"expires_in"`
}

// MFAEnrollmentChallenge is returned by Login when the user's application has
// MFA mode 'required' but the user has no active second factor. The
// enrollment token authorizes only the /auth/login/mfa/* endpoints for this
// one user; AllowedMethods lists which methods the application permits
// ("totp" → enroll + activate, "email" → email/send + activate). Activation
// completes the pending login and returns the token pair. No JWT exists until
// then.
type MFAEnrollmentChallenge struct {
	MFAEnrollmentRequired bool     `json:"mfa_enrollment_required"`
	EnrollmentToken       string   `json:"enrollment_token"`
	AllowedMethods        []string `json:"allowed_methods"`
	ExpiresIn             int      `json:"expires_in"`
}

// LoginResult wraps a full token pair, an OTP challenge, or a forced-MFA
// enrollment challenge — exactly one field is non-nil.
type LoginResult struct {
	Token         *AuthResult
	OTPChallenge  *OTPChallenge
	MFAEnrollment *MFAEnrollmentChallenge
}

// MeResult is returned by GET /api/v1/auth/me.
type MeResult struct {
	UserID      string   `json:"user_id"`
	TenantID    string   `json:"tenant_id"`
	Email       string   `json:"email"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	// AdminScope and AdminApps mirror the token's administrative reach (issue
	// #97) so a client can render the same boundary the server enforces —
	// showing a co-owner only the applications they administer, rather than
	// offering every tenant-level control and letting each one 403 on submit.
	// Empty for callers who are not tenant administrators.
	AdminScope string   `json:"admin_scope,omitempty"`
	AdminApps  []string `json:"admin_apps,omitempty"`
}

// resolveTenant fetches the tenant id by slug. Returns pgx.ErrNoRows if not found.
//
// It used to also SELECT jwt_secret, which both call sites discarded with `_`
// (issue #95). Nothing leaked, but pulling signing authority into memory for no
// reason is exactly the kind of gratuitous handling that turns into a leak the
// day someone adds a log line or an error message that includes the row.
// Signing now goes through JWTService, which fetches the key it needs itself.
func (s *AuthService) resolveTenant(ctx context.Context, slug string) (id int64, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = $1 AND is_active = true`,
		slug,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("resolve tenant %q: %w", slug, err)
	}
	return id, nil
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

// sessionContext describes the session a token pair is being minted into.
//
// Grouped into a struct rather than added as parameters because issueTokenPair
// has eight call sites (password login, registration, MFA completion, magic link,
// both social callbacks, SAML, and the two refresh paths) and the set of
// per-session facts keeps growing — persistence, authentication time, methods
// used, and the family's absolute deadline all arrived together. A struct means
// the next addition has one zero value to define instead of eight call sites to
// edit, and a caller that omits a field gets the documented default rather than
// whatever the parameter order happened to put there.
type sessionContext struct {
	// sessionID is nil for a new session (a user_sessions row is created) and set
	// when rotating a credential within an existing one.
	sessionID *int64
	// persistent records whether the user asked to be remembered, selecting which
	// idle clock the policy applies. False — the safer of the two — is the zero
	// value.
	persistent bool
	// amr lists the authentication methods actually used (OIDC "amr").
	amr []string
	// authTime is when the user proved who they were. Zero means "now", correct for
	// a fresh login. Rotation leaves it alone: it is already on the session row, so
	// there is nothing to carry forward and nothing to get wrong.
	authTime time.Time
}

// issueTokenPair signs a JWT access token and persists a matching refresh token.
//
// appID is the string-encoded oauth_clients.id when the token is issued through a
// registered application; pass "" when no application context is present.
//
// Ordering note: the refresh-token row is inserted BEFORE the JWT is signed, and
// the signing happens inside the same transaction. Both are deliberate. A new
// session's family id is the inserted row's own primary key, and that id is the
// "sid" claim, so the row must exist before the token can be signed — and signing
// inside the transaction means a signing failure rolls the row back instead of
// leaving a live refresh token that no access token was ever paired with.
func (s *AuthService) issueTokenPair(ctx context.Context, userID, tenantID int64, email, role string, perms []string, sess sessionContext, appID string) (*AuthResult, error) {
	return s.issueTokenPairWithScope(ctx, userID, tenantID, email, role, perms, sess, appID, "")
}

// issueTokenPairWithScope is issueTokenPair with the OAuth `scope` claim.
//
// Only the OAuth authorization-code path passes a non-empty scope; every other
// caller goes through issueTokenPair and gets "". That is not incidental — the
// claim is `omitempty`, so "" produces an ABSENT claim, and absent is what every
// first-party flow must keep emitting. An empty-but-present scope claim reads
// downstream as "granted nothing" and would strip the claims those callers
// depend on (see Claims.Scope and /oauth/userinfo).
func (s *AuthService) issueTokenPairWithScope(ctx context.Context, userID, tenantID int64, email, role string, perms []string, sess sessionContext, appID, scope string) (*AuthResult, error) {
	claims := &Claims{
		UserID:      strconv.FormatInt(userID, 10),
		TenantID:    strconv.FormatInt(tenantID, 10),
		AppID:       appID,
		Email:       email,
		Role:        role,
		Permissions: perms,
		Scope:       scope,
	}

	// Administrative reach is resolved here rather than at each caller because
	// every path that mints a user token — Login, Register, Refresh, MFA
	// completion, magic link, OAuth callbacks — funnels through this function.
	// Resolving it once means a co-owner's grants cannot survive their own
	// revocation by riding a refresh rotation that forgot to reload them.
	// resolveAdminScope picks between the 00062 tables and admin_grants (00071)
	// according to ADMIN_GRANTS_ENABLED, and shadow-compares the two while the
	// flag is off. The claim's shape is identical either way, so a token minted
	// across the cutover is indistinguishable to every guard.
	adminScope, adminApps, err := s.resolveAdminScope(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	claims.AdminScope, claims.AdminApps = adminScope, adminApps

	rawRefresh, err := GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}
	refreshHash := HashToken(rawRefresh)

	// Session lifetime is per-tenant policy, not a global constant: see
	// migration 00067. Resolution never fails — it degrades to platform defaults —
	// so a policy-table problem cannot stop anybody signing in.
	policy := s.policySvc.Resolve(ctx, tenantID, parseAppID(appID))

	now := time.Now().UTC()
	authTime := sess.authTime
	if authTime.IsZero() {
		authTime = now
	}

	// The idle deadline is measured from NOW (this rotation is the activity that
	// resets it), while the absolute deadline is measured from the original
	// authentication and never moves. Deriving both from authTime would make the
	// idle clock un-resettable; deriving both from now would make the absolute cap
	// slide forever, which is the bug the cap exists to prevent.
	//
	// On rotation the absolute deadline is not recomputed at all — it is already on
	// the session row and stays there. Only the idle clock is written.
	_, absoluteExpiresAt := policy.Deadlines(authTime, sess.persistent)
	idleExpiresAt := now.Add(policy.IdleTTLFor(sess.persistent))
	if idleExpiresAt.After(absoluteExpiresAt) {
		idleExpiresAt = absoluteExpiresAt
	}

	amr := sess.amr
	if amr == nil {
		amr = []string{}
	}
	device := requestctx.FromContext(ctx)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin session tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var sessionID int64
	// tokenExpiresAt is the credential's own deadline, distinct from the session's.
	// Clamped to the session's absolute cap so a token can never outlive the session
	// that issued it.
	var tokenExpiresAt time.Time
	// evicted holds sessions the concurrent-session cap displaced. Denied only after
	// a successful commit — see the end of this function.
	var evicted []int64

	if sess.sessionID != nil {
		// Rotation. The session row already holds the authentication context and the
		// absolute cap; all that changes is that it has been used again.
		//
		// This is the change the parent table buys: nothing is copied forward, so no
		// rotation path can drop a field and silently alter the session's character.
		// Re-reading the absolute deadline rather than trusting the caller also means
		// a policy change cannot retroactively extend a session already in flight.
		sessionID = *sess.sessionID
		// revoked_at IS NULL is re-checked here, not just in the caller's lookup.
		//
		// The caller read the session a moment ago; a revoke landing in between would
		// otherwise have this UPDATE touch a revoked session and mint a token against
		// it. The token would be unusable — every read requires a live session — but
		// the caller would be handed it as though the refresh had succeeded. Failing
		// here instead turns the race into the correct answer: the session is gone,
		// so the refresh is invalid.
		if err := tx.QueryRow(ctx, `
			UPDATE user_sessions
			SET last_seen_at = NOW(),
			    idle_expires_at = LEAST($2, absolute_expires_at),
			    updated_at = NOW()
			WHERE id = $1 AND revoked_at IS NULL
			RETURNING absolute_expires_at
		`, sessionID, idleExpiresAt).Scan(&tokenExpiresAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, ErrInvalidRefreshToken
			}
			return nil, fmt.Errorf("touch session: %w", err)
		}
	} else {
		// New session. Serialise concurrent logins for this user before counting
		// live sessions: the cap's count-then-insert would otherwise let N
		// simultaneous logins each see room for one more and each take it,
		// overshooting by N. The lock is transaction-scoped, so the commit or
		// rollback below releases it without an explicit unlock.
		lockA, lockB := sessionCapLockKey(userID, tenantID)
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, $2)`, lockA, lockB); err != nil {
			return nil, fmt.Errorf("acquire session cap lock: %w", err)
		}
		evicted, err = enforceSessionCap(ctx, tx, userID, tenantID, policy.MaxConcurrentSessions)
		if err != nil {
			return nil, err
		}

		if err := tx.QueryRow(ctx, `
			INSERT INTO user_sessions
			    (user_id, tenant_id, application_id, user_agent, device_hint, ip_address,
			     auth_time, amr, is_persistent, idle_expires_at, absolute_expires_at)
			VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, '')::INET,
			        $7, $8, $9, $10, $11)
			RETURNING id
		`, userID, tenantID, parseAppID(appID), device.UserAgent, DeviceHint(device.UserAgent),
			device.IPAddress, authTime, amr, sess.persistent,
			idleExpiresAt, absoluteExpiresAt).Scan(&sessionID); err != nil {
			return nil, fmt.Errorf("create session: %w", err)
		}
		tokenExpiresAt = absoluteExpiresAt
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO refresh_tokens
		    (user_id, tenant_id, token_hash, expires_at, session_id, session_family_id, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $5, NOW())
	`, userID, tenantID, refreshHash, tokenExpiresAt, sessionID); err != nil {
		return nil, fmt.Errorf("persist refresh token: %w", err)
	}

	// "sid" is the OIDC session identifier, and now genuinely identifies a row.
	// It is what makes a single session revocable on its own: without it the access
	// token carries no session identity and there is no way to invalidate one.
	claims.SessionID = strconv.FormatInt(sessionID, 10)

	accessToken, err := s.jwtSvc.Sign(ctx, tenantID, AudienceAPI, claims)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit refresh token: %w", err)
	}

	// Only now deny the sessions the cap displaced.
	//
	// After the commit, and NOT in a defer: a defer registered at eviction time also
	// runs when the function returns an error — a failed JWT signing, say — and the
	// transaction has then rolled back, so the eviction never happened. Denying in
	// that case would sign users out of sessions that were never actually evicted.
	// A Redis entry cannot be rolled back, so it must not be written until the
	// database says the eviction is real.
	for _, id := range evicted {
		s.denySession(ctx, id)
	}

	return &AuthResult{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(AccessTokenTTL.Seconds()),
		ExpiresAt:    now.Add(AccessTokenTTL).Unix(),
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
func (s *AuthService) Register(ctx context.Context, in RegisterInput) (*RegisterResult, error) {
	in.Email = emailaddr.Normalize(in.Email)

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
			slugTenantID, err := s.resolveTenant(ctx, in.TenantSlug)
			if err != nil || slugTenantID != tid {
				return nil, ErrInvalidClient
			}
		}
		tenantID, appRowID = tid, &aid
		appID = strconv.FormatInt(aid, 10)
	} else {
		tid, err := s.resolveTenant(ctx, in.TenantSlug)
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

	// Only application-credentialed registration can pick up a default role —
	// end-user default roles are defined per application, and tenant-management
	// roles (owner/super_admin) must never be auto-assigned by self-registration.
	var roleID *int64
	var roleName string
	if appRowID != nil {
		err = s.pool.QueryRow(ctx,
			`SELECT id, name FROM roles
			 WHERE tenant_id = $1 AND application_id = $2 AND is_default = true AND is_system = false`,
			tenantID, *appRowID,
		).Scan(&roleID, &roleName)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("fetch default role: %w", err)
		}
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

	// Dispatch an email-verification link (best-effort — never blocks or fails
	// the registration). Google/social sign-ups arrive pre-verified elsewhere.
	if s.verifSvc != nil {
		appName := ""
		if appRowID != nil {
			appName = s.appNameByID(ctx, appID)
		}
		s.verifSvc.SendVerification(ctx, tenantID, appRowID, userID, in.Email, appName)
	}

	// Warn if the password chosen at sign-up is already in a breach corpus — the
	// earliest useful moment to tell the user. Detached; never blocks registration.
	s.brchSvc.Notify(ctx, tenantID, appRowID, userID, in.Email, in.Password)

	// Registration deliberately does NOT sign the user in.
	//
	// It used to return a token pair, which meant creating a session — so every new
	// account began with a session nobody had asked for. A client that registered and
	// then logged in (the normal shape, and what our own portal does) produced two
	// sessions seconds apart, and the user's device list opened on a phantom entry
	// they could not explain.
	//
	// Creating an account and starting a session are separate acts, and only the
	// second is a statement about a device. The portal already worked this way — its
	// register mutation discards the response and routes to /login — so the tokens
	// were unused by the one client we control.
	return &RegisterResult{
		UserID:        userID,
		TenantID:      tenantID,
		ApplicationID: appRowID,
		Email:         in.Email,
		Role:          roleName,
	}, nil
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
	in.Email = emailaddr.Normalize(in.Email)

	// Application-authenticated mode: verify the app before touching any user
	// data so bad app credentials fail fast and identically regardless of the
	// submitted email.
	appID := ""
	var appTenantID, appRowID int64
	switch {
	case in.VerifiedApp != nil:
		// Caller already resolved this application from oauth_clients — see the
		// LoginInput.VerifiedApp contract. Checked first so a caller that
		// supplies both does not silently get the secret path instead.
		appTenantID, appRowID = in.VerifiedApp.TenantID, in.VerifiedApp.AppRowID
		appID = strconv.FormatInt(appRowID, 10)
	case in.ClientSecret != "":
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
		// Per-account brute-force counting. Every candidate account saw a failed
		// attempt, so each one's counter advances: in the generic (non-app) mode a
		// single wrong guess for an email held in several tenants counts against
		// each of those accounts, which is the intended reading of "this account
		// was attacked". The per-IP limiter remains the first line of defence.
		for i := range candidates {
			s.blockSvc.RecordFailedLogin(ctx, candidates[i].tenantID, candidates[i].userID)
		}
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

	// The password is now proven correct, so the lockout counter is cleared here
	// rather than after the MFA gate: a user who holds the right password should
	// not accumulate lockout progress while completing a second factor.
	s.blockSvc.ResetFailedLogins(ctx, tenantID, userID)

	// Advisory breached-password check (detached; never delays or blocks login).
	s.brchSvc.Notify(ctx, tenantID, appRowIDFromClaim(appID), userID, email, in.Password)

	perms, err := s.loadPermissions(ctx, userID, tenantID)
	if err != nil {
		s.logger.Warn().Err(err).Msg("login: failed to load permissions, continuing with empty set")
		perms = []string{}
	}

	if gate, err := s.mfaGate(ctx, userID, tenantID, appRowID, appID, email, roleName, perms, in.Persistent); err != nil {
		return nil, err
	} else if gate != nil {
		return gate, nil
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

	tokens, err := s.issueTokenPair(ctx, userID, tenantID, email, roleName, perms,
		sessionContext{persistent: in.Persistent, amr: []string{AMRPassword}}, appID)
	if err != nil {
		return nil, err
	}
	return &LoginResult{Token: tokens}, nil
}

// mfaGate applies the post-credential MFA step shared by every first factor
// (password login and magic-link verification). It returns a non-nil
// LoginResult carrying a challenge when one is due, or nil when the caller
// may issue tokens directly:
//
//   - any ACTIVE second factor (TOTP or email) → OTP challenge, even when the
//     application's policy is 'disabled' (fail-secure: the server never
//     silently skips a factor the user set up; admins remove enrollments
//     explicitly via the MFA reset API);
//   - application mode 'required' and no active factor → forced-enrollment
//     challenge. Fails closed on a policy read error — issuing tokens when we
//     cannot prove the app does NOT require MFA would turn a transient DB
//     error into a silent policy bypass.
//
// persistent carries the caller's "remember me" choice into the challenge state so
// the finally-issued session honours it. Threaded through rather than re-read at the
// completion step because the completion request has no access to it: the user
// ticked the box on the password form, one or more requests ago.
func (s *AuthService) mfaGate(ctx context.Context, userID, tenantID, appRowID int64, appID, email, roleName string, perms []string, persistent bool) (*LoginResult, error) {
	if s.totpSvc == nil || s.redisCli == nil {
		return nil, nil
	}

	// Load the application's policy first so it governs which active factors are
	// offered. Fail closed on a read error — issuing tokens when we cannot read
	// the policy would turn a transient DB error into a silent MFA bypass.
	// appRowID 0 is a non-app-scoped login (tenant admin): no app policy, so
	// every active factor is honoured.
	var mode string
	var allowedMethods []string
	if appRowID != 0 {
		var cfgErr error
		mode, allowedMethods, cfgErr = s.totpSvc.GetAppMFAConfig(ctx, appRowID)
		if cfgErr != nil {
			return nil, fmt.Errorf("load app MFA policy: %w", cfgErr)
		}
	}

	totpActive, err := s.totpSvc.IsActive(ctx, userID)
	if err != nil {
		s.logger.Warn().Err(err).Msg("login: failed to check TOTP status, skipping TOTP step")
	}
	emailActive := false
	if s.emailSvc != nil {
		emailActive, err = s.emailSvc.IsActive(ctx, userID)
		if err != nil {
			s.logger.Warn().Err(err).Msg("login: failed to check email MFA status, skipping email step")
			emailActive = false
		}
	}

	// The application policy is authoritative: a factor is only challenged/sent
	// when it is BOTH active for the user AND still in the app's allowed_methods.
	// Removing a method from the policy therefore stops it being offered even to
	// users who had already enrolled it. A non-app login (appRowID 0) has no
	// policy and honours every active factor.
	permitted := func(method string) bool {
		return appRowID == 0 || methodAllowed(allowedMethods, method)
	}
	var methods []string
	if totpActive && permitted(MFAMethodTOTP) {
		methods = append(methods, MFAMethodTOTP)
	}
	if emailActive && permitted(MFAMethodEmail) {
		methods = append(methods, MFAMethodEmail)
	}

	if len(methods) > 0 {
		challenge, err := s.createOTPSession(ctx, userID, tenantID, email, roleName, perms, appID, methods, persistent)
		if err != nil {
			return nil, fmt.Errorf("create OTP session: %w", err)
		}
		return &LoginResult{OTPChallenge: challenge}, nil
	}

	// No policy-permitted active factor remains. Under 'required' the user must
	// (re)enroll a permitted method before finishing login; otherwise the login
	// proceeds (the app does not enforce MFA).
	if appRowID != 0 && mode == MFAModeRequired {
		challenge, err := s.createMFAEnrollmentSession(ctx, userID, tenantID, email, roleName, perms, appID, allowedMethods, persistent)
		if err != nil {
			return nil, fmt.Errorf("create MFA enrollment session: %w", err)
		}
		return &LoginResult{MFAEnrollment: challenge}, nil
	}
	return nil, nil
}

// LoginOTPInput is the payload for completing a TOTP-gated login.
type LoginOTPInput struct {
	OTPSessionToken string
	Code            string
}

// emailCodeConsume deletes the stored email-code hash only when it matches the
// submitted hash, in one atomic step. A plain GET-check-then-delete would let
// two concurrent requests both pass the comparison and redeem the same code
// once each; a plain GETDEL would burn an outstanding email code whenever a
// non-matching code (e.g. a TOTP code) is tried against it.
var emailCodeConsume = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
	return redis.call("DEL", KEYS[1])
end
return 0
`)

// consumeEmailCode reports whether code matches the email-code hash stored at
// key, consuming the hash atomically on success so the code is single-use even
// under concurrent verification attempts. A mismatch (or missing/expired key)
// leaves any stored code intact and returns false.
func (s *AuthService) consumeEmailCode(ctx context.Context, key, code string) bool {
	n, err := emailCodeConsume.Run(ctx, s.redisCli, []string{key}, HashToken(code)).Int()
	return err == nil && n == 1
}

// LoginOTP completes a TOTP-gated login.
func (s *AuthService) LoginOTP(ctx context.Context, in LoginOTPInput) (*AuthResult, error) {
	if s.totpSvc == nil || s.redisCli == nil {
		return nil, fmt.Errorf("TOTP not configured on this server")
	}

	key := otpSessionKey(in.OTPSessionToken)
	session, err := s.loadOTPSession(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired OTP session")
	}

	// Per-session attempt budget — a 6-digit code inside a 5-minute window
	// with unlimited attempts is a realistic brute-force target.
	if err := s.bumpOTPAttempts(ctx, key, OTPSessionTTL); err != nil {
		return nil, err
	}

	// Accept whichever active method the code satisfies: the emailed code for
	// this session, a TOTP code, or a backup code.
	verified := false
	if methodAllowed(session.Methods, MFAMethodEmail) {
		verified = s.consumeEmailCode(ctx, key+":email", in.Code)
	}
	if !verified && methodAllowed(session.Methods, MFAMethodTOTP) {
		if s.totpSvc.Verify(ctx, session.UserID, in.Code) == nil {
			verified = true
		} else if s.totpSvc.VerifyBackupCode(ctx, session.UserID, in.Code) == nil {
			verified = true
		}
	}
	if !verified {
		return nil, fmt.Errorf("invalid TOTP code")
	}

	s.clearOTPSession(ctx, key)

	// session.AppID carries the application context through the challenge so
	// an app-authenticated login keeps its app_id claim after the OTP step.
	return s.issueTokenPair(ctx, session.UserID, session.TenantID, session.Email, session.RoleName, session.Perms,
		sessionContext{
			persistent: session.Persistent,
			amr:        []string{AMRPassword, AMROTP, AMRMFA},
		}, session.AppID)
}

// EnrollPending generates the TOTP secret for a forced-enrollment login
// (application MFA mode 'required', user not yet enrolled). Authorized solely
// by the enrollment token minted at the password step — no JWT exists yet.
// The returned OTPSession identifies the user for audit logging.
func (s *AuthService) EnrollPending(ctx context.Context, enrollmentToken string) (*EnrollResult, *OTPSession, error) {
	if s.totpSvc == nil || s.redisCli == nil {
		return nil, nil, fmt.Errorf("TOTP not configured on this server")
	}

	key := mfaEnrollKey(enrollmentToken)
	session, err := s.loadOTPSession(ctx, key)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid or expired enrollment session")
	}

	// Forced enrollment must respect the application's allowed method set.
	if !methodAllowed(session.Methods, MFAMethodTOTP) {
		return nil, nil, ErrMFAMethodNotAllowed
	}

	// The session exists because the user had no ACTIVE enrollment at the
	// password step. If one was activated since (e.g. a parallel login
	// completed enrollment first), this token must not rotate it.
	active, err := s.totpSvc.IsActive(ctx, session.UserID)
	if err != nil {
		return nil, nil, err
	}
	if active {
		s.clearOTPSession(ctx, key)
		return nil, nil, fmt.Errorf("invalid or expired enrollment session")
	}

	// The authenticator entry is labelled with the owning application's name.
	issuer := s.appNameByID(ctx, session.AppID)

	result, err := s.totpSvc.Enroll(ctx, session.UserID, session.TenantID, session.Email, issuer)
	if err != nil {
		return nil, nil, err
	}
	return result, session, nil
}

// SendPendingEnrollmentCode starts the EMAIL path of a forced enrollment:
// mints a one-time code bound to the enrollment session and sends it to the
// account's inbox. Activating with that code (ActivatePending) enrolls the
// user in email MFA and completes the login.
func (s *AuthService) SendPendingEnrollmentCode(ctx context.Context, enrollmentToken string) (*OTPSession, error) {
	if s.emailSvc == nil || s.redisCli == nil {
		return nil, fmt.Errorf("email MFA not configured on this server")
	}

	key := mfaEnrollKey(enrollmentToken)
	session, err := s.loadOTPSession(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired enrollment session")
	}
	if !methodAllowed(session.Methods, MFAMethodEmail) {
		return session, ErrMFAMethodNotAllowed
	}

	resends, err := s.redisCli.Incr(ctx, key+":resend").Result()
	if err != nil {
		return session, ErrServiceUnavailable
	}
	if resends == 1 {
		s.redisCli.Expire(ctx, key+":resend", MFAEnrollmentSessionTTL+time.Minute) //nolint:errcheck
	}
	if resends > EmailOTPMaxResends {
		return session, ErrTooManyResends
	}

	appName := s.appNameByID(ctx, session.AppID)
	if err := s.emailSvc.mintAndSend(ctx, key+":email", session.Email, appName, session.TenantID, appRowIDFromClaim(session.AppID), MFAEnrollmentSessionTTL); err != nil {
		return session, err
	}
	return session, nil
}

// ActivatePending verifies the first TOTP code of a forced enrollment,
// activates it, and completes the pending login in one step — the response
// carries the token pair, so the user lands in the application without
// re-entering their password. The returned OTPSession identifies the user for
// audit logging (non-nil whenever the session resolved, even on code errors).
func (s *AuthService) ActivatePending(ctx context.Context, enrollmentToken, code string) (*AuthResult, *OTPSession, error) {
	if s.totpSvc == nil || s.redisCli == nil {
		return nil, nil, fmt.Errorf("TOTP not configured on this server")
	}

	key := mfaEnrollKey(enrollmentToken)
	session, err := s.loadOTPSession(ctx, key)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid or expired enrollment session")
	}

	if err := s.bumpOTPAttempts(ctx, key, MFAEnrollmentSessionTTL); err != nil {
		return nil, session, err
	}

	// The code may satisfy either pending path: the emailed enrollment code
	// (email method) or the first authenticator code (TOTP method). The email
	// hash is checked first — a 6-digit emailed code must never be fed into
	// the TOTP activator, and vice versa a TOTP code will not match the hash.
	activated := false
	if methodAllowed(session.Methods, MFAMethodEmail) && s.emailSvc != nil {
		if s.consumeEmailCode(ctx, key+":email", code) {
			if err := s.emailSvc.ActivatePendingEnrollment(ctx, session.UserID, session.TenantID); err != nil {
				return nil, session, err
			}
			activated = true
		}
	}
	if !activated {
		if !methodAllowed(session.Methods, MFAMethodTOTP) {
			return nil, session, fmt.Errorf("invalid TOTP code")
		}
		if err := s.totpSvc.VerifyAndActivate(ctx, session.UserID, code); err != nil {
			return nil, session, err
		}
	}

	s.clearOTPSession(ctx, key)

	tokens, err := s.issueTokenPair(ctx, session.UserID, session.TenantID, session.Email, session.RoleName, session.Perms,
		sessionContext{
			persistent: session.Persistent,
			amr:        []string{AMRPassword, AMROTP, AMRMFA},
		}, session.AppID)
	if err != nil {
		return nil, session, err
	}
	return tokens, session, nil
}

// createOTPSession stores pre-auth user state in Redis and returns a challenge
// token. When the user's active methods include email, a one-time code is
// minted and sent to the account's inbox alongside the challenge.
func (s *AuthService) createOTPSession(ctx context.Context, userID, tenantID int64, email, roleName string, perms []string, appID string, methods []string, persistent bool) (*OTPChallenge, error) {
	sessionToken, err := s.storePreAuthSession(ctx, otpSessionKey, OTPSessionTTL, OTPSession{
		UserID:     userID,
		TenantID:   tenantID,
		Email:      email,
		RoleName:   roleName,
		Perms:      perms,
		AppID:      appID,
		Methods:    methods,
		Persistent: persistent,
	})
	if err != nil {
		return nil, err
	}

	if methodAllowed(methods, MFAMethodEmail) && s.emailSvc != nil {
		appName := s.appNameByID(ctx, appID)
		if err := s.emailSvc.mintAndSend(ctx, otpSessionKey(sessionToken)+":email", email, appName, tenantID, appRowIDFromClaim(appID), OTPSessionTTL); err != nil {
			// If email is the ONLY method the challenge would be uncompletable —
			// fail the login rather than strand the user. With TOTP also active
			// the challenge still works, so log and continue.
			if !methodAllowed(methods, MFAMethodTOTP) {
				s.clearOTPSession(ctx, otpSessionKey(sessionToken))
				return nil, fmt.Errorf("send email OTP: %w", err)
			}
			s.logger.Warn().Err(err).Msg("login: email OTP send failed, TOTP still available")
		}
	}

	return &OTPChallenge{
		RequiresOTP:     true,
		OTPSessionToken: sessionToken,
		Methods:         methods,
		ExpiresIn:       int(OTPSessionTTL.Seconds()),
	}, nil
}

// ResendLoginOTP re-sends the emailed code for an open OTP challenge, capped
// at EmailOTPMaxResends per session.
func (s *AuthService) ResendLoginOTP(ctx context.Context, otpSessionToken string) error {
	if s.emailSvc == nil || s.redisCli == nil {
		return fmt.Errorf("email MFA not configured on this server")
	}
	key := otpSessionKey(otpSessionToken)
	session, err := s.loadOTPSession(ctx, key)
	if err != nil {
		return fmt.Errorf("invalid or expired OTP session")
	}
	if !methodAllowed(session.Methods, MFAMethodEmail) {
		return fmt.Errorf("email is not an available method for this login")
	}

	resends, err := s.redisCli.Incr(ctx, key+":resend").Result()
	if err != nil {
		return ErrServiceUnavailable
	}
	if resends == 1 {
		s.redisCli.Expire(ctx, key+":resend", OTPSessionTTL+time.Minute) //nolint:errcheck
	}
	if resends > EmailOTPMaxResends {
		return ErrTooManyResends
	}

	appName := s.appNameByID(ctx, session.AppID)
	return s.emailSvc.mintAndSend(ctx, key+":email", session.Email, appName, session.TenantID, appRowIDFromClaim(session.AppID), OTPSessionTTL)
}

// createMFAEnrollmentSession stores pre-auth state for a forced enrollment and
// returns the challenge handed back by Login instead of tokens.
func (s *AuthService) createMFAEnrollmentSession(ctx context.Context, userID, tenantID int64, email, roleName string, perms []string, appID string, allowedMethods []string, persistent bool) (*MFAEnrollmentChallenge, error) {
	enrollmentToken, err := s.storePreAuthSession(ctx, mfaEnrollKey, MFAEnrollmentSessionTTL, OTPSession{
		UserID:     userID,
		TenantID:   tenantID,
		Email:      email,
		RoleName:   roleName,
		Perms:      perms,
		AppID:      appID,
		Methods:    allowedMethods,
		Persistent: persistent,
	})
	if err != nil {
		return nil, err
	}
	return &MFAEnrollmentChallenge{
		MFAEnrollmentRequired: true,
		EnrollmentToken:       enrollmentToken,
		AllowedMethods:        allowedMethods,
		ExpiresIn:             int(MFAEnrollmentSessionTTL.Seconds()),
	}, nil
}

// appRowIDFromClaim parses the string-encoded oauth_clients.id used in JWT
// claims and pre-auth sessions; nil for tenant-level ("") or malformed values.
func appRowIDFromClaim(appID string) *int64 {
	if appID == "" {
		return nil
	}
	id, err := strconv.ParseInt(appID, 10, 64)
	if err != nil {
		return nil
	}
	return &id
}

// appNameByID resolves an application's display name from its string row id;
// returns "" for tenant-level logins or on lookup failure (personalisation
// only — never fatal).
func (s *AuthService) appNameByID(ctx context.Context, appID string) string {
	if appID == "" {
		return ""
	}
	id, err := strconv.ParseInt(appID, 10, 64)
	if err != nil {
		return ""
	}
	var name string
	if err := s.pool.QueryRow(ctx, `SELECT name FROM oauth_clients WHERE id = $1`, id).Scan(&name); err != nil {
		return ""
	}
	return name
}

// storePreAuthSession mints an opaque token, stores the session under
// keyFn(token) with the given TTL, and returns the raw token.
func (s *AuthService) storePreAuthSession(ctx context.Context, keyFn func(string) string, ttl time.Duration, sess OTPSession) (string, error) {
	raw, err := GenerateRefreshToken()
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		return "", err
	}
	if err := s.redisCli.Set(ctx, keyFn(raw), payload, ttl).Err(); err != nil {
		return "", fmt.Errorf("store pre-auth session: %w", err)
	}
	return raw, nil
}

// loadOTPSession retrieves and decodes a pre-auth session from Redis by its
// full storage key (otpSessionKey(...) or mfaEnrollKey(...)).
func (s *AuthService) loadOTPSession(ctx context.Context, key string) (*OTPSession, error) {
	data, err := s.redisCli.Get(ctx, key).Bytes()
	if err != nil {
		return nil, fmt.Errorf("OTP session not found or expired: %w", err)
	}
	var sess OTPSession
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("decode OTP session: %w", err)
	}
	return &sess, nil
}

// bumpOTPAttempts enforces the per-session attempt budget (MaxOTPAttempts).
// Counting uses an atomic INCR on a sibling key; exceeding the budget deletes
// the session so the user must restart from the password step. Fails closed:
// if the counter is unreachable, no verification happens.
func (s *AuthService) bumpOTPAttempts(ctx context.Context, baseKey string, ttl time.Duration) error {
	attemptsKey := baseKey + ":attempts"
	attempts, err := s.redisCli.Incr(ctx, attemptsKey).Result()
	if err != nil {
		return ErrServiceUnavailable
	}
	if attempts == 1 {
		// Outlive the session slightly so the counter cannot expire first and
		// reset the budget mid-session.
		s.redisCli.Expire(ctx, attemptsKey, ttl+time.Minute) //nolint:errcheck
	}
	if attempts > MaxOTPAttempts {
		s.clearOTPSession(ctx, baseKey)
		return ErrTooManyOTPAttempts
	}
	return nil
}

// clearOTPSession removes a pre-auth session and its sibling keys (attempt
// counter, pending email code, resend counter).
func (s *AuthService) clearOTPSession(ctx context.Context, baseKey string) {
	s.redisCli.Del(ctx, baseKey, baseKey+":attempts", baseKey+":email", baseKey+":resend") //nolint:errcheck
}

func otpSessionKey(token string) string {
	return "otp:session:" + HashToken(token)
}

func mfaEnrollKey(token string) string {
	return "mfa:enroll:" + HashToken(token)
}

// Me returns profile information derived from JWT claims.
func (s *AuthService) Me(claims *Claims) *MeResult {
	return &MeResult{
		UserID:      claims.UserID,
		TenantID:    claims.TenantID,
		Email:       claims.Email,
		Role:        claims.Role,
		Permissions: claims.Permissions,
		AdminScope:  claims.AdminScope,
		AdminApps:   claims.AdminApps,
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
	// SessionID is the session the grace-path request belongs to.
	//
	// Carried because the claims synthesised from this result are what the request
	// then authenticates with, and claims without a session id are exempt from the
	// per-session revocation check. Omitting it left a ten-second window — the grace
	// period — in which a single-session revoke was not enforced.
	SessionID int64
}

// Refresh rotates a refresh token pair (AUTH-03).
func (s *AuthService) Refresh(ctx context.Context, rawRefreshToken string) (*AuthResult, error) {
	hash := HashToken(rawRefreshToken)

	// Joined to the session, and BOTH must be live: the token has its own expiry and
	// single-use lifetime, while the session carries the idle and absolute clocks and
	// the revocation flag. Either one being dead means this refresh must fail, and
	// the join is what makes a session revoke instantly effective on every token it
	// issued without having to touch those token rows first.
	var tokenID, userID, tenantID, sessionID int64
	var carried sessionContext
	err := s.pool.QueryRow(ctx, `
		SELECT rt.id, s.user_id, s.tenant_id, s.id,
		       s.is_persistent, s.auth_time, s.amr
		FROM refresh_tokens rt
		JOIN user_sessions s ON s.id = rt.session_id
		WHERE rt.token_hash = $1
		  AND `+LiveTokenWhere("rt.")+`
		  AND `+LiveSessionWhere("s."),
		hash).Scan(&tokenID, &userID, &tenantID, &sessionID,
		&carried.persistent, &carried.authTime, &carried.amr)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, fmt.Errorf("lookup refresh token: %w", err)
	}
	carried.sessionID = &sessionID

	_, err = s.pool.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = NOW(), revoked_reason = $2, updated_at = NOW()
		WHERE id = $1
	`, tokenID, RevokeReasonRotated)
	if err != nil {
		return nil, fmt.Errorf("revoke old refresh token: %w", err)
	}
	metrics.SessionRevocations.WithLabelValues(RevokeReasonRotated).Inc()

	var email, roleName string
	var roleID, applicationID *int64
	err = s.pool.QueryRow(ctx, `
		SELECT u.email, COALESCE(r.name, ''), u.role_id, u.application_id
		FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.id = $1 AND u.tenant_id = $2 AND u.is_active = true AND u.deleted_at IS NULL
	`, userID, tenantID).Scan(&email, &roleName, &roleID, &applicationID)
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

	return s.issueTokenPair(ctx, userID, tenantID, email, roleName, perms, carried, appIDClaim(applicationID))
}

// appIDClaim renders a nullable users.application_id into the string form used
// for the JWT app_id claim: the decimal id for application-scoped users, or ""
// for tenant-level users. Keeping this consistent with Login/Register ensures a
// token's application context survives every refresh rotation.
func appIDClaim(applicationID *int64) string {
	if applicationID == nil {
		return ""
	}
	return strconv.FormatInt(*applicationID, 10)
}

// gracePeriod is the window in which a concurrent rotation is not treated as a replay.
const gracePeriod = 10 // seconds

// checkGraceWindow looks for a token in the given session that was issued within
// the last gracePeriod seconds. Used when concurrent requests arrive on the same
// expiring access token — one rotates, the other hits the grace path.
//
// Scoped by user_id and tenant_id as well as session id. The caller already knows
// both from the presented token, and passing them turns a lookup that USED to be
// able to return a different account's identity into one that provably cannot: the
// historical session_family_id = 0 bug (migration 00068, step 3) put many users'
// tokens in the same family, and this function's result becomes the caller's
// identity for the rest of the request.
//
// The session must still be live, not merely have a recent token: a session revoked
// during the grace window must not be waved through by a token minted a moment
// before the revoke.
func (s *AuthService) checkGraceWindow(ctx context.Context, userID, tenantID, sessionID int64) (*GraceResult, error) {
	err := s.pool.QueryRow(ctx, `
		SELECT 1
		FROM refresh_tokens rt
		JOIN user_sessions s ON s.id = rt.session_id
		WHERE rt.session_id = $1 AND s.user_id = $2 AND s.tenant_id = $3
		  AND rt.created_at > NOW() - make_interval(secs => $4)
		  AND `+LiveTokenWhere("rt.")+`
		  AND `+LiveSessionWhere("s.")+`
		ORDER BY rt.created_at DESC
		LIMIT 1
	`, sessionID, userID, tenantID, gracePeriod).Scan(new(int))
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
		SessionID:   sessionID,
	}, nil
}

// TokenOwner is the resolved identity behind a refresh token, used to attribute
// a *failed* refresh/replay event in the audit trail. It is looked up by token
// hash regardless of the token's revoked/expired state, so a replayed or
// expired token can still be tied to the account whose session it belonged to.
type TokenOwner struct {
	UserID   int64
	TenantID int64
	Email    string
}

// ResolveTokenOwner returns the account a refresh token belongs to, if the token
// hash matches a stored row (revoked or expired included). Returns (nil, false)
// for a token that never existed — those failures stay legitimately anonymous
// in the audit trail rather than being attributed to a guessed identity.
//
// Read-only, single indexed lookup by token_hash; only called on the refresh
// *failure* path (rare, rate-limited), so it adds no cost to successful refresh.
func (s *AuthService) ResolveTokenOwner(ctx context.Context, rawToken string) (*TokenOwner, bool) {
	if rawToken == "" {
		return nil, false
	}
	var o TokenOwner
	err := s.pool.QueryRow(ctx, `
		SELECT rt.user_id, rt.tenant_id, COALESCE(u.email, '')
		FROM refresh_tokens rt
		LEFT JOIN users u ON u.id = rt.user_id
		WHERE rt.token_hash = $1
	`, HashToken(rawToken)).Scan(&o.UserID, &o.TenantID, &o.Email)
	if err != nil {
		return nil, false
	}
	return &o, true
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

	// Initial read — fetch the token row WITHOUT the liveness predicate, including
	// revoked and expired rows.
	//
	// This must stay unfiltered even though every other read applies the liveness
	// predicates. Replay detection depends on recognising a token that exists but is
	// no longer live: filtering here would turn a replayed token into ErrNoRows →
	// "invalid token", silently downgrading a security event into a routine failure
	// and never revoking the session the attacker holds. The liveness checks are
	// applied explicitly further down instead, after the lock.
	//
	// The session join is a LEFT JOIN for the same reason the token filter is absent:
	// a token whose session row is gone (reaped, or cascade-deleted with the user)
	// must still be recognisable rather than vanishing into "invalid token".
	var tokenID, userID, tenantID, sessionID int64
	var revokedAt, sessionRevokedAt *time.Time
	var expiresAt time.Time
	var sessionIdleExpires, sessionAbsoluteExpires *time.Time
	var carried sessionContext
	err := s.pool.QueryRow(ctx, `
		SELECT rt.id, rt.user_id, rt.tenant_id,
		       COALESCE(rt.session_id, rt.session_family_id),
		       rt.revoked_at, rt.expires_at,
		       COALESCE(s.is_persistent, false),
		       COALESCE(s.auth_time, rt.created_at),
		       COALESCE(s.amr, '{}'),
		       s.revoked_at, s.idle_expires_at, s.absolute_expires_at
		FROM refresh_tokens rt
		LEFT JOIN user_sessions s ON s.id = rt.session_id
		WHERE rt.token_hash = $1
	`, hash).Scan(&tokenID, &userID, &tenantID, &sessionID, &revokedAt, &expiresAt,
		&carried.persistent, &carried.authTime, &carried.amr,
		&sessionRevokedAt, &sessionIdleExpires, &sessionAbsoluteExpires)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrInvalidRefreshToken
		}
		return nil, nil, fmt.Errorf("lookup refresh token: %w", err)
	}
	carried.sessionID = &sessionID

	lockKey := fmt.Sprintf("renewal:lock:session:%d", sessionID)

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
		// Another request is currently rotating this session. Wait briefly then
		// check whether a fresh token was issued within the grace window.
		time.Sleep(300 * time.Millisecond)
		grace, err := s.checkGraceWindow(ctx, userID, tenantID, sessionID)
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
		if _, err := s.revokeSession(ctx, userID, tenantID, sessionID, RevokeReasonReplay); err != nil {
			s.logger.Error().Err(err).Int64("session_id", sessionID).Msg("renewal: session revocation failed")
		}
		return nil, nil, ErrTokenReplay
	}

	// Lifetime checks, applied here rather than in the lookup query so that a
	// replayed token still reaches the session revoke above.
	//
	// An expired or revoked SESSION is ErrInvalidRefreshToken, NOT a replay: the user
	// did nothing wrong — they were away too long, or an operator ended the session —
	// and reporting it as a replay would flood the audit trail with false positives
	// and alarm every operator watching that metric.
	//
	// The session-side nils are the mid-rolling-deploy case: a token inserted by the
	// previous binary has no session_id, so the LEFT JOIN found no parent. Treated as
	// "no session-level limit" rather than as expired, because failing those closed
	// would sign out every user still on the old binary.
	nowUTC := time.Now().UTC()
	if expiresAt.Before(nowUTC) ||
		sessionRevokedAt != nil ||
		(sessionAbsoluteExpires != nil && sessionAbsoluteExpires.Before(nowUTC)) ||
		(sessionIdleExpires != nil && sessionIdleExpires.Before(nowUTC)) {
		return nil, nil, ErrInvalidRefreshToken
	}

	// Revoke the presented token.
	_, err = s.pool.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = NOW(), revoked_reason = $2, updated_at = NOW()
		WHERE id = $1
	`, tokenID, RevokeReasonRotated)
	if err != nil {
		return nil, nil, fmt.Errorf("revoke old refresh token: %w", err)
	}
	metrics.SessionRevocations.WithLabelValues(RevokeReasonRotated).Inc()

	// Fresh user load from DB — catches suspensions, role changes, or email bans
	// that occurred during the access token's lifetime (key security gate).
	var email, roleName string
	var roleID, applicationID *int64
	err = s.pool.QueryRow(ctx, `
		SELECT u.email, COALESCE(r.name, ''), u.role_id, u.application_id
		FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.id = $1 AND u.tenant_id = $2 AND u.is_active = true AND u.deleted_at IS NULL
	`, userID, tenantID).Scan(&email, &roleName, &roleID, &applicationID)
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

	result, err := s.issueTokenPair(ctx, userID, tenantID, email, roleName, perms, carried, appIDClaim(applicationID))
	return result, nil, err
}

// IssueServiceToken signs a short-lived access token for a machine client using
// the client_credentials grant. There is no user, no refresh token, and the
// role is fixed to "service". The sub claim carries the public client_id so
// integrators can correlate tokens with their credentials; the numeric
// oauth_clients.id remains available in the app_id claim. Scopes are loaded
// from the oauth_clients.scopes column so downstream permission checks receive
// the correct grants.
//
// The token carries AudienceM2M so it is distinguishable from a user session
// token (issue #84): it is accepted on admin/management routes, where a machine
// client is a legitimate caller subject to its scopes, but refused on user
// self-service routes, which assume a real user behind the token.
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
	token, err := s.jwtSvc.Sign(ctx, tenantID, AudienceM2M, claims)
	if err != nil {
		return "", 0, fmt.Errorf("sign service token: %w", err)
	}
	return token, int(AccessTokenTTL.Seconds()), nil
}

// Logout (AUTH-04) now lives in session.go, where it revokes the whole session
// family rather than the single presented token. See LogoutSession for why.

// RevokeRefreshTokenForTenant revokes a refresh token, but only if it belongs to
// the given tenant. Reports whether a live token was actually revoked.
//
// This is Logout with a tenant guard, and it exists for POST /oauth/revoke
// (RFC 7009). Logout is reached only by a caller already holding that user's own
// session; the revocation endpoint is reached by any client that can
// authenticate, so "I hold this string" must not be sufficient authority to
// invalidate it. Scoping the UPDATE by tenant_id means an authenticated client
// in one tenant cannot revoke a token issued in another — the same isolation
// boundary every other query in this codebase enforces.
//
// The boolean is the honest answer to "did anything happen", which the caller
// needs for its audit record. It must NOT be reflected in the HTTP response:
// RFC 7009 §2.2 requires 200 for an unknown token, because a distinguishable
// response would make this endpoint an oracle for whether a captured string is
// a live token.
//
// Per-client ownership is NOT checked, and cannot be: refresh_tokens carries
// user_id and tenant_id but no application_id (see migrations 00009 / 00026), so
// there is no column to compare a client_id against. Tenant scoping is the
// tightest guard available without a schema change — tracked as CLAUDE.md
// deferred item #22.
func (s *AuthService) RevokeRefreshTokenForTenant(ctx context.Context, rawRefreshToken string, tenantID int64) (bool, error) {
	hash := HashToken(rawRefreshToken)
	tag, err := s.pool.Exec(ctx, `
		UPDATE refresh_tokens
		SET    revoked_at = NOW()
		WHERE  token_hash = $1 AND tenant_id = $2 AND revoked_at IS NULL
	`, hash, tenantID)
	if err != nil {
		return false, fmt.Errorf("revoke refresh token: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// LookupUserForApp resolves an authenticated user to their row id and canonical
// email within one application's isolated user base (issue #6).
//
// Called only AFTER credentials have been verified, by the hosted login at
// /oauth/authorize, which needs the user id to bind an authorization code to.
// It performs no authentication of its own and must never be reachable from an
// unauthenticated path — an email address is not a credential.
//
// Scoped by application_id as well as tenant_id, matching Login's own candidate
// query: an app-authenticated login only ever sees that application's users, so
// resolving the same address against the tenant-level user base here would
// return a different person than the one who just authenticated.
//
// The email is normalized on the way in (issue #104) so a caller that kept the
// user's original casing still matches the stored row.
func (s *AuthService) LookupUserForApp(ctx context.Context, tenantID, appRowID int64, email string) (userID int64, canonicalEmail string, err error) {
	normalized := emailaddr.Normalize(email)
	err = s.pool.QueryRow(ctx, `
		SELECT u.id, u.email
		FROM   users u
		JOIN   tenants t ON t.id = u.tenant_id
		WHERE  u.email = $1 AND u.tenant_id = $2 AND u.application_id = $3
		  AND  u.is_active = true AND u.deleted_at IS NULL AND t.is_active = true
	`, normalized, tenantID, appRowID).Scan(&userID, &canonicalEmail)
	if err != nil {
		return 0, "", fmt.Errorf("lookup user for application: %w", err)
	}
	return userID, canonicalEmail, nil
}

// AuthorizedUser is everything the token endpoint needs about the user behind a
// redeemed authorization code: the tokens to hand back, and the profile facts
// the ID token may describe.
type AuthorizedUser struct {
	Tokens  *AuthResult
	Subject IDTokenSubject
}

// IssueTokensForAuthorizationCode mints the token pair for a redeemed
// authorization code (issue #6) and returns the profile facts alongside it.
//
// The user is re-read here rather than trusted from the code. A code lives 60
// seconds, which is long enough for an account to be deactivated or deleted
// between the authorize redirect and the token exchange; issuing a 15-minute
// access token for an account that no longer exists would outlive the
// revocation by the full token lifetime.
//
// Scoped by application_id as well as tenant_id, matching Login and
// LookupUserForApp — the code was issued inside one application's user base and
// must be redeemed against the same one.
func (s *AuthService) IssueTokensForAuthorizationCode(ctx context.Context, tenantID, userID, appRowID int64, grantedScopes []string) (*AuthorizedUser, error) {
	var (
		email, firstName, lastName, roleName string
		emailVerified                        bool
		updatedAt                            time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT u.email, u.first_name, u.last_name, u.email_verified, u.updated_at,
		       COALESCE(r.name, '')
		FROM   users u
		JOIN   tenants t ON t.id = u.tenant_id
		LEFT   JOIN roles r ON r.id = u.role_id
		WHERE  u.id = $1 AND u.tenant_id = $2 AND u.application_id = $3
		  AND  u.is_active = true AND u.deleted_at IS NULL AND t.is_active = true
	`, userID, tenantID, appRowID).Scan(&email, &firstName, &lastName, &emailVerified, &updatedAt, &roleName)
	if err != nil {
		return nil, fmt.Errorf("load user for authorization code: %w", err)
	}

	perms, err := s.loadPermissions(ctx, userID, tenantID)
	if err != nil {
		// Matches the stance ExchangeLoginCode already takes: a permission-load
		// failure degrades to an empty grant set rather than failing the login,
		// because the alternative is a user who authenticated correctly being
		// unable to sign in at all.
		s.logger.Warn().Err(err).Msg("authorization code: failed to load permissions, continuing with empty set")
		perms = []string{}
	}

	appID := strconv.FormatInt(appRowID, 10)
	tokens, err := s.issueScopedTokenPair(ctx, userID, tenantID, email, roleName, perms, appID, grantedScopes)
	if err != nil {
		return nil, err
	}

	name := strings.TrimSpace(firstName + " " + lastName)
	return &AuthorizedUser{
		Tokens: tokens,
		Subject: IDTokenSubject{
			UserID:        strconv.FormatInt(userID, 10),
			Email:         email,
			EmailVerified: emailVerified,
			Name:          name,
			GivenName:     firstName,
			FamilyName:    lastName,
			UpdatedAt:     updatedAt,
		},
	}, nil
}

// issueScopedTokenPair mints the token pair for an OAuth grant, carrying the
// granted scopes as the `scope` claim.
//
// A thin wrapper on issueTokenPairWithScope: the scope is threaded into the ONE
// signing call rather than the token being signed twice. An earlier shape signed
// without the claim and then re-signed with it, which meant a second Sign and a
// second loadAdminScope — two round trips on the token-exchange path, and a
// window in which two differently-claimed access tokens existed for one grant.
//
// strings.Join of an empty slice is "", so the no-scope case needs no branch:
// the claim is omitempty and simply does not appear.
func (s *AuthService) issueScopedTokenPair(ctx context.Context, userID, tenantID int64, email, role string, perms []string, appID string, scopes []string) (*AuthResult, error) {
	// NOTE (CLAUDE.md deferred #19 / #23): the access token minted here carries
	// the OAuth `scope` claim AND the full internal `permissions` claim. That is
	// safe only because /oauth/authorize refuses first_party = false, so every
	// grant reaching this function belongs to a client the tenant owns. When the
	// consent screen lands and genuinely third-party clients become possible,
	// this line becomes a data-leakage path — an external client would receive
	// internal permission strings it was never shown on a consent page. Filter
	// perms by grant, or drop them for non-first-party clients, as part of that
	// work. Read #19 before enabling third-party clients.
	return s.issueTokenPairWithScope(ctx, userID, tenantID, email, role, perms,
		sessionContext{amr: []string{AMRPassword}}, appID,
		strings.Join(scopes, " "))
}
