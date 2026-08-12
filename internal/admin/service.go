// Package admin implements the Admin API business logic:
// tenant management (super_admin only), user pool CRUD, role CRUD,
// and permission CRUD (all tenant-scoped).
package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/emailaddr"
)

// Sentinel errors returned by service methods.
var (
	// ErrNotFound is returned when a requested resource does not exist within the caller's tenant.
	ErrNotFound = errors.New("not found")
	// ErrAlreadyExists is returned when a unique constraint would be violated.
	ErrAlreadyExists = errors.New("already exists")
	// ErrAlreadyActive is returned when ActivateTenant is called on an already-active tenant.
	ErrAlreadyActive = errors.New("tenant already active")
	// ErrSystemRole is returned when an operation that only applies to end-user
	// application roles (e.g. SetDefaultRole) targets a tenant-management role
	// (super_admin/owner, is_system = true).
	ErrSystemRole = errors.New("cannot use a system role for this operation")
	// ErrPermissionScope is returned when a role-permission assignment refers
	// to a permission that does not exist in the role's own scope — roles are
	// isolated to their application and can only hold that application's
	// permissions (or tenant-level permissions for tenant-level roles).
	ErrPermissionScope = errors.New("permission does not belong to this role's application")
	// ErrRoleScope is returned when a user-role assignment pairs a user and a
	// role from different scopes — an application's users can only hold that
	// application's roles, and tenant-level users only tenant-level roles.
	ErrRoleScope = errors.New("role does not belong to this user's application")
)

// ---------------------------------------------------------------------------
// Result types (returned to handlers → JSON)
// ---------------------------------------------------------------------------

// TenantResult is the public representation of a tenant (jwt_secret is never exposed).
type TenantResult struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	DisplayName *string   `json:"display_name"`
	Domain      *string   `json:"domain"`
	Region      *string   `json:"region"`
	Description *string   `json:"description"`
	Plan        string    `json:"plan"`
	IsActive    bool      `json:"is_active"`
	CORSOrigins []string  `json:"cors_origins"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// OwnedTenantStats summarizes one tenant's size for OwnedTenantResult.
type OwnedTenantStats struct {
	UserCount int `json:"user_count"`
	RoleCount int `json:"role_count"`
	AppCount  int `json:"app_count"`
}

// OwnedTenantResult is one tenant returned by ListOwnedTenants: the tenant
// itself, the caller's role in it, and basic usage stats for that tenant only.
type OwnedTenantResult struct {
	TenantResult
	Role  string           `json:"role"`
	Stats OwnedTenantStats `json:"stats"`
}

// TenantFilter holds optional filter and pagination params for ListTenantsPaginated.
type TenantFilter struct {
	Search string // ILIKE match on name, display_name, domain; empty = no filter
	Status string // "active", "inactive", or "" for all
	Region string // exact match on region column; empty = no filter
	Page   int    // 1-based; defaults to 1
	Limit  int    // rows per page; defaults to 25, max 100
}

// TenantsPage wraps a paginated tenant list.
type TenantsPage struct {
	Data       []TenantResult `json:"data"`
	Total      int            `json:"total"`
	Page       int            `json:"page"`
	TotalPages int            `json:"total_pages"`
	PerPage    int            `json:"per_page"`
}

// Owner account states reported in OwnerResult.Status.
const (
	// OwnerStatusPendingInvitation means the account exists with no password;
	// the owner claims it by following the emailed invitation link.
	OwnerStatusPendingInvitation = "pending_invitation"
)

// OwnerResult carries the auto-created owner user returned once on tenant creation.
//
// It no longer carries a temp_password. Returning a live credential in an HTTP
// response body meant the owner's first password existed in whatever logged,
// proxied, or screenshotted that response, and the address it belonged to had
// never been proven deliverable — a typo produced a tenant nobody could enter,
// with no error to show for it. The owner now proves control of the inbox by
// following the invitation link, which is also what marks the address verified.
//
// InviteSent is false when the invitation could not be delivered. The tenant is
// still created: a mail failure is a reason to resend, not a reason to discard a
// tenant the caller asked for. InviteError then carries the reason, and the
// super-admin break-glass path remains available.
type OwnerResult struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	Role        string `json:"role"`
	Status      string `json:"status"`
	InviteSent  bool   `json:"invite_sent"`
	InviteError string `json:"invite_error,omitempty"`
}

// CreateTenantResult is returned by CreateTenant; it combines the new tenant with
// the auto-seeded owner user.
type CreateTenantResult struct {
	Tenant TenantResult `json:"tenant"`
	Owner  OwnerResult  `json:"owner"`
}

// TenantDashboardDelta holds month-over-month percentage changes.
type TenantDashboardDelta struct {
	TotalTenantsPct      float64 `json:"total_tenants_pct"`
	ActiveTenantsPct     float64 `json:"active_tenants_pct"`
	TotalApplicationsPct float64 `json:"total_applications_pct"`
	TotalUsersPct        float64 `json:"total_users_pct"`
}

// TenantDashboardStats is the system-wide aggregate returned by GetTenantDashboardStats.
type TenantDashboardStats struct {
	TotalTenants      int                  `json:"total_tenants"`
	ActiveTenants     int                  `json:"active_tenants"`
	TotalApplications int                  `json:"total_applications"`
	TotalUsers        int                  `json:"total_users"`
	Delta             TenantDashboardDelta `json:"delta"`
}

// CreateTenantInput carries all fields accepted by CreateTenant.
type CreateTenantInput struct {
	Name        string
	Slug        string
	DisplayName string
	Domain      string
	Region      string
	Description string
	Plan        string // defaults to "free" when empty
	OwnerEmail  string // required; the tenant owner's real, deliverable email
}

// UpdateTenantInput carries all fields accepted by UpdateTenant.
type UpdateTenantInput struct {
	Name        string
	DisplayName string
	Domain      string
	Region      string
	Description string
	Plan        string
}

// PermissionResult is the public representation of a permission.
// ApplicationID is nil for tenant-level management permissions (the seeded
// catalog held by owner/super_admin); set for end-user permissions defined
// inside one of the tenant's applications.
type PermissionResult struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ApplicationID *string   `json:"application_id,omitempty"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	CreatedAt     time.Time `json:"created_at"`
}

// RoleResult is the public representation of a role with its permissions.
// ApplicationID is nil for tenant-management roles (super_admin/owner); set
// for end-user roles defined inside one of the tenant's applications.
type RoleResult struct {
	ID            string             `json:"id"`
	TenantID      string             `json:"tenant_id"`
	ApplicationID *string            `json:"application_id,omitempty"`
	Name          string             `json:"name"`
	IsSystem      bool               `json:"is_system"`
	IsDefault     bool               `json:"is_default"`
	Permissions   []PermissionResult `json:"permissions"`
	CreatedAt     time.Time          `json:"created_at"`
}

// UserResult is the public representation of a user in the pool.
type UserResult struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ApplicationID *string   `json:"application_id,omitempty"`
	Email         string    `json:"email"`
	FirstName     string    `json:"first_name"`
	LastName      string    `json:"last_name"`
	Role          string    `json:"role"`
	RoleID        *string   `json:"role_id"`
	IsActive      bool      `json:"is_active"`
	CreatedAt     time.Time `json:"created_at"`
	// LastLoginAt is the most recent session activity (Auth0's "Latest Login").
	LastLoginAt *time.Time `json:"last_login_at"`
	// LoginsCount is the number of successful logins on record (audit-derived,
	// Auth0's stats.loginsCount equivalent).
	LoginsCount int `json:"logins_count"`
	// Connections lists how this user can sign in: "password" when a
	// credentials row exists, plus every linked federated provider (Auth0's
	// "Connection" column).
	Connections []string `json:"connections"`
}

// UsersPage wraps a paginated user list.
type UsersPage struct {
	Users      []UserResult `json:"users"`
	Total      int          `json:"total"`
	Page       int          `json:"page"`
	TotalPages int          `json:"total_pages"`
}

// UserMFAStatus summarizes a user's enrolled second factors.
type UserMFAStatus struct {
	TOTPEnabled          bool `json:"totp_enabled"`
	EmailEnabled         bool `json:"email_enabled"`
	BackupCodesRemaining int  `json:"backup_codes_remaining"`
}

// UserIdentity is a linked federated (social) identity.
type UserIdentity struct {
	Provider      string    `json:"provider"`
	ProviderEmail *string   `json:"provider_email,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// UserDetail is the enriched single-user view for the admin detail page.
// LastLoginAt/LoginsCount/Connections live on the embedded UserResult.
type UserDetail struct {
	UserResult
	EmailVerified bool `json:"email_verified"`
	// TokenVersion is the internal JWT-invalidation counter. Loaded for internal
	// use but never serialized — exposing it would leak the invalidation
	// mechanism to API clients (the admin UI has no use for it).
	TokenVersion   int            `json:"-"`
	UpdatedAt      time.Time      `json:"updated_at"`
	ActiveSessions int            `json:"active_sessions"`
	MFA            UserMFAStatus  `json:"mfa"`
	Identities     []UserIdentity `json:"identities"`
	// Lockout state. BlockReason distinguishes an automatic failed-attempt
	// lockout (which the user can lift via an emailed link) from an operator
	// block (which they cannot) — without it an admin cannot tell why an account
	// is inactive. Both are nil for an account that was never blocked.
	BlockedAt   *time.Time `json:"blocked_at,omitempty"`
	BlockReason *string    `json:"block_reason,omitempty"`
	// FailedLoginAttempts is the current consecutive-failure count, so an admin
	// can see an account approaching the lockout threshold.
	FailedLoginAttempts int `json:"failed_login_attempts"`
	// PendingInvitation is true when an unused, unexpired invitation exists —
	// the account has been created but never claimed.
	PendingInvitation bool `json:"pending_invitation"`
}

// UserSession is one active refresh-token session family for a user.
type UserSession struct {
	SessionFamilyID string  `json:"session_family_id"`
	IPAddress       *string `json:"ip_address,omitempty"`
	UserAgent       string  `json:"user_agent"`
	// DeviceHint is the server-parsed "Chrome on Windows" form of UserAgent.
	//
	// Both are returned: the hint so a consumer does not need its own User-Agent
	// parser to show a user which device they are looking at, the raw header because
	// it is the evidence and a parser that guesses wrong must not destroy it.
	DeviceHint *string    `json:"device_hint,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
	// IdleExpiresAt is when the session dies if it is not used again, and
	// AbsoluteExpiresAt is the hard deadline it cannot outlive whatever it does.
	// Both are surfaced because "expires_at" alone cannot answer the question an
	// operator actually has — is this session about to go away on its own, or does
	// it need revoking? Nullable for rows written before migration 00068.
	IdleExpiresAt     *time.Time `json:"idle_expires_at,omitempty"`
	AbsoluteExpiresAt *time.Time `json:"absolute_expires_at,omitempty"`
	// IsPersistent records whether the user asked to be remembered on this device.
	IsPersistent bool `json:"is_persistent"`
	// AuthTime is when the user actually authenticated, as opposed to when the
	// current token in the family was minted.
	AuthTime *time.Time `json:"auth_time,omitempty"`
	// AMR lists the authentication methods used to establish the session.
	AMR []string `json:"amr"`
	// IsCurrent marks the session the caller is making this request from.
	//
	// Only ever true on the end-user (/me/sessions) view, where the caller and the
	// subject are the same person: it prevents somebody from revoking the session
	// they are sitting in and wondering why the page broke. On the admin view the
	// caller is a different person from the subject, so no session in the list can
	// be theirs and the field stays false throughout.
	IsCurrent bool `json:"is_current"`
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

// Service implements all Admin API operations.
type Service struct {
	pool     *pgxpool.Pool
	resetSvc *auth.ResetService
	invSvc   *auth.InvitationService   // nil when invitations are not configured
	blockSvc *auth.AccountBlockService // nil when block notifications are not configured
	// signingKeys mints a tenant's asymmetric JWT key pair at creation time
	// (issue #95). nil is safe — key generation then falls back to lazy.
	signingKeys *auth.SigningKeyService
	// authSvc owns session revocation. Admin revocation goes through it rather
	// than issuing its own UPDATE so that revoking from the admin API and revoking
	// from a logout take exactly the same code path — including the revoked-session
	// denylist, without which an admin revoke would leave the session's access
	// token working for up to 15 more minutes while the API reported success.
	//
	// nil is tolerated: session revocation then falls back to a direct database
	// write, which is what this package did before. Tests that construct a bare
	// Service therefore keep working, at the cost of the immediate-revocation
	// accelerator they do not exercise.
	authSvc *auth.AuthService
	logger  zerolog.Logger
}

// New creates a Service.
func New(pool *pgxpool.Pool, resetSvc *auth.ResetService, logger zerolog.Logger) *Service {
	return &Service{pool: pool, resetSvc: resetSvc, logger: logger}
}

// WithAuthService wires the auth service so session revocation shares one
// implementation with logout — see the authSvc field for why that matters.
func (s *Service) WithAuthService(authSvc *auth.AuthService) *Service {
	s.authSvc = authSvc
	return s
}

// WithInvitations wires the invitation service so admin-created accounts can be
// invited instead of handed a password out-of-band.
func (s *Service) WithInvitations(invSvc *auth.InvitationService) *Service {
	s.invSvc = invSvc
	return s
}

// WithAccountBlocking wires the block service so an admin block notifies the
// affected user and an admin unblock clears their lockout counters.
func (s *Service) WithAccountBlocking(blockSvc *auth.AccountBlockService) *Service {
	s.blockSvc = blockSvc
	return s
}

// WithSigningKeys wires the asymmetric signing-key service so a newly created
// tenant gets its RSA key pair immediately (issue #95), rather than lazily on its
// first login. Optional: without it, JWTService's EnsureTenantKey still generates
// on demand, so tenant creation never depends on this being wired.
func (s *Service) WithSigningKeys(keys *auth.SigningKeyService) *Service {
	s.signingKeys = keys
	return s
}

// ---------------------------------------------------------------------------
// Tenant management (super_admin only — caller must hold "tenant:manage" perm)
// ---------------------------------------------------------------------------

// defaultPermissions lists the permissions seeded into every new tenant.
// Each entry maps 1:1 onto the granular route guards in internal/api/routes.go,
// so the auto-created owner role can operate the full tenant-admin API.
var defaultPermissions = []struct{ name, description string }{
	{"users:read", "Read users in the tenant"},
	{"users:write", "Create and update users in the tenant"},
	{"roles:read", "Read roles in the tenant"},
	{"roles:write", "Create and update roles in the tenant"},
	{"permissions:read", "Read permissions in the tenant"},
	{"permissions:write", "Create and update permissions in the tenant"},
	{"apps:read", "Read applications, API keys, agents, and rate limits in the tenant"},
	{"apps:write", "Create and update applications, API keys, agents, and rate limits in the tenant"},
	{"audit:read", "Read the tenant audit log"},
	{"stats:read", "Read tenant monitoring statistics"},
	{"saml:manage", "Configure SAML SSO for the tenant"},
}

// CreateTenant creates a new tenant inside a single transaction that also seeds:
//   - the default granular permissions (see defaultPermissions)
//   - an "owner" system role holding all of them
//   - an owner user (email: in.OwnerEmail) with NO credentials row
//   - the matching tenant_admins row, and the tenant's primary_admin_id
//
// The owner has no password until they accept the invitation sent immediately
// after commit; auth.InvitationService.Accept sets it, marks the address
// verified, and activates the account in one transaction.
//
// The same email may be used as OwnerEmail across multiple CreateTenant calls —
// each call creates an independent users row scoped to its own tenant, so one
// person can own multiple tenants without any shared credentials between them.
// IMPORTANT: if that owner later chooses the same password on two or more of
// their tenants, Login cannot tell which tenant they mean and rejects the
// attempt entirely. That hazard now lives at invitation-accept time rather than
// at hand-off time, but it has not gone away — advise owners who manage
// multiple tenants to keep a distinct password per tenant.
func (s *Service) CreateTenant(ctx context.Context, in CreateTenantInput) (*CreateTenantResult, error) {
	ownerAddr, err := mail.ParseAddress(in.OwnerEmail)
	if err != nil {
		return nil, fmt.Errorf("owner_email is required and must be a valid email address")
	}
	// mail.ParseAddress accepts RFC 5322 mailbox strings with a display name
	// (e.g. "Jane Doe <jane@example.com>"). Store only the bare address —
	// otherwise the literal input string ends up in users.email and the owner
	// can never log in with the address they were actually given, since Login
	// matches on an exact string. Normalize for the same reason: an owner
	// invited as Jane.Doe@example.com must be able to sign in as
	// jane.doe@example.com.
	ownerEmailAddr := emailaddr.Normalize(ownerAddr.Address)

	// Refused up front, before a single row is written.
	//
	// The invitation is the owner's ONLY route to a password — no credentials row
	// is created here by design. Creating the tenant anyway and reporting
	// invite_sent=false hands back a 201 for a tenant whose owner can never sign
	// in and which no endpoint can repair, because every route that could is
	// guarded by an administrator who does not yet exist. A configuration fault
	// the operator can fix in a minute is a far better outcome than a tenant that
	// has to be deleted.
	if s.invSvc == nil {
		s.logger.Error().Str("owner_email", ownerEmailAddr).
			Msg("admin: refusing to create a tenant — no invitation service is wired, so the owner could never sign in")
		return nil, ErrInvitationsUnavailable
	}

	secret, err := generateSecret()
	if err != nil {
		return nil, fmt.Errorf("generate jwt secret: %w", err)
	}

	plan := in.Plan
	if plan == "" {
		plan = "free"
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin create tenant tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Step 1: insert tenant row.
	var tenantID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, display_name, domain, region, description, plan, is_active)
		VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), $8, true)
		RETURNING id
	`, in.Name, in.Slug, secret,
		in.DisplayName, in.Domain, in.Region, in.Description, plan,
	).Scan(&tenantID)
	if err != nil {
		if isDuplicateErr(err) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("create tenant: %w", err)
	}

	// Step 2: seed default permissions.
	permIDs := make([]int64, len(defaultPermissions))
	for i, p := range defaultPermissions {
		err = tx.QueryRow(ctx, `
			INSERT INTO permissions (tenant_id, name, description)
			VALUES ($1, $2, $3)
			RETURNING id
		`, tenantID, p.name, p.description).Scan(&permIDs[i])
		if err != nil {
			return nil, fmt.Errorf("seed permission %s: %w", p.name, err)
		}
	}

	// Step 3: create owner role (is_system = true so it cannot be deleted).
	var roleID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO roles (tenant_id, name, is_system, created_at)
		VALUES ($1, 'owner', true, NOW())
		RETURNING id
	`, tenantID).Scan(&roleID)
	if err != nil {
		return nil, fmt.Errorf("create owner role: %w", err)
	}

	// Step 4: assign all permissions to the owner role.
	for _, permID := range permIDs {
		_, err = tx.Exec(ctx, `
			INSERT INTO role_permissions (role_id, permission_id, tenant_id)
			VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING
		`, roleID, permID, tenantID)
		if err != nil {
			return nil, fmt.Errorf("assign permission to owner role: %w", err)
		}
	}

	// Step 5: create owner user.
	//
	// role_id is left NULL: like every other administrative grant, the owner's
	// takes effect when they accept the invitation, and the role is what carries
	// its permissions. auth.activatePendingAdminGrant attaches roleID then.
	ownerEmail := ownerEmailAddr
	var userID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO users (tenant_id, email, first_name, last_name, is_active)
		VALUES ($1, $2, 'Owner', $3, true)
		RETURNING id
	`, tenantID, ownerEmail, in.Slug).Scan(&userID)
	if err != nil {
		return nil, fmt.Errorf("create owner user: %w", err)
	}

	// Step 6: record the owner as a tenant administrator. This is the row that
	// answers "who administers this tenant?" — deliberately not inferred from
	// users.role_id, so that an application end user can never be mistaken for
	// an administrator by a query that forgets a scope predicate.
	//
	// No user_credentials row is written: the account has no password until the
	// invitation is accepted.
	var adminID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO tenant_admins (tenant_id, user_id, admin_role)
		VALUES ($1, $2, $3)
		RETURNING id
	`, tenantID, userID, auth.AdminRoleOwner).Scan(&adminID)
	if err != nil {
		return nil, fmt.Errorf("create tenant admin: %w", err)
	}

	if _, err = tx.Exec(ctx,
		`UPDATE tenants SET primary_admin_id = $1 WHERE id = $2`, adminID, tenantID,
	); err != nil {
		return nil, fmt.Errorf("set primary admin: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit create tenant tx: %w", err)
	}

	s.logger.Info().
		Str("slug", in.Slug).
		Str("tenant_id", strconv.FormatInt(tenantID, 10)).
		Str("owner_email", ownerEmail).
		Msg("admin: tenant created with owner")

	// Mint the tenant's asymmetric signing key pair (issue #95) so its JWKS
	// endpoint is live and its first token is RS256-signed.
	//
	// Deliberately AFTER the commit and deliberately non-fatal. RSA generation
	// takes ~100ms and cannot join the transaction (it goes through the key
	// service's own pool), and failing tenant creation over it would be the wrong
	// trade: JWTService.EnsureTenantKey generates on demand, so the worst case is
	// that the tenant's first login pays the 100ms instead. Logged at error level
	// because it should not happen and it silently shifts cost to the login path.
	if s.signingKeys != nil {
		if _, keyErr := s.signingKeys.EnsureTenantKey(ctx, tenantID); keyErr != nil {
			s.logger.Error().Err(keyErr).
				Str("tenant_id", strconv.FormatInt(tenantID, 10)).
				Msg("admin: tenant created but signing key generation failed — will be generated lazily on first token")
		}
	}

	tenant, err := s.getTenantByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	owner := OwnerResult{
		ID:     strconv.FormatInt(userID, 10),
		Email:  ownerEmail,
		Role:   "owner",
		Status: OwnerStatusPendingInvitation,
	}

	// The invitation is sent after commit, deliberately outside the
	// transaction: holding a tenant-creation transaction open across an SMTP
	// round-trip would let a slow mail server stall it, and rolling the tenant
	// back because mail failed would be worse than reporting the failure. The
	// caller gets 201 with invite_sent=false and can resend.
	// s.invSvc is non-nil: checked before any row was written.
	if err := s.invSvc.InviteRequired(ctx, tenantID, nil, userID, ownerEmail, "", nil); err != nil {
		owner.InviteError = err.Error()
		s.logger.Error().Err(err).
			Str("owner_email", ownerEmail).
			Int64("tenant_id", tenantID).
			Msg("admin: tenant created but owner invitation was not delivered")
		return &CreateTenantResult{Tenant: *tenant, Owner: owner}, nil
	}
	owner.InviteSent = true

	return &CreateTenantResult{Tenant: *tenant, Owner: owner}, nil
}

// ListTenantsPaginated returns a filtered, paginated list of tenants.
func (s *Service) ListTenantsPaginated(ctx context.Context, f TenantFilter) (*TenantsPage, error) {
	if f.Page < 1 {
		f.Page = 1
	}
	if f.Limit < 1 {
		f.Limit = 25
	}
	if f.Limit > 100 {
		f.Limit = 100
	}

	// Build the search pattern. When f.Search is empty the pattern is "%%",
	// which matches the literal sentinel used in the SQL guard below.
	searchPattern := "%" + f.Search + "%"

	var total int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM tenants
		WHERE ($1 = '%%' OR name ILIKE $1 OR display_name ILIKE $1 OR domain ILIKE $1)
		  AND ($2 = ''  OR is_active = ($2 = 'active'))
		  AND ($3 = ''  OR region = $3)
	`, searchPattern, f.Status, f.Region).Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("count tenants: %w", err)
	}

	offset := (f.Page - 1) * f.Limit
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, slug, display_name, domain, region, description, plan,
		       is_active, cors_origins, created_at, updated_at
		FROM tenants
		WHERE ($1 = '%%' OR name ILIKE $1 OR display_name ILIKE $1 OR domain ILIKE $1)
		  AND ($2 = ''  OR is_active = ($2 = 'active'))
		  AND ($3 = ''  OR region = $3)
		ORDER BY created_at DESC
		LIMIT $4 OFFSET $5
	`, searchPattern, f.Status, f.Region, f.Limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	defer rows.Close()

	var tenants []TenantResult
	for rows.Next() {
		t, scanErr := scanTenantRow(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan tenant: %w", scanErr)
		}
		tenants = append(tenants, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if tenants == nil {
		tenants = []TenantResult{}
	}

	totalPages := (total + f.Limit - 1) / f.Limit
	if totalPages == 0 {
		totalPages = 1
	}
	return &TenantsPage{
		Data:       tenants,
		Total:      total,
		Page:       f.Page,
		TotalPages: totalPages,
		PerPage:    f.Limit,
	}, nil
}

// GetTenantByID returns a single tenant by its ID.
func (s *Service) GetTenantByID(ctx context.Context, tenantID int64) (*TenantResult, error) {
	t, err := s.getTenantByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// UpdateTenant replaces the editable fields on a tenant.
func (s *Service) UpdateTenant(ctx context.Context, tenantID int64, in UpdateTenantInput) (*TenantResult, error) {
	ct, err := s.pool.Exec(ctx, `
		UPDATE tenants
		SET name         = $1,
		    display_name = NULLIF($2, ''),
		    domain       = NULLIF($3, ''),
		    region       = NULLIF($4, ''),
		    description  = NULLIF($5, ''),
		    plan         = $6,
		    updated_at   = NOW()
		WHERE id = $7
	`, in.Name, in.DisplayName, in.Domain, in.Region, in.Description, in.Plan, tenantID)
	if err != nil {
		return nil, fmt.Errorf("update tenant: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.getTenantByID(ctx, tenantID)
}

// ActivateTenant sets is_active = true for a tenant that was previously deactivated.
func (s *Service) ActivateTenant(ctx context.Context, tenantID int64) (*TenantResult, error) {
	var isActive bool
	err := s.pool.QueryRow(ctx, `
		SELECT is_active FROM tenants WHERE id = $1
	`, tenantID).Scan(&isActive)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("activate tenant: lookup: %w", err)
	}
	if isActive {
		return nil, ErrAlreadyActive
	}

	_, err = s.pool.Exec(ctx, `
		UPDATE tenants SET is_active = true, updated_at = NOW() WHERE id = $1
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("activate tenant: update: %w", err)
	}

	s.logger.Info().Str("tenant_id", strconv.FormatInt(tenantID, 10)).Msg("admin: tenant activated")
	return s.getTenantByID(ctx, tenantID)
}

// CheckSlugAvailable reports whether a slug is not yet taken.
func (s *Service) CheckSlugAvailable(ctx context.Context, slug string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM tenants WHERE slug = $1)
	`, slug).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check slug: %w", err)
	}
	return !exists, nil
}

// GetTenantDashboardStats returns system-wide aggregate counts with month-over-month deltas.
func (s *Service) GetTenantDashboardStats(ctx context.Context) (*TenantDashboardStats, error) {
	// Single query: current totals + count of entities created this calendar month
	// vs the prior calendar month — used to compute MoM growth %.
	var (
		totalTenants     int
		activeTenants    int
		tenantsThisMonth int
		tenantsLastMonth int
		totalApps        int
		appsThisMonth    int
		appsLastMonth    int
		totalUsers       int
		usersThisMonth   int
		usersLastMonth   int
	)

	err := s.pool.QueryRow(ctx, `
		SELECT
		    (SELECT COUNT(*)                                                                    FROM tenants)                                     AS total_tenants,
		    (SELECT COUNT(*) FILTER (WHERE is_active = true)                                   FROM tenants)                                     AS active_tenants,
		    (SELECT COUNT(*) FILTER (WHERE DATE_TRUNC('month', created_at) = DATE_TRUNC('month', NOW()))             FROM tenants)               AS tenants_this_month,
		    (SELECT COUNT(*) FILTER (WHERE DATE_TRUNC('month', created_at) = DATE_TRUNC('month', NOW() - INTERVAL '1 month')) FROM tenants)      AS tenants_last_month,
		    (SELECT COUNT(*)                                                                    FROM oauth_clients WHERE deleted_at IS NULL)      AS total_apps,
		    (SELECT COUNT(*) FILTER (WHERE DATE_TRUNC('month', created_at) = DATE_TRUNC('month', NOW()))             FROM oauth_clients WHERE deleted_at IS NULL) AS apps_this_month,
		    (SELECT COUNT(*) FILTER (WHERE DATE_TRUNC('month', created_at) = DATE_TRUNC('month', NOW() - INTERVAL '1 month')) FROM oauth_clients WHERE deleted_at IS NULL) AS apps_last_month,
		    (SELECT COUNT(*)                                                                    FROM users WHERE deleted_at IS NULL)              AS total_users,
		    (SELECT COUNT(*) FILTER (WHERE DATE_TRUNC('month', created_at) = DATE_TRUNC('month', NOW()))             FROM users WHERE deleted_at IS NULL) AS users_this_month,
		    (SELECT COUNT(*) FILTER (WHERE DATE_TRUNC('month', created_at) = DATE_TRUNC('month', NOW() - INTERVAL '1 month')) FROM users WHERE deleted_at IS NULL) AS users_last_month
	`).Scan(
		&totalTenants, &activeTenants, &tenantsThisMonth, &tenantsLastMonth,
		&totalApps, &appsThisMonth, &appsLastMonth,
		&totalUsers, &usersThisMonth, &usersLastMonth,
	)
	if err != nil {
		return nil, fmt.Errorf("tenant dashboard stats: %w", err)
	}

	// active-tenants delta: compare active now vs active last month.
	// There is no historical snapshot of is_active, so this is an ESTIMATE:
	// active last month ≈ active now, minus tenants created this month (not
	// present last month), plus tenants created last month (assumed still
	// active, since new tenants default to active). It does not account for
	// tenants deactivated or reactivated within the window, so it can drift
	// from the true prior count in either direction; clamp to a sane range
	// so a skewed estimate can't produce a negative baseline for momPct.
	activePrior := activeTenants - tenantsThisMonth + tenantsLastMonth
	if activePrior < 0 {
		activePrior = 0
	}

	return &TenantDashboardStats{
		TotalTenants:      totalTenants,
		ActiveTenants:     activeTenants,
		TotalApplications: totalApps,
		TotalUsers:        totalUsers,
		Delta: TenantDashboardDelta{
			TotalTenantsPct:      momPct(tenantsThisMonth, tenantsLastMonth),
			ActiveTenantsPct:     momPct(activeTenants, activePrior),
			TotalApplicationsPct: momPct(appsThisMonth, appsLastMonth),
			TotalUsersPct:        momPct(usersThisMonth, usersLastMonth),
		},
	}, nil
}

// momPct returns the month-over-month percentage change.
// Returns 0 when there is no prior-month baseline to avoid division by zero.
func momPct(current, prior int) float64 {
	if prior == 0 {
		if current > 0 {
			return 100.0
		}
		return 0.0
	}
	return float64(current-prior) / float64(prior) * 100.0
}

// DeactivateTenant soft-deactivates a tenant (sets is_active = false).
func (s *Service) DeactivateTenant(ctx context.Context, tenantID int64) error {
	ct, err := s.pool.Exec(ctx, `
		UPDATE tenants SET is_active = false, updated_at = NOW()
		WHERE id = $1
	`, tenantID)
	if err != nil {
		return fmt.Errorf("deactivate tenant: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	s.logger.Info().Str("tenant_id", strconv.FormatInt(tenantID, 10)).Msg("admin: tenant deactivated")
	return nil
}

// UpdateTenantCORSOrigins replaces the allowed CORS origins for a tenant.
func (s *Service) UpdateTenantCORSOrigins(ctx context.Context, tenantID int64, origins []string) error {
	if origins == nil {
		origins = []string{}
	}
	ct, err := s.pool.Exec(ctx, `
		UPDATE tenants SET cors_origins = $2, updated_at = NOW()
		WHERE id = $1
	`, tenantID, origins)
	if err != nil {
		return fmt.Errorf("update cors_origins: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------------
// Permission management (tenant-scoped)
// ---------------------------------------------------------------------------

// CreatePermission adds a new permission. applicationID nil creates a
// tenant-level management permission; set, an end-user permission scoped to
// (and isolated within) that application.
func (s *Service) CreatePermission(ctx context.Context, tenantID int64, applicationID *int64, name, description string) (*PermissionResult, error) {
	var p PermissionResult
	var id, tid int64
	var appID *int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO permissions (tenant_id, application_id, name, description)
		VALUES ($1, $2, $3, $4)
		RETURNING id, tenant_id, application_id, name, description, created_at
	`, tenantID, applicationID, name, description).Scan(&id, &tid, &appID, &p.Name, &p.Description, &p.CreatedAt)
	if err != nil {
		if isDuplicateErr(err) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("create permission: %w", err)
	}
	p.ID = strconv.FormatInt(id, 10)
	p.TenantID = strconv.FormatInt(tid, 10)
	if appID != nil {
		s := strconv.FormatInt(*appID, 10)
		p.ApplicationID = &s
	}
	return &p, nil
}

// ListPermissions returns permissions for the tenant. applicationID nil lists
// every permission in the tenant (management catalog plus every application's,
// matching pre-existing behavior); non-nil scopes to that application only.
func (s *Service) ListPermissions(ctx context.Context, tenantID int64, applicationID *int64) ([]PermissionResult, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, application_id, name, description, created_at
		FROM permissions
		WHERE tenant_id = $1
		  AND ($2::BIGINT IS NULL OR application_id = $2)
		ORDER BY name
	`, tenantID, applicationID)
	if err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}
	defer rows.Close()

	var perms []PermissionResult
	for rows.Next() {
		var p PermissionResult
		var id, tid int64
		var appID *int64
		if err := rows.Scan(&id, &tid, &appID, &p.Name, &p.Description, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		p.ID = strconv.FormatInt(id, 10)
		p.TenantID = strconv.FormatInt(tid, 10)
		if appID != nil {
			s := strconv.FormatInt(*appID, 10)
			p.ApplicationID = &s
		}
		perms = append(perms, p)
	}
	if perms == nil {
		perms = []PermissionResult{}
	}
	return perms, rows.Err()
}

// UpdatePermission renames a permission and/or replaces its description.
// An empty name keeps the current one. applicationID nil applies no scope
// filter (tenant-admin routes may edit any of the tenant's permissions);
// non-nil requires the permission to belong to that application.
func (s *Service) UpdatePermission(ctx context.Context, tenantID int64, applicationID *int64, permissionID int64, name, description string) (*PermissionResult, error) {
	var p PermissionResult
	var id, tid int64
	var appID *int64
	err := s.pool.QueryRow(ctx, `
		UPDATE permissions
		SET name = COALESCE(NULLIF($1, ''), name), description = $2, updated_at = NOW()
		WHERE id = $3 AND tenant_id = $4
		  AND ($5::BIGINT IS NULL OR application_id = $5)
		RETURNING id, tenant_id, application_id, name, description, created_at
	`, name, description, permissionID, tenantID, applicationID).Scan(&id, &tid, &appID, &p.Name, &p.Description, &p.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		if isDuplicateErr(err) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("update permission: %w", err)
	}
	p.ID = strconv.FormatInt(id, 10)
	p.TenantID = strconv.FormatInt(tid, 10)
	if appID != nil {
		s := strconv.FormatInt(*appID, 10)
		p.ApplicationID = &s
	}
	return &p, nil
}

// DeletePermission removes a permission from the tenant. applicationID nil
// applies no scope filter; non-nil requires the permission to belong to that
// application. Cascades to role_permissions and user_permissions (FK ON
// DELETE CASCADE).
func (s *Service) DeletePermission(ctx context.Context, tenantID int64, applicationID *int64, permissionID int64) error {
	ct, err := s.pool.Exec(ctx, `
		DELETE FROM permissions
		WHERE id = $1 AND tenant_id = $2
		  AND ($3::BIGINT IS NULL OR application_id = $3)
	`, permissionID, tenantID, applicationID)
	if err != nil {
		return fmt.Errorf("delete permission: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------------
// Role management (tenant-scoped)
// ---------------------------------------------------------------------------

// CreateRole creates a role and optionally assigns permissions to it.
// applicationID is nil for a tenant-level role; set to scope the role as an
// end-user role belonging to one of the tenant's applications.
func (s *Service) CreateRole(ctx context.Context, tenantID int64, applicationID *int64, name string, permissionIDs []int64) (*RoleResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin create role tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var roleID int64
	var createdAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO roles (tenant_id, application_id, name, is_system, created_at)
		VALUES ($1, $2, $3, false, NOW())
		RETURNING id, created_at
	`, tenantID, applicationID, name).Scan(&roleID, &createdAt)
	if err != nil {
		if isDuplicateErr(err) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("insert role: %w", err)
	}

	// Isolation: a role may only hold permissions from its own scope — the
	// same application for app roles, tenant-level for tenant-level roles.
	// IS NOT DISTINCT FROM treats two NULLs as equal, unlike plain =.
	for _, permID := range dedupeInt64s(permissionIDs) {
		ct, err := tx.Exec(ctx, `
			INSERT INTO role_permissions (role_id, permission_id, tenant_id)
			SELECT $1, id, tenant_id FROM permissions
			WHERE id = $2 AND tenant_id = $3
			  AND application_id IS NOT DISTINCT FROM $4::BIGINT
			ON CONFLICT DO NOTHING
		`, roleID, permID, tenantID, applicationID)
		if err != nil {
			return nil, fmt.Errorf("assign permission to role: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return nil, fmt.Errorf("permission %d: %w", permID, ErrPermissionScope)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit create role: %w", err)
	}

	return s.getRoleByID(ctx, tenantID, roleID)
}

// int64PtrEqual reports whether two optional ids are the same scope: both
// nil (tenant-level) or both set to the same value.
func int64PtrEqual(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// dedupeInt64s returns ids with duplicates removed, preserving order — a
// duplicated id would make the ON CONFLICT DO NOTHING attach report zero rows
// and be misread as a scope violation.
func dedupeInt64s(ids []int64) []int64 {
	seen := make(map[int64]struct{}, len(ids))
	out := ids[:0:0]
	for _, id := range ids {
		if _, dup := seen[id]; !dup {
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}

// ListRoles returns roles for the tenant, each with their assigned permissions.
// applicationID nil lists every role in the tenant (tenant-management roles
// plus every application's end-user roles, matching pre-existing behavior);
// a non-nil value scopes the list to that application's end-user roles only.
func (s *Service) ListRoles(ctx context.Context, tenantID int64, applicationID *int64) ([]RoleResult, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, application_id, name, is_system, is_default, created_at
		FROM roles
		WHERE tenant_id = $1
		  AND ($2::BIGINT IS NULL OR application_id = $2)
		ORDER BY name
	`, tenantID, applicationID)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	defer rows.Close()

	var roles []RoleResult
	for rows.Next() {
		var r RoleResult
		var id, tid int64
		var appID *int64
		if err := rows.Scan(&id, &tid, &appID, &r.Name, &r.IsSystem, &r.IsDefault, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		r.ID = strconv.FormatInt(id, 10)
		r.TenantID = strconv.FormatInt(tid, 10)
		if appID != nil {
			s := strconv.FormatInt(*appID, 10)
			r.ApplicationID = &s
		}
		r.Permissions = []PermissionResult{}
		roles = append(roles, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if roles == nil {
		return []RoleResult{}, nil
	}

	for i := range roles {
		roleIDInt, _ := strconv.ParseInt(roles[i].ID, 10, 64)
		perms, err := s.loadRolePermissions(ctx, roleIDInt)
		if err != nil {
			return nil, err
		}
		roles[i].Permissions = perms
	}

	return roles, nil
}

// UpdateRolePermissions replaces the permission set on a role. Every
// permission must belong to the role's own scope (its application, or
// tenant-level for tenant-level roles) — see ErrPermissionScope.
func (s *Service) UpdateRolePermissions(ctx context.Context, tenantID, roleID int64, permissionIDs []int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin update role perms tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var roleAppID *int64
	err = tx.QueryRow(ctx, `SELECT application_id FROM roles WHERE id = $1 AND tenant_id = $2`, roleID, tenantID).Scan(&roleAppID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("update role perms: lookup role: %w", err)
	}

	_, err = tx.Exec(ctx, `DELETE FROM role_permissions WHERE role_id = $1`, roleID)
	if err != nil {
		return fmt.Errorf("clear role permissions: %w", err)
	}

	for _, permID := range dedupeInt64s(permissionIDs) {
		ct, err := tx.Exec(ctx, `
			INSERT INTO role_permissions (role_id, permission_id, tenant_id)
			SELECT $1, id, tenant_id FROM permissions
			WHERE id = $2 AND tenant_id = $3
			  AND application_id IS NOT DISTINCT FROM $4::BIGINT
			ON CONFLICT DO NOTHING
		`, roleID, permID, tenantID, roleAppID)
		if err != nil {
			return fmt.Errorf("assign permission: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return fmt.Errorf("permission %d: %w", permID, ErrPermissionScope)
		}
	}

	return tx.Commit(ctx)
}

// UpdateRoleName renames an end-user application role. System roles
// (owner/super_admin) and roles outside the given application are rejected.
func (s *Service) UpdateRoleName(ctx context.Context, tenantID, applicationID, roleID int64, name string) (*RoleResult, error) {
	ct, err := s.pool.Exec(ctx, `
		UPDATE roles SET name = $1, updated_at = NOW()
		WHERE id = $2 AND tenant_id = $3 AND application_id = $4 AND is_system = false
	`, name, roleID, tenantID, applicationID)
	if err != nil {
		if isDuplicateErr(err) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("rename role: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.getRoleByID(ctx, tenantID, roleID)
}

// DeleteRole removes a role from the tenant.
func (s *Service) DeleteRole(ctx context.Context, tenantID, roleID int64) error {
	ct, err := s.pool.Exec(ctx, `
		DELETE FROM roles WHERE id = $1 AND tenant_id = $2 AND is_system = false
	`, roleID, tenantID)
	if err != nil {
		return fmt.Errorf("delete role: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetDefaultRole marks roleID as the default role for applicationID, clearing
// any previously-default role for that application in one transaction. Only
// application-scoped, non-system roles are eligible — tenant-management roles
// (super_admin/owner) must never be handed to an end user via /register.
func (s *Service) SetDefaultRole(ctx context.Context, tenantID, applicationID, roleID int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin set default role tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var isSystem bool
	var appID *int64
	err = tx.QueryRow(ctx, `
		SELECT is_system, application_id FROM roles WHERE id = $1 AND tenant_id = $2
	`, roleID, tenantID).Scan(&isSystem, &appID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("set default role: lookup: %w", err)
	}
	if isSystem || appID == nil || *appID != applicationID {
		return ErrSystemRole
	}

	_, err = tx.Exec(ctx, `
		UPDATE roles SET is_default = false
		WHERE tenant_id = $1 AND application_id = $2 AND is_default = true
	`, tenantID, applicationID)
	if err != nil {
		return fmt.Errorf("clear previous default role: %w", err)
	}

	_, err = tx.Exec(ctx, `
		UPDATE roles SET is_default = true
		WHERE id = $1 AND tenant_id = $2 AND application_id = $3
	`, roleID, tenantID, applicationID)
	if err != nil {
		return fmt.Errorf("set default role: %w", err)
	}

	return tx.Commit(ctx)
}

// ---------------------------------------------------------------------------
// User pool management (tenant-scoped)
// ---------------------------------------------------------------------------

// ListUsers returns a paginated, searchable list of users in the tenant.
// ListUsers returns a paginated, searchable user list. applicationID nil
// lists every user in the tenant (admins plus every application's end users,
// matching pre-existing behavior); non-nil isolates the list to that
// application's own user base.
func (s *Service) ListUsers(ctx context.Context, tenantID int64, applicationID *int64, search string, page, limit int) (*UsersPage, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	offset := (page - 1) * limit

	searchPattern := "%" + search + "%"

	var total int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM users
		WHERE tenant_id = $1
		  AND deleted_at IS NULL
		  AND ($2::BIGINT IS NULL OR application_id = $2)
		  AND ($3 = '%%' OR email ILIKE $3 OR first_name ILIKE $3 OR last_name ILIKE $3)
	`, tenantID, applicationID, searchPattern).Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("count users: %w", err)
	}

	// The enrichment subqueries (last login, login count, connections) run per
	// returned row (≤100), each index-backed: refresh_tokens (user_id,
	// tenant_id), audit_logs (tenant_id, user_id), user_identities (user_id),
	// user_credentials (user_id PK).
	rows, err := s.pool.Query(ctx, `
		SELECT u.id, u.tenant_id, u.application_id, u.email, u.first_name, u.last_name,
		       COALESCE(r.name, '') as role_name, u.role_id, u.is_active, u.created_at,
		       `+userEnrichmentColumns+`
		FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.tenant_id = $1
		  AND u.deleted_at IS NULL
		  AND ($2::BIGINT IS NULL OR u.application_id = $2)
		  AND ($3 = '%%' OR u.email ILIKE $3 OR u.first_name ILIKE $3 OR u.last_name ILIKE $3)
		ORDER BY u.created_at DESC
		LIMIT $4 OFFSET $5
	`, tenantID, applicationID, searchPattern, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []UserResult
	for rows.Next() {
		var u UserResult
		var id, tid int64
		var appID, roleID *int64
		var hasPassword bool
		var providers []string
		if err := rows.Scan(&id, &tid, &appID, &u.Email, &u.FirstName, &u.LastName,
			&u.Role, &roleID, &u.IsActive, &u.CreatedAt,
			&u.LastLoginAt, &u.LoginsCount, &hasPassword, &providers); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		u.ID = strconv.FormatInt(id, 10)
		u.TenantID = strconv.FormatInt(tid, 10)
		if appID != nil {
			as := strconv.FormatInt(*appID, 10)
			u.ApplicationID = &as
		}
		if roleID != nil {
			rs := strconv.FormatInt(*roleID, 10)
			u.RoleID = &rs
		}
		u.Connections = buildConnections(hasPassword, providers)
		users = append(users, u)
	}
	if users == nil {
		users = []UserResult{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	totalPages := (total + limit - 1) / limit
	if totalPages == 0 {
		totalPages = 1
	}
	return &UsersPage{
		Users:      users,
		Total:      total,
		Page:       page,
		TotalPages: totalPages,
	}, nil
}

// CreateUser creates a new user with a hashed password. applicationID nil
// creates a tenant-level user; set, an end user belonging to that
// application's isolated user base. An optional role must belong to the same
// scope as the user (ErrRoleScope otherwise) and must not be a system role
// (ErrSystemRole) — see AssignUserRole for why, which applies identically here:
// creating the account and granting it an administrative role in one call is the
// same bypass, minus a step.
func (s *Service) CreateUser(ctx context.Context, tenantID int64, applicationID *int64, email, password, firstName, lastName string, roleID *int64) (*UserResult, error) {
	email = emailaddr.Normalize(email)

	if roleID != nil {
		var roleAppID *int64
		var roleIsSystem bool
		err := s.pool.QueryRow(ctx,
			`SELECT application_id, is_system FROM roles WHERE id = $1 AND tenant_id = $2`,
			*roleID, tenantID,
		).Scan(&roleAppID, &roleIsSystem)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, ErrNotFound
			}
			return nil, fmt.Errorf("create user: lookup role: %w", err)
		}
		if roleIsSystem {
			return nil, ErrSystemRole
		}
		if !int64PtrEqual(roleAppID, applicationID) {
			return nil, ErrRoleScope
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), auth.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin create user tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var userID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO users (tenant_id, application_id, email, first_name, last_name, role_id, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, true)
		RETURNING id
	`, tenantID, applicationID, email, firstName, lastName, roleID).Scan(&userID)
	if err != nil {
		if isDuplicateErr(err) {
			return nil, ErrAlreadyExists
		}
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
		return nil, fmt.Errorf("commit create user: %w", err)
	}

	return s.getUserByID(ctx, tenantID, applicationID, userID)
}

// ErrInvitationsUnavailable is returned when an invitation is requested on a
// server that has no invitation service wired.
var ErrInvitationsUnavailable = errors.New("invitations are not configured on this server")

// InviteUser creates a user and emails them an invitation to set their own
// password, instead of the admin choosing one and passing it out of band.
//
// The account is created with a random unusable password: the invitation link is
// the only way to set a real one, so the throwaway value is never known to
// anybody, including the admin who triggered it.
func (s *Service) InviteUser(ctx context.Context, tenantID int64, applicationID *int64, email, firstName, lastName string, roleID *int64, inviterID *int64, inviterName string) (*UserResult, error) {
	if s.invSvc == nil {
		return nil, ErrInvitationsUnavailable
	}
	// Normalized here as well as in CreateUser: the address is also used as the
	// invitation recipient below, and the invite must be addressed to exactly
	// the account that was created.
	email = emailaddr.Normalize(email)

	placeholder, err := generateTempPassword()
	if err != nil {
		return nil, fmt.Errorf("invite user: generate placeholder password: %w", err)
	}
	result, err := s.CreateUser(ctx, tenantID, applicationID, email, placeholder, firstName, lastName, roleID)
	if err != nil {
		return nil, err
	}

	userID, err := strconv.ParseInt(result.ID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invite user: parse created id: %w", err)
	}
	if err := s.invSvc.Invite(ctx, tenantID, applicationID, userID, email, inviterName, inviterID); err != nil {
		// The account exists but the invitation did not go out. Report it so the
		// admin can resend rather than silently returning a claimable-by-nobody
		// account.
		return result, fmt.Errorf("user created but invitation could not be sent: %w", err)
	}
	return result, nil
}

// ResendInvitation issues a fresh invitation for an existing user, superseding
// any outstanding one.
func (s *Service) ResendInvitation(ctx context.Context, tenantID int64, applicationID *int64, userID int64, inviterID *int64, inviterName string) error {
	if s.invSvc == nil {
		return ErrInvitationsUnavailable
	}
	var email string
	var appRowID *int64
	err := s.pool.QueryRow(ctx, `
		SELECT email, application_id FROM users
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		  AND ($3::BIGINT IS NULL OR application_id = $3)
	`, userID, tenantID, applicationID).Scan(&email, &appRowID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("lookup user for invitation: %w", err)
	}
	return s.invSvc.Invite(ctx, tenantID, appRowID, userID, email, inviterName, inviterID)
}

// GetUser fetches a single user by ID. applicationID nil applies no scope
// filter (tenant-admin routes may reach any of the tenant's users); non-nil
// requires the user to belong to that application.
func (s *Service) GetUser(ctx context.Context, tenantID int64, applicationID *int64, userID int64) (*UserResult, error) {
	return s.getUserByID(ctx, tenantID, applicationID, userID)
}

// UpdateUser updates a user's profile fields, with the same optional
// application scope filter as GetUser.
func (s *Service) UpdateUser(ctx context.Context, tenantID int64, applicationID *int64, userID int64, email, firstName, lastName string) (*UserResult, error) {
	email = emailaddr.Normalize(email)

	ct, err := s.pool.Exec(ctx, `
		UPDATE users
		SET email = $1, first_name = $2, last_name = $3, updated_at = NOW()
		WHERE id = $4 AND tenant_id = $5 AND deleted_at IS NULL
		  AND ($6::BIGINT IS NULL OR application_id = $6)
	`, email, firstName, lastName, userID, tenantID, applicationID)
	if err != nil {
		if isDuplicateErr(err) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("update user: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.getUserByID(ctx, tenantID, applicationID, userID)
}

// AssignUserRole sets the role for a user. The role must belong to the same
// scope as the user — an application's users may only hold that application's
// roles, tenant-level users only tenant-level roles (ErrRoleScope otherwise).
//
// System roles are refused outright (ErrSystemRole). They are the administrative
// tiers — a tenant's "owner"/"co_owner" and the platform's "super_admin" — and
// this route is not how anyone acquires one. The supported path is an invitation
// whose acceptance calls auth.activatePendingAdminGrant, which writes role_id
// itself alongside the tenant_admins row that records the grant.
//
// Allowing it here would let an operator hand out administrative permissions
// with no tenant_admins row behind them. Such an account holds every admin
// permission but resolves to an EMPTY admin_scope claim, which
// RequireTenantSelfOrAny reads as tenant-wide; it never accepted an invitation,
// defeating the activation gate in migration 00064; and it appears in neither
// the tenant's administrator list nor the platform directory, both of which read
// tenant_admins. In the platform's own seeded tenant the reachable system role
// is "super_admin", so the same call would confer tenant:manage — authority over
// every tenant.
// applicationID optionally pins the user lookup to one application.
func (s *Service) AssignUserRole(ctx context.Context, tenantID int64, applicationID *int64, userID, roleID int64) error {
	var roleAppID *int64
	var roleIsSystem bool
	err := s.pool.QueryRow(ctx,
		`SELECT application_id, is_system FROM roles WHERE id = $1 AND tenant_id = $2`,
		roleID, tenantID,
	).Scan(&roleAppID, &roleIsSystem)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("assign role: lookup role: %w", err)
	}
	if roleIsSystem {
		return ErrSystemRole
	}

	var userAppID *int64
	err = s.pool.QueryRow(ctx, `
		SELECT application_id FROM users
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		  AND ($3::BIGINT IS NULL OR application_id = $3)
	`, userID, tenantID, applicationID).Scan(&userAppID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("assign role: lookup user: %w", err)
	}

	if !int64PtrEqual(roleAppID, userAppID) {
		return ErrRoleScope
	}

	ct, err := s.pool.Exec(ctx, `
		UPDATE users SET role_id = $1, updated_at = NOW()
		WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL
	`, roleID, userID, tenantID)
	if err != nil {
		return fmt.Errorf("assign role: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteUser soft-deletes a user (sets deleted_at, is_active = false), with
// the same optional application scope filter as GetUser.
func (s *Service) DeleteUser(ctx context.Context, tenantID int64, applicationID *int64, userID int64) error {
	ct, err := s.pool.Exec(ctx, `
		UPDATE users SET deleted_at = NOW(), is_active = false, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		  AND ($3::BIGINT IS NULL OR application_id = $3)
	`, userID, tenantID, applicationID)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ForcePasswordReset dispatches a password reset email to the specified user,
// with the same optional application scope filter as GetUser.
func (s *Service) ForcePasswordReset(ctx context.Context, tenantID int64, applicationID *int64, userID int64) error {
	var email string
	var appRowID *int64
	err := s.pool.QueryRow(ctx, `
		SELECT u.email, u.application_id
		FROM users u
		WHERE u.id = $1 AND u.tenant_id = $2 AND u.is_active = true AND u.deleted_at IS NULL
		  AND ($3::BIGINT IS NULL OR u.application_id = $3)
	`, userID, tenantID, applicationID).Scan(&email, &appRowID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("lookup user for force reset: %w", err)
	}

	s.logger.Info().Str("user_id", strconv.FormatInt(userID, 10)).Int64("tenant_id", tenantID).Msg("admin: force password reset dispatched")
	// Admin force-reset always sends, even if the tenant/app disabled the
	// password-reset template — an operator action must not be silently dropped.
	return s.resetSvc.ForgotPasswordForced(ctx, tenantID, appRowID, email)
}

// GetUserDetail returns the enriched single-user view (profile + MFA status,
// linked identities, active-session count, last login). applicationID carries
// the same optional scope filter as GetUser.
func (s *Service) GetUserDetail(ctx context.Context, tenantID int64, applicationID *int64, userID int64) (*UserDetail, error) {
	base, err := s.getUserByID(ctx, tenantID, applicationID, userID)
	if err != nil {
		return nil, err
	}

	d := &UserDetail{UserResult: *base, Identities: []UserIdentity{}}

	// Profile extras straight off the users row.
	if err := s.pool.QueryRow(ctx, `
		SELECT email_verified, token_version, updated_at,
		       blocked_at, block_reason, failed_login_attempts
		FROM users WHERE id = $1 AND tenant_id = $2
	`, userID, tenantID).Scan(
		&d.EmailVerified, &d.TokenVersion, &d.UpdatedAt,
		&d.BlockedAt, &d.BlockReason, &d.FailedLoginAttempts,
	); err != nil {
		return nil, fmt.Errorf("user detail: profile: %w", err)
	}

	// A live invitation means the account exists but has never been claimed.
	if err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM user_invitations
			WHERE user_id = $1 AND used_at IS NULL AND expires_at > NOW()
		)
	`, userID).Scan(&d.PendingInvitation); err != nil {
		return nil, fmt.Errorf("user detail: invitation: %w", err)
	}

	// MFA status. Both tables are keyed by user_id; absence = not enrolled.
	var backupCodes []string
	if err := s.pool.QueryRow(ctx, `
		SELECT is_active, backup_codes FROM totp_secrets WHERE user_id = $1 AND tenant_id = $2
	`, userID, tenantID).Scan(&d.MFA.TOTPEnabled, &backupCodes); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("user detail: totp: %w", err)
	}
	d.MFA.BackupCodesRemaining = len(backupCodes)
	if err := s.pool.QueryRow(ctx, `
		SELECT is_active FROM email_mfa_settings WHERE user_id = $1 AND tenant_id = $2
	`, userID, tenantID).Scan(&d.MFA.EmailEnabled); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("user detail: email mfa: %w", err)
	}

	// Active-session count. LastLoginAt comes with the base row and deliberately
	// does NOT use this predicate — it must survive the sessions it was derived
	// from being revoked, expired, and eventually reaped (see
	// userEnrichmentColumns).
	// COUNT(*) over one row per session, rather than COUNT(DISTINCT …) over a
	// rotation log.
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM user_sessions
		WHERE user_id = $1 AND tenant_id = $2 AND `+auth.LiveSessionWhere(""),
		userID, tenantID).Scan(&d.ActiveSessions); err != nil {
		return nil, fmt.Errorf("user detail: sessions: %w", err)
	}

	// Linked federated identities. Scoped to the tenant and, when an application
	// filter is in effect, to that application (user_identities is app-owned).
	rows, err := s.pool.Query(ctx, `
		SELECT provider, provider_email, created_at
		FROM user_identities
		WHERE user_id = $1 AND tenant_id = $2
		  AND ($3::BIGINT IS NULL OR application_id = $3)
		ORDER BY created_at
	`, userID, tenantID, applicationID)
	if err != nil {
		return nil, fmt.Errorf("user detail: identities: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id UserIdentity
		if err := rows.Scan(&id.Provider, &id.ProviderEmail, &id.CreatedAt); err != nil {
			return nil, fmt.Errorf("user detail: scan identity: %w", err)
		}
		d.Identities = append(d.Identities, id)
	}
	return d, rows.Err()
}

// SetUserActive blocks (active=false) or unblocks (active=true) a user.
// Blocking bumps token_version and revokes every live refresh token so the
// user is signed out everywhere immediately. Returns the refreshed user row.
func (s *Service) SetUserActive(ctx context.Context, tenantID int64, applicationID *int64, userID int64, active bool) (*UserResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin set-active tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// token_version bump only when blocking — invalidates issued access tokens.
	ct, err := tx.Exec(ctx, `
		UPDATE users
		SET is_active = $1,
		    token_version = CASE WHEN $1 THEN token_version ELSE token_version + 1 END,
		    updated_at = NOW()
		WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL
		  AND ($4::BIGINT IS NULL OR application_id = $4)
	`, active, userID, tenantID, applicationID)
	if err != nil {
		return nil, fmt.Errorf("set user active: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return nil, ErrNotFound
	}

	if !active {
		if _, err := tx.Exec(ctx, `
			UPDATE refresh_tokens SET revoked_at = NOW()
			WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
		`, userID, tenantID); err != nil {
			return nil, fmt.Errorf("revoke tokens on block: %w", err)
		}
	} else {
		// An admin unblock also clears automatic-lockout state: leaving a stale
		// counter at the threshold would re-block the account on the next typo,
		// and leaving blocked_at set would keep an old unblock link usable.
		if _, err := tx.Exec(ctx, `
			UPDATE users
			SET failed_login_attempts = 0, last_failed_login_at = NULL,
			    blocked_at = NULL, block_reason = NULL
			WHERE id = $1 AND tenant_id = $2
		`, userID, tenantID); err != nil {
			return nil, fmt.Errorf("clear lockout state on unblock: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit set-active: %w", err)
	}

	// Blocking has to end the sessions the account already holds, not just stop it
	// renewing them. The refresh revocation above is not enough on its own: an
	// operator who blocks a compromised account and watches it keep making requests
	// for another fifteen minutes has been given a control that does not do what its
	// name says. After the commit so nothing is denied on a rolled-back block.
	if !active && s.authSvc != nil {
		s.authSvc.DenyUserSessions(ctx, userID, tenantID)
	}

	result, err := s.getUserByID(ctx, tenantID, applicationID, userID)
	if err != nil {
		return nil, err
	}

	// Tell the user an operator blocked them. Best-effort and after commit: the
	// block stands whether or not the mail is delivered.
	if !active {
		var appRowID *int64
		if err := s.pool.QueryRow(ctx, `SELECT application_id FROM users WHERE id = $1 AND tenant_id = $2`, userID, tenantID).Scan(&appRowID); err != nil {
			s.logger.Warn().Err(err).Int64("user_id", userID).Msg("admin: could not resolve app scope for block notification")
		} else {
			s.blockSvc.NotifyAdminBlock(ctx, tenantID, appRowID, userID, result.Email)
		}
	}
	return result, nil
}

// MaxSessionsListed bounds one page of session results.
//
// The endpoint used to return every live session in one response. That was
// tolerable only because nothing expired: with a 30-day absolute lifetime, no
// idle clock, and a logout that revoked one token instead of the session, a
// single active dev account accumulated over four hundred live families and the
// response returned all of them. The lifecycle work makes that number small
// again, but an unbounded query over a table with one row per token rotation is
// a latent problem regardless of how tidy the data currently is.
//
// Set above the default concurrent-session cap (20) so a user at the cap still
// sees every session they have, and truncation only happens where the cap itself
// has been raised.
const MaxSessionsListed = 100

// ListUserSessions returns the user's live sessions, one row per session family,
// most-recently-active first.
//
// currentFamilyID marks the caller's own session in the result; pass "" from the
// admin path, where the caller is by definition somebody else.
func (s *Service) ListUserSessions(ctx context.Context, tenantID int64, applicationID *int64, userID int64, currentFamilyID string) ([]UserSession, error) {
	if _, err := s.getUserByID(ctx, tenantID, applicationID, userID); err != nil {
		return nil, err
	}

	// One row per session, straight from user_sessions — no DISTINCT ON over a
	// rotation log. Liveness comes from auth.LiveSessionWhere rather than a
	// hand-written clause so this list and the refresh path can never disagree about
	// which sessions still work; that drift presents to an operator as "I revoked
	// that session and it is still listed as active".
	//
	// ORDER BY is most-recently-active, so the LIMIT keeps the sessions that matter.
	// The previous version ordered by session id because DISTINCT ON required it,
	// which meant the limit silently kept the OLDEST hundred and hid everything
	// recent — the Go-side sort then reordered those, making the output look correct.
	rows, err := s.pool.Query(ctx, `
		SELECT id, host(ip_address), user_agent, device_hint, created_at, last_seen_at,
		       absolute_expires_at, idle_expires_at, absolute_expires_at,
		       is_persistent, auth_time, amr
		FROM user_sessions
		WHERE user_id = $1 AND tenant_id = $2
		  AND `+auth.LiveSessionWhere("")+`
		ORDER BY last_seen_at DESC
		LIMIT $3
	`, userID, tenantID, MaxSessionsListed)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	sessions := []UserSession{}
	for rows.Next() {
		var sess UserSession
		var sessionID int64
		var ip, deviceHint *string
		var lastSeenAt time.Time
		if err := rows.Scan(&sessionID, &ip, &sess.UserAgent, &deviceHint,
			&sess.CreatedAt, &lastSeenAt,
			&sess.ExpiresAt, &sess.IdleExpiresAt, &sess.AbsoluteExpiresAt,
			&sess.IsPersistent, &sess.AuthTime, &sess.AMR); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sess.SessionFamilyID = strconv.FormatInt(sessionID, 10)
		sess.IPAddress = ip
		sess.DeviceHint = deviceHint
		// last_seen_at is NOT NULL on the session row, so the pointer field the API
		// exposes is always populated now — the nullability was an artefact of
		// last_used_at being unset on a token that had never been rotated.
		sess.LastUsedAt = &lastSeenAt
		sess.IsCurrent = currentFamilyID != "" && sess.SessionFamilyID == currentFamilyID
		if sess.AMR == nil {
			sess.AMR = []string{}
		}
		sessions = append(sessions, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// No Go-side sort: the query orders by last_seen_at, which is also what the LIMIT
	// now applies to. Sorting here previously masked the fact that the limit was
	// keeping the wrong rows.
	return sessions, nil
}

// RevokeUserSession revokes a single session family belonging to the user.
// Returns ErrNotFound if no live token in that family belongs to the user.
//
// Unlike RevokeAllUserSessions / SetUserActive, this does NOT bump token_version:
// that counter is global to the user, so bumping it would invalidate the access
// tokens of every OTHER session too — the opposite of a single-session revoke.
//
// The access token IS session-scoped now (the "sid" claim), so revocation takes
// effect immediately rather than waiting out the token's remaining lifetime: the
// session is added to a short-lived denylist that the authenticating middleware
// checks. That denylist is a Redis accelerator, not the guarantee — if it is
// unavailable, revoking the refresh-token family still stops the session being
// renewed and the already-issued access token dies at its 15-minute expiry, which
// is the behaviour this endpoint had before. Use RevokeAllUserSessions when
// immediate account-wide invalidation must not depend on Redis at all.
//
// reason is recorded on the revoked rows so the cause survives in the data, not
// only in the audit trail.
func (s *Service) RevokeUserSession(ctx context.Context, tenantID int64, applicationID *int64, userID, familyID int64, reason string) error {
	if _, err := s.getUserByID(ctx, tenantID, applicationID, userID); err != nil {
		return err
	}
	n, err := s.revokeSession(ctx, userID, tenantID, familyID, reason)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// revokeSession routes session revocation through the auth service when it is
// wired, and falls back to a direct write when it is not.
//
// The fallback exists for tests that construct a bare Service. It is deliberately
// identical in its database effect and different only in that it cannot populate
// the revoked-session denylist — so a deployment that forgets WithAuthService
// degrades to the pre-denylist behaviour (revocation effective within 15 minutes)
// rather than failing, but says so in the log, because silently losing immediate
// revocation is exactly the kind of regression nobody notices until an incident.
func (s *Service) revokeSession(ctx context.Context, userID, tenantID, sessionID int64, reason string) (int64, error) {
	if s.authSvc != nil {
		return s.authSvc.RevokeSession(ctx, userID, tenantID, sessionID, reason)
	}
	s.logger.Warn().Msg("admin: auth service not wired; session revoke will not deny outstanding access tokens")
	ct, err := s.pool.Exec(ctx, `
		UPDATE user_sessions
		SET revoked_at = NOW(), revoked_reason = $4, updated_at = NOW()
		WHERE id = $1 AND user_id = $2 AND tenant_id = $3 AND revoked_at IS NULL
	`, sessionID, userID, tenantID, reason)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

// RevokeAllUserSessions revokes every live refresh token for the user, signing
// them out everywhere. Returns the number of tokens revoked.
//
// The account-wide denylist entry written after the commit is what actually ends
// the sessions. Without it this method reported success while the user stayed
// signed in for up to another fifteen minutes: it revoked the refresh tokens
// (which only stops RENEWAL) and bumped users.token_version — a counter that,
// despite its name and every comment that referred to it, is verified nowhere in
// this codebase and has never affected token validity.
//
// Written after the commit rather than inside the transaction, and deliberately:
// a Redis entry cannot be rolled back, so denying sessions the transaction then
// failed to revoke would sign a user out on the strength of a write that never
// landed. This ordering leaves a sub-millisecond window in which the rows are
// revoked and the tokens still pass, which the next request closes.
func (s *Service) RevokeAllUserSessions(ctx context.Context, tenantID int64, applicationID *int64, userID int64) (int64, error) {
	if _, err := s.getUserByID(ctx, tenantID, applicationID, userID); err != nil {
		return 0, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin revoke-all tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Counted before the revoke: the return value is "how many sessions did this
	// end", and after the UPDATE there are none left to count.
	var revoked int64
	if err := tx.QueryRow(ctx, `
		SELECT COUNT(*) FROM user_sessions
		WHERE user_id = $1 AND tenant_id = $2 AND `+auth.LiveSessionWhere(""),
		userID, tenantID).Scan(&revoked); err != nil {
		return 0, fmt.Errorf("count sessions to revoke: %w", err)
	}

	err = auth.RevokeAllSessionsTx(ctx, tx, userID, tenantID, auth.RevokeReasonAdminAll)
	if err != nil {
		return 0, fmt.Errorf("revoke all sessions: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users SET token_version = token_version + 1, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2
	`, userID, tenantID); err != nil {
		return 0, fmt.Errorf("bump token version: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit revoke-all: %w", err)
	}

	if s.authSvc != nil {
		s.authSvc.DenyUserSessions(ctx, userID, tenantID)
	} else {
		s.logger.Warn().Int64("user_id", userID).
			Msg("admin: auth service not wired; revoke-all will not sign the user out until their access token expires")
	}

	// The metric is emitted by RevokeAllSessionsTx, so it is not repeated here.
	return revoked, nil
}

// GetUserMFA returns just the user's MFA enrollment status.
func (s *Service) GetUserMFA(ctx context.Context, tenantID int64, applicationID *int64, userID int64) (*UserMFAStatus, error) {
	if _, err := s.getUserByID(ctx, tenantID, applicationID, userID); err != nil {
		return nil, err
	}
	var status UserMFAStatus
	var backupCodes []string
	if err := s.pool.QueryRow(ctx, `
		SELECT is_active, backup_codes FROM totp_secrets WHERE user_id = $1 AND tenant_id = $2
	`, userID, tenantID).Scan(&status.TOTPEnabled, &backupCodes); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get user mfa: totp: %w", err)
	}
	status.BackupCodesRemaining = len(backupCodes)
	if err := s.pool.QueryRow(ctx, `
		SELECT is_active FROM email_mfa_settings WHERE user_id = $1 AND tenant_id = $2
	`, userID, tenantID).Scan(&status.EmailEnabled); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get user mfa: email: %w", err)
	}
	return &status, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// getTenantByID fetches a single tenant row by primary key.
func (s *Service) getTenantByID(ctx context.Context, tenantID int64) (*TenantResult, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, name, slug, display_name, domain, region, description, plan,
		       is_active, cors_origins, created_at, updated_at
		FROM tenants
		WHERE id = $1
	`, tenantID)
	t, err := scanTenantRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get tenant by id: %w", err)
	}
	return &t, nil
}

// ListOwnedTenants returns every tenant where an active, non-deleted user row
// exists with the given email — i.e. every tenant this email owns or has an
// account in — along with the caller's role and per-tenant usage stats.
// Unlike ListTenantsPaginated (platform-admin-only, lists every tenant), this
// is self-scoped: it only ever returns tenants tied to the caller's own email.
func (s *Service) ListOwnedTenants(ctx context.Context, email string) ([]OwnedTenantResult, error) {
	// The email arrives from a JWT claim, which may predate normalization.
	email = emailaddr.Normalize(email)

	rows, err := s.pool.Query(ctx, `
		SELECT
			t.id, t.name, t.slug, t.display_name, t.domain, t.region, t.description,
			t.plan, t.is_active, t.cors_origins, t.created_at, t.updated_at,
			COALESCE(r.name, '') AS role_name,
			(SELECT COUNT(*) FROM users        WHERE tenant_id = t.id AND deleted_at IS NULL) AS user_count,
			(SELECT COUNT(*) FROM roles        WHERE tenant_id = t.id)                        AS role_count,
			(SELECT COUNT(*) FROM oauth_clients WHERE tenant_id = t.id AND deleted_at IS NULL) AS app_count
		FROM users u
		JOIN tenants t ON t.id = u.tenant_id
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.email = $1 AND u.is_active = true AND u.deleted_at IS NULL
		ORDER BY t.created_at DESC
	`, email)
	if err != nil {
		return nil, fmt.Errorf("list owned tenants: %w", err)
	}
	defer rows.Close()

	out := []OwnedTenantResult{}
	for rows.Next() {
		var r OwnedTenantResult
		var id int64
		if err := rows.Scan(
			&id, &r.Name, &r.Slug, &r.DisplayName, &r.Domain, &r.Region, &r.Description,
			&r.Plan, &r.IsActive, &r.CORSOrigins, &r.CreatedAt, &r.UpdatedAt,
			&r.Role, &r.Stats.UserCount, &r.Stats.RoleCount, &r.Stats.AppCount,
		); err != nil {
			return nil, fmt.Errorf("scan owned tenant: %w", err)
		}
		r.ID = strconv.FormatInt(id, 10)
		if r.CORSOrigins == nil {
			r.CORSOrigins = []string{}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// pgxScanner is satisfied by both *pgx.Row and pgx.Rows so scanTenantRow works for both.
type pgxScanner interface {
	Scan(dest ...any) error
}

// scanTenantRow scans a tenant row from a pgx.Row or pgx.Rows into a TenantResult.
func scanTenantRow(row pgxScanner) (TenantResult, error) {
	var t TenantResult
	var id int64
	if err := row.Scan(
		&id, &t.Name, &t.Slug, &t.DisplayName, &t.Domain, &t.Region,
		&t.Description, &t.Plan, &t.IsActive, &t.CORSOrigins, &t.CreatedAt, &t.UpdatedAt,
	); err != nil {
		return TenantResult{}, err
	}
	t.ID = strconv.FormatInt(id, 10)
	if t.CORSOrigins == nil {
		t.CORSOrigins = []string{}
	}
	return t, nil
}

// userEnrichmentColumns are the Auth0-style per-user stats selected alongside
// the base row: latest login, successful-login count, and sign-in connections.
// Requires the users table aliased as u.
//
// last_login_at is the GREATEST of two sources, and needs both.
//
// refresh_tokens gives the finer answer — MAX(last_used_at, created_at) is the
// last time the account actually did something, including silent token rotations
// that produce no login event. But that table is no longer permanent: the session
// reaper deletes rows once they are dead and past their retention margin, so on
// its own it would report NULL for any user whose last session died more than a
// week ago, and the console would show a long-dormant account as having never
// signed in. That is worse than imprecise; it is confidently wrong about the one
// field an operator uses to decide whether an account is abandoned.
//
// audit_logs is the durable half: login events are retained under the audit
// retention policy and are never reaped by session cleanup. It is coarser (it
// records logins, not subsequent activity), which is why it does not simply
// replace the other.
//
// Taking the greatest keeps the previous behaviour exactly while a session is
// live, and degrades to the audited login time afterwards instead of to NULL.
const userEnrichmentColumns = `
	       GREATEST(
	           (SELECT MAX(COALESCE(rt.last_used_at, rt.created_at))
	            FROM refresh_tokens rt
	            WHERE rt.user_id = u.id AND rt.tenant_id = u.tenant_id),
	           (SELECT MAX(al.created_at) FROM audit_logs al
	            WHERE al.user_id = u.id AND al.tenant_id = u.tenant_id
	              AND al.action IN (
	                  'auth.login', 'auth.google_login', 'auth.github_login',
	                  'auth.magic_link_requested', 'auth.register'))
	       ) AS last_login_at,
	       (SELECT COUNT(*) FROM audit_logs al
	        WHERE al.user_id = u.id AND al.tenant_id = u.tenant_id
	          AND al.action = 'auth.login') AS logins_count,
	       EXISTS (SELECT 1 FROM user_credentials uc
	               WHERE uc.user_id = u.id AND uc.tenant_id = u.tenant_id AND uc.deleted_at IS NULL) AS has_password,
	       (SELECT COALESCE(array_agg(ui.provider ORDER BY ui.provider), '{}')
	        FROM user_identities ui WHERE ui.user_id = u.id AND ui.tenant_id = u.tenant_id) AS providers`

// buildConnections merges the password credential and federated providers
// into the public Connections list ("password", "google", ...).
func buildConnections(hasPassword bool, providers []string) []string {
	connections := make([]string, 0, len(providers)+1)
	if hasPassword {
		connections = append(connections, "password")
	}
	return append(connections, providers...)
}

func (s *Service) getUserByID(ctx context.Context, tenantID int64, applicationID *int64, userID int64) (*UserResult, error) {
	var u UserResult
	var id, tid int64
	var appID, roleID *int64
	var hasPassword bool
	var providers []string
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, u.tenant_id, u.application_id, u.email, u.first_name, u.last_name,
		       COALESCE(r.name, '') as role_name, u.role_id, u.is_active, u.created_at,
		       `+userEnrichmentColumns+`
		FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.id = $1 AND u.tenant_id = $2 AND u.deleted_at IS NULL
		  AND ($3::BIGINT IS NULL OR u.application_id = $3)
	`, userID, tenantID, applicationID).Scan(
		&id, &tid, &appID, &u.Email, &u.FirstName, &u.LastName,
		&u.Role, &roleID, &u.IsActive, &u.CreatedAt,
		&u.LastLoginAt, &u.LoginsCount, &hasPassword, &providers,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get user: %w", err)
	}
	u.ID = strconv.FormatInt(id, 10)
	u.TenantID = strconv.FormatInt(tid, 10)
	if appID != nil {
		as := strconv.FormatInt(*appID, 10)
		u.ApplicationID = &as
	}
	if roleID != nil {
		rs := strconv.FormatInt(*roleID, 10)
		u.RoleID = &rs
	}
	u.Connections = buildConnections(hasPassword, providers)
	return &u, nil
}

func (s *Service) getRoleByID(ctx context.Context, tenantID, roleID int64) (*RoleResult, error) {
	var r RoleResult
	var id, tid int64
	var appID *int64
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, application_id, name, is_system, is_default, created_at
		FROM roles WHERE id = $1 AND tenant_id = $2
	`, roleID, tenantID).Scan(&id, &tid, &appID, &r.Name, &r.IsSystem, &r.IsDefault, &r.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get role: %w", err)
	}
	r.ID = strconv.FormatInt(id, 10)
	r.TenantID = strconv.FormatInt(tid, 10)
	if appID != nil {
		s := strconv.FormatInt(*appID, 10)
		r.ApplicationID = &s
	}
	perms, err := s.loadRolePermissions(ctx, roleID)
	if err != nil {
		return nil, err
	}
	r.Permissions = perms
	return &r, nil
}

func (s *Service) loadRolePermissions(ctx context.Context, roleID int64) ([]PermissionResult, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT p.id, p.tenant_id, p.application_id, p.name, p.description, p.created_at
		FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		WHERE rp.role_id = $1
		ORDER BY p.name
	`, roleID)
	if err != nil {
		return nil, fmt.Errorf("load role permissions: %w", err)
	}
	defer rows.Close()

	var perms []PermissionResult
	for rows.Next() {
		var p PermissionResult
		var id, tid int64
		var appID *int64
		if err := rows.Scan(&id, &tid, &appID, &p.Name, &p.Description, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan role permission: %w", err)
		}
		if appID != nil {
			s := strconv.FormatInt(*appID, 10)
			p.ApplicationID = &s
		}
		p.ID = strconv.FormatInt(id, 10)
		p.TenantID = strconv.FormatInt(tid, 10)
		perms = append(perms, p)
	}
	if perms == nil {
		perms = []PermissionResult{}
	}
	return perms, rows.Err()
}

// generateSecret generates a 32-byte random hex string for use as a JWT secret.
func generateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// generateTempPassword generates a 12-character alphanumeric temporary password.
func generateTempPassword() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b), nil
}

// isDuplicateErr returns true when err is a PostgreSQL unique_violation (code 23505).
func isDuplicateErr(err error) bool {
	if err == nil {
		return false
	}
	e := err.Error()
	return containsSubstr(e, "23505") || containsSubstr(e, "duplicate") || containsSubstr(e, "unique")
}

func containsSubstr(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
