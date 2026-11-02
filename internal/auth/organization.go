package auth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/password"
)

// ---------------------------------------------------------------------------
// Organizations (migrations 00100–00104).
//
// An organisation is a customer organisation inside ONE application. A user can
// be a member of several, holding different roles in each — "Sarah is Admin at
// Acme and Viewer at Globex" — which application-wide roles (user_roles) cannot
// express.
//
// OPT-IN. Nothing here runs for an application whose organizations_mode is
// 'off', which is every application until an operator changes it, and nothing
// at all while ORGANIZATIONS_ENABLED is false. Tokens for such applications are
// exactly what they were before this file existed.
//
// The service is deliberately ignorant of HTTP and of how a caller proved who it
// is. The admin console and an application's own backend both arrive with an
// OrganizationScope they have already established; every query then pins
// tenant_id AND application_id so a scope can never reach a sibling
// application's organisations.
// ---------------------------------------------------------------------------

// Application organisation modes — oauth_clients.organizations_mode.
const (
	// OrganizationsModeOff is the default: organisations do not exist as far as
	// sign-in is concerned, and organisation parameters are ignored.
	OrganizationsModeOff = "off"
	// OrganizationsModeOptional lets a session be inside one organisation or
	// none. A login that names no organisation gets today's token.
	OrganizationsModeOptional = "optional"
	// OrganizationsModeRequired puts every end-user session inside exactly one
	// organisation. A user with none cannot sign in to the application.
	OrganizationsModeRequired = "required"
)

// Membership status values — organization_members.status.
const (
	OrganizationMemberActive    = "active"
	OrganizationMemberSuspended = "suspended"
)

// Abuse limits. Generous for real use; their job is to bound what one leaked
// client secret can make this server store.
const (
	MaxOrganizationsPerApplication = 10000
	MaxMembersPerOrganization      = 5000
	MaxOrganizationRolesPerMember  = 20
	maxOrganizationMetadataBytes   = 4096
	maxOrganizationDisplayName     = 200
	maxOrganizationPageSize        = 100
	defaultOrganizationPageSize    = 25
)

// RevokeReasonOrganization is the session revocation reason recorded when a
// session ends because its organisation access changed: the member was removed
// or suspended, the organisation was deactivated or deleted, or the
// application's organisation mode changed underneath it.
const RevokeReasonOrganization = "organization_access_changed"

var (
	// ErrOrganizationsDisabled is returned when the feature is switched off for
	// the deployment. Handlers answer 404 so a disabled feature is
	// indistinguishable from one that was never built.
	ErrOrganizationsDisabled = errors.New("organizations are not enabled")
	// ErrOrganizationNotFound covers unknown, deleted and other applications'
	// organisations alike, so one application cannot probe for another's.
	ErrOrganizationNotFound = errors.New("organization not found")
	// ErrOrganizationSlugTaken is a slug collision inside one application.
	ErrOrganizationSlugTaken = errors.New("an organization with this slug already exists in this application")
	// ErrInvalidOrganizationSlug is a slug that fails the format rule.
	ErrInvalidOrganizationSlug = errors.New("slug must be 1-63 lowercase letters, digits or hyphens, and must not start or end with a hyphen")
	// ErrInvalidOrganizationName is an empty or over-long display name.
	ErrInvalidOrganizationName = errors.New("display_name is required and must be at most 200 characters")
	// ErrInvalidOrganizationMetadata is metadata that is not a JSON object or
	// exceeds the size cap.
	ErrInvalidOrganizationMetadata = errors.New("metadata must be a JSON object of at most 4096 bytes")
	// ErrOrganizationLimitReached means the application holds the maximum
	// number of organisations.
	ErrOrganizationLimitReached = errors.New("organization limit reached for this application")
	// ErrOrganizationMemberNotFound is a user who is not a member.
	ErrOrganizationMemberNotFound = errors.New("member not found in this organization")
	// ErrOrganizationMemberLimitReached means the organisation is full.
	ErrOrganizationMemberLimitReached = errors.New("member limit reached for this organization")
	// ErrOrganizationRoleLimitReached means a member would hold too many roles.
	ErrOrganizationRoleLimitReached = errors.New("a member may hold at most 20 roles in one organization")
	// ErrInvalidOrganizationMemberStatus is a status other than active/suspended.
	ErrInvalidOrganizationMemberStatus = errors.New(`status must be "active" or "suspended"`)
	// ErrInvalidOrganizationsMode is a mode other than off/optional/required.
	ErrInvalidOrganizationsMode = errors.New(`organizations_mode must be "off", "optional" or "required"`)
	// ErrOrganizationAccessDenied refuses a sign-in to an organisation.
	//
	// ONE error for every reason — unknown organisation, another application's,
	// deactivated, deleted, not a member, suspended — so the login endpoints
	// cannot be used to learn which organisations exist or who belongs to them.
	ErrOrganizationAccessDenied = errors.New("organization access denied")
	// ErrOrganizationSelectionInvalid is an unknown, expired or used selection
	// token.
	ErrOrganizationSelectionInvalid = errors.New("invalid or expired organization selection")
	// ErrOrganizationUnavailable is returned when organisation state could not be
	// read during a mint. The mint fails rather than issuing a token without the
	// organisation claims, because a missing org_id changes what a relying party
	// believes the session is.
	ErrOrganizationUnavailable = errors.New("organization state unavailable")
	// ErrOrganizationsNotApplicable is a switch request for a session that has
	// no application, or whose application is not organisation-enabled.
	ErrOrganizationsNotApplicable = errors.New("organizations are not enabled for this application")
)

// OrganizationsModeUnmetError refuses switching an application to 'required'
// while some of its active users belong to no active organisation: every one of
// them would be locked out at their next sign-in. Passing force overrides it.
type OrganizationsModeUnmetError struct {
	UsersWithoutMembership int64
}

func (e *OrganizationsModeUnmetError) Error() string {
	return fmt.Sprintf("%d active users of this application belong to no active organization; "+
		"add them to an organization first, or pass force=true to lock them out", e.UsersWithoutMembership)
}

// OrganizationScope is an application both callers have already authenticated
// or authorised: an application backend via its client secret, an
// administrator via the console's tenant and application guards.
type OrganizationScope struct {
	TenantID int64
	AppRowID int64
}

// Organization is the external view of an organisation. ID is the public id;
// the row id never leaves the server.
type Organization struct {
	ID          string         `json:"id"`
	Slug        string         `json:"slug"`
	DisplayName string         `json:"display_name"`
	Metadata    map[string]any `json:"metadata"`
	IsActive    bool           `json:"is_active"`
	MemberCount int64          `json:"member_count"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`

	rowID int64
}

// OrganizationRef is the short form used in selection challenges and
// membership listings.
type OrganizationRef struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`

	rowID int64
}

// OrganizationMember is one member of an organisation.
type OrganizationMember struct {
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Status    string    `json:"status"`
	Roles     []string  `json:"roles"`
	JoinedAt  time.Time `json:"joined_at"`
}

// OrganizationMembership is one organisation a user belongs to.
type OrganizationMembership struct {
	Organization OrganizationRef `json:"organization"`
	Status       string          `json:"status"`
	Roles        []string        `json:"roles"`
	JoinedAt     time.Time       `json:"joined_at"`
}

// OrganizationsPage is a page of organisations.
type OrganizationsPage struct {
	Items  []Organization `json:"items"`
	Total  int64          `json:"total"`
	Limit  int            `json:"limit"`
	Offset int            `json:"offset"`
}

// OrganizationMembersPage is a page of members.
type OrganizationMembersPage struct {
	Items  []OrganizationMember `json:"items"`
	Total  int64                `json:"total"`
	Limit  int                  `json:"limit"`
	Offset int                  `json:"offset"`
}

// PageParams bounds a listing. Zero values select the defaults.
type PageParams struct {
	Search string
	Limit  int
	Offset int
}

func (p PageParams) normalised() PageParams {
	if p.Limit <= 0 {
		p.Limit = defaultOrganizationPageSize
	}
	if p.Limit > maxOrganizationPageSize {
		p.Limit = maxOrganizationPageSize
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	p.Search = strings.TrimSpace(p.Search)
	return p
}

// CreateOrganizationInput creates an organisation.
type CreateOrganizationInput struct {
	Slug        string
	DisplayName string
	Metadata    map[string]any
	// CreatedBy is the administrator, nil when an application backend created it.
	CreatedBy *int64
}

// UpdateOrganizationInput changes an organisation. Nil leaves a field as it is.
// The slug is immutable: it is carried in tokens as org_name, and a rename would
// make two live tokens for one organisation disagree about what it is called.
type UpdateOrganizationInput struct {
	DisplayName *string
	Metadata    map[string]any
	// IsActive false suspends the organisation and revokes its sessions.
	IsActive *bool
}

// MemberRolesResult reports an organisation role change.
type MemberRolesResult struct {
	UserID string `json:"user_id"`
	// Roles is every organisation role the member holds after the call.
	Roles []string `json:"roles"`
	// Assigned lists only roles this call added.
	Assigned []string `json:"assigned"`
	// Removed lists roles this call removed (replace mode or a single removal).
	Removed []string `json:"removed"`
}

// organizationSessionRevoker is the slice of AuthService the organisation
// service needs to end sessions. An interface rather than a pointer so this
// file does not reach into session bookkeeping it does not own.
type organizationSessionRevoker interface {
	revokeOrganizationSessions(ctx context.Context, orgRowID int64, userID *int64) int
	revokeApplicationSessionsByBinding(ctx context.Context, appRowID int64, bound bool) int
	DenyUserSessions(ctx context.Context, userID, tenantID int64)
}

// OrganizationService manages organisations, memberships and organisation roles.
type OrganizationService struct {
	pool     *pgxpool.Pool
	redisCli *redis.Client
	enabled  bool
	sessions organizationSessionRevoker
	notify   EmailNotifier
	// hasher writes the credential when an invitation creates an account.
	hasher *password.Hasher
	logger zerolog.Logger
}

// NewOrganizationService creates the service. enabled is the deployment switch
// (ORGANIZATIONS_ENABLED); when false every method refuses with
// ErrOrganizationsDisabled and the mint treats every application as 'off'.
func NewOrganizationService(pool *pgxpool.Pool, redisCli *redis.Client, enabled bool, logger zerolog.Logger) *OrganizationService {
	return &OrganizationService{pool: pool, redisCli: redisCli, enabled: enabled, logger: logger}
}

// WithNotifier sets the email notifier used for organisation invitations, so
// they are branded and customisable per application like every other mail.
func (s *OrganizationService) WithNotifier(n EmailNotifier) *OrganizationService {
	s.notify = n
	return s
}

// Enabled reports whether the deployment switch is on. Safe on a nil receiver,
// so call sites need no separate nil check.
func (s *OrganizationService) Enabled() bool { return s != nil && s.enabled }

func (s *OrganizationService) guard() error {
	if !s.Enabled() {
		return ErrOrganizationsDisabled
	}
	return nil
}

// ---------------------------------------------------------------------------
// Identifiers and validation
// ---------------------------------------------------------------------------

const base62Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var (
	organizationSlugRe     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	organizationPublicIDRe = regexp.MustCompile(`^org_[A-Za-z0-9]{20}$`)
)

// randomBase62 returns n characters from crypto/rand, uniformly distributed.
func randomBase62(n int) (string, error) {
	max := big.NewInt(int64(len(base62Alphabet)))
	b := make([]byte, n)
	for i := range b {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("generate identifier: %w", err)
		}
		b[i] = base62Alphabet[v.Int64()]
	}
	return string(b), nil
}

func newOrganizationPublicID() (string, error) {
	r, err := randomBase62(20)
	if err != nil {
		return "", err
	}
	return "org_" + r, nil
}

// NormalizeOrganizationSlug lower-cases and trims a slug. Exported so handlers
// can echo the stored form back.
func NormalizeOrganizationSlug(slug string) string {
	return strings.ToLower(strings.TrimSpace(slug))
}

func validateOrganizationMetadata(md map[string]any) ([]byte, error) {
	if md == nil {
		return []byte("{}"), nil
	}
	raw, err := json.Marshal(md)
	if err != nil || len(raw) > maxOrganizationMetadataBytes {
		return nil, ErrInvalidOrganizationMetadata
	}
	return raw, nil
}

func validOrganizationsMode(mode string) bool {
	switch mode {
	case OrganizationsModeOff, OrganizationsModeOptional, OrganizationsModeRequired:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Application mode
// ---------------------------------------------------------------------------

// ApplicationMode returns an application's organisation mode, or 'off' when the
// deployment switch is off. An unknown application also reads as 'off'.
func (s *OrganizationService) ApplicationMode(ctx context.Context, appRowID int64) (string, error) {
	if !s.Enabled() || appRowID == 0 {
		return OrganizationsModeOff, nil
	}
	var mode string
	err := s.pool.QueryRow(ctx, `
		SELECT organizations_mode FROM oauth_clients
		WHERE id = $1 AND deleted_at IS NULL
	`, appRowID).Scan(&mode)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OrganizationsModeOff, nil
		}
		return "", fmt.Errorf("read organizations mode: %w", err)
	}
	return mode, nil
}

// VerifyScope confirms the application exists in the tenant. The admin routes
// carry tenant and application ids from the URL; the guards authorise the
// caller for the tenant, and this pins the application to it.
func (s *OrganizationService) VerifyScope(ctx context.Context, sc OrganizationScope) error {
	if err := s.guard(); err != nil {
		return err
	}
	var ok bool
	if err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM oauth_clients
		               WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL)
	`, sc.AppRowID, sc.TenantID).Scan(&ok); err != nil {
		return fmt.Errorf("verify application scope: %w", err)
	}
	if !ok {
		return ErrOrganizationNotFound
	}
	return nil
}

// SetApplicationMode changes an application's organisation mode and ends the
// sessions the change makes wrong. Returns the previous mode.
//
//   - Moving to 'required' is refused while any active user of the application
//     belongs to no active organisation, unless force is set: those users
//     would be locked out at their next sign-in. Sessions without an
//     organisation are revoked so nobody keeps an organisation-less session in
//     an application that no longer permits one.
//   - Moving to 'off' revokes every organisation session, so no token keeps
//     carrying org_* claims for an application that no longer issues them.
//     Users sign in again and get a plain token.
func (s *OrganizationService) SetApplicationMode(ctx context.Context, sc OrganizationScope, mode string, force bool) (string, error) {
	if err := s.VerifyScope(ctx, sc); err != nil {
		return "", err
	}
	if !validOrganizationsMode(mode) {
		return "", ErrInvalidOrganizationsMode
	}

	if mode == OrganizationsModeRequired && !force {
		var missing int64
		if err := s.pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM users u
			WHERE u.tenant_id = $1 AND u.application_id = $2
			  AND u.deleted_at IS NULL AND u.is_active = true
			  AND NOT EXISTS (
			      SELECT 1 FROM organization_members m
			      JOIN organizations o ON o.id = m.organization_id
			      WHERE m.user_id = u.id AND m.status = 'active'
			        AND o.is_active = true AND o.deleted_at IS NULL)
		`, sc.TenantID, sc.AppRowID).Scan(&missing); err != nil {
			return "", fmt.Errorf("count users without organization: %w", err)
		}
		if missing > 0 {
			return "", &OrganizationsModeUnmetError{UsersWithoutMembership: missing}
		}
	}

	// Read-then-write under a row lock, in one transaction. A single
	// UPDATE … RETURNING (SELECT … FROM a FOR UPDATE CTE) does not work: the
	// CTE's locked read of the row being updated comes back empty, so the
	// previous mode — which decides which sessions to revoke — was NULL.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("begin update organizations mode: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var previous string
	if err := tx.QueryRow(ctx, `
		SELECT organizations_mode FROM oauth_clients
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		FOR UPDATE
	`, sc.AppRowID, sc.TenantID).Scan(&previous); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrOrganizationNotFound
		}
		return "", fmt.Errorf("read organizations mode: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE oauth_clients SET organizations_mode = $3, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2
	`, sc.AppRowID, sc.TenantID, mode); err != nil {
		return "", fmt.Errorf("update organizations mode: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit organizations mode: %w", err)
	}

	if s.sessions != nil && previous != mode {
		switch mode {
		case OrganizationsModeOff:
			s.sessions.revokeApplicationSessionsByBinding(ctx, sc.AppRowID, true)
		case OrganizationsModeRequired:
			s.sessions.revokeApplicationSessionsByBinding(ctx, sc.AppRowID, false)
		}
	}
	return previous, nil
}

// ---------------------------------------------------------------------------
// Organisations
// ---------------------------------------------------------------------------

const organizationColumns = `o.id, o.public_id, o.slug, o.display_name, o.metadata, o.is_active,
	o.created_at, o.updated_at,
	(SELECT COUNT(*) FROM organization_members m WHERE m.organization_id = o.id)`

func scanOrganization(row pgx.Row) (*Organization, error) {
	var o Organization
	var md []byte
	if err := row.Scan(&o.rowID, &o.ID, &o.Slug, &o.DisplayName, &md, &o.IsActive,
		&o.CreatedAt, &o.UpdatedAt, &o.MemberCount); err != nil {
		return nil, err
	}
	o.Metadata = map[string]any{}
	if len(md) > 0 {
		_ = json.Unmarshal(md, &o.Metadata)
	}
	return &o, nil
}

// CreateOrganization creates an organisation in the scope's application.
//
// Allowed while the application's mode is still 'off', so organisations and
// memberships can be backfilled before sign-in starts depending on them.
func (s *OrganizationService) CreateOrganization(ctx context.Context, sc OrganizationScope, in CreateOrganizationInput) (*Organization, error) {
	if err := s.guard(); err != nil {
		return nil, err
	}
	slug := NormalizeOrganizationSlug(in.Slug)
	if !organizationSlugRe.MatchString(slug) {
		return nil, ErrInvalidOrganizationSlug
	}
	name := strings.TrimSpace(in.DisplayName)
	if name == "" || len([]rune(name)) > maxOrganizationDisplayName {
		return nil, ErrInvalidOrganizationName
	}
	md, err := validateOrganizationMetadata(in.Metadata)
	if err != nil {
		return nil, err
	}
	publicID, err := newOrganizationPublicID()
	if err != nil {
		return nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin create organization: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Serialise creation per application so the count-then-insert below cannot
	// be raced past the cap by concurrent requests. The single-bigint lock form,
	// keyed by hashing a fixed namespace with the application id as the seed, so
	// the 64-bit id is never narrowed.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('organizations:create', $1))`,
		sc.AppRowID); err != nil {
		return nil, fmt.Errorf("lock organization count: %w", err)
	}
	var count int64
	if err := tx.QueryRow(ctx, `
		SELECT COUNT(*) FROM organizations
		WHERE application_id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`, sc.AppRowID, sc.TenantID).Scan(&count); err != nil {
		return nil, fmt.Errorf("count organizations: %w", err)
	}
	if count >= MaxOrganizationsPerApplication {
		return nil, ErrOrganizationLimitReached
	}

	org, err := scanOrganization(tx.QueryRow(ctx, `
		WITH ins AS (
			INSERT INTO organizations (public_id, tenant_id, application_id, slug, display_name, metadata, created_by)
			SELECT $1, $2, $3, $4, $5, $6, $7
			WHERE EXISTS (SELECT 1 FROM oauth_clients
			              WHERE id = $3 AND tenant_id = $2 AND deleted_at IS NULL)
			RETURNING *
		)
		SELECT o.id, o.public_id, o.slug, o.display_name, o.metadata, o.is_active,
		       o.created_at, o.updated_at, 0::BIGINT
		FROM ins o
	`, publicID, sc.TenantID, sc.AppRowID, slug, name, md, in.CreatedBy))
	if err != nil {
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return nil, ErrOrganizationNotFound
		case isUniqueViolation(err):
			return nil, ErrOrganizationSlugTaken
		}
		return nil, fmt.Errorf("insert organization: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit create organization: %w", err)
	}
	return org, nil
}

// organizationRefPredicate matches an organisation by public id or by slug,
// whichever form ref takes. Scoped to live organisations only.
func organizationRefArgs(ref string) (byPublicID bool, value string) {
	ref = strings.TrimSpace(ref)
	if organizationPublicIDRe.MatchString(ref) {
		return true, ref
	}
	return false, NormalizeOrganizationSlug(ref)
}

// GetOrganization returns one organisation by public id or slug.
func (s *OrganizationService) GetOrganization(ctx context.Context, sc OrganizationScope, ref string) (*Organization, error) {
	if err := s.guard(); err != nil {
		return nil, err
	}
	return s.getOrganization(ctx, s.pool, sc, ref, false)
}

type queryRower interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func (s *OrganizationService) getOrganization(ctx context.Context, q queryRower, sc OrganizationScope, ref string, forUpdate bool) (*Organization, error) {
	byID, value := organizationRefArgs(ref)
	if value == "" {
		return nil, ErrOrganizationNotFound
	}
	sql := `SELECT ` + organizationColumns + `
		FROM organizations o
		WHERE o.tenant_id = $1 AND o.application_id = $2 AND o.deleted_at IS NULL
		  AND ` + map[bool]string{true: "o.public_id = $3", false: "o.slug = $3"}[byID]
	if forUpdate {
		sql += ` FOR UPDATE OF o`
	}
	org, err := scanOrganization(q.QueryRow(ctx, sql, sc.TenantID, sc.AppRowID, value))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrOrganizationNotFound
		}
		return nil, fmt.Errorf("load organization: %w", err)
	}
	return org, nil
}

// ListOrganizations pages through the application's organisations, newest first.
// Search matches slug or display name, case-insensitively.
func (s *OrganizationService) ListOrganizations(ctx context.Context, sc OrganizationScope, p PageParams) (*OrganizationsPage, error) {
	if err := s.guard(); err != nil {
		return nil, err
	}
	p = p.normalised()
	pattern := "%" + escapeLike(p.Search) + "%"

	var total int64
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM organizations o
		WHERE o.tenant_id = $1 AND o.application_id = $2 AND o.deleted_at IS NULL
		  AND ($3 = '%%' OR o.slug ILIKE $3 OR o.display_name ILIKE $3)
	`, sc.TenantID, sc.AppRowID, pattern).Scan(&total); err != nil {
		return nil, fmt.Errorf("count organizations: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT `+organizationColumns+`
		FROM organizations o
		WHERE o.tenant_id = $1 AND o.application_id = $2 AND o.deleted_at IS NULL
		  AND ($3 = '%%' OR o.slug ILIKE $3 OR o.display_name ILIKE $3)
		ORDER BY o.created_at DESC, o.id DESC
		LIMIT $4 OFFSET $5
	`, sc.TenantID, sc.AppRowID, pattern, p.Limit, p.Offset)
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}
	defer rows.Close()
	items := []Organization{}
	for rows.Next() {
		o, err := scanOrganization(rows)
		if err != nil {
			return nil, fmt.Errorf("scan organization: %w", err)
		}
		items = append(items, *o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate organizations: %w", err)
	}
	return &OrganizationsPage{Items: items, Total: total, Limit: p.Limit, Offset: p.Offset}, nil
}

// escapeLike escapes the LIKE metacharacters in user input.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// UpdateOrganization changes display name, metadata or active state.
// Deactivating revokes every session signed in to the organisation.
func (s *OrganizationService) UpdateOrganization(ctx context.Context, sc OrganizationScope, ref string, in UpdateOrganizationInput) (*Organization, error) {
	if err := s.guard(); err != nil {
		return nil, err
	}
	var name *string
	if in.DisplayName != nil {
		n := strings.TrimSpace(*in.DisplayName)
		if n == "" || len([]rune(n)) > maxOrganizationDisplayName {
			return nil, ErrInvalidOrganizationName
		}
		name = &n
	}
	var md []byte
	if in.Metadata != nil {
		raw, err := validateOrganizationMetadata(in.Metadata)
		if err != nil {
			return nil, err
		}
		md = raw
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin update organization: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	cur, err := s.getOrganization(ctx, tx, sc, ref, true)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE organizations
		SET display_name = COALESCE($2, display_name),
		    metadata     = COALESCE($3::JSONB, metadata),
		    is_active    = COALESCE($4, is_active),
		    updated_at   = NOW()
		WHERE id = $1
	`, cur.rowID, name, md, in.IsActive); err != nil {
		return nil, fmt.Errorf("update organization: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit update organization: %w", err)
	}

	if in.IsActive != nil && !*in.IsActive && cur.IsActive && s.sessions != nil {
		s.sessions.revokeOrganizationSessions(ctx, cur.rowID, nil)
	}
	return s.getOrganization(ctx, s.pool, sc, cur.ID, false)
}

// DeleteOrganization soft-deletes an organisation: sign-in to it stops, its
// sessions are revoked and its pending invitations are closed. Members and
// roles are kept for the audit trail.
func (s *OrganizationService) DeleteOrganization(ctx context.Context, sc OrganizationScope, ref string) (*Organization, error) {
	if err := s.guard(); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin delete organization: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	cur, err := s.getOrganization(ctx, tx, sc, ref, true)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE organizations SET deleted_at = NOW(), is_active = false, updated_at = NOW()
		WHERE id = $1
	`, cur.rowID); err != nil {
		return nil, fmt.Errorf("delete organization: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE organization_invitations SET revoked_at = NOW()
		WHERE organization_id = $1 AND accepted_at IS NULL AND revoked_at IS NULL
	`, cur.rowID); err != nil {
		return nil, fmt.Errorf("close organization invitations: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit delete organization: %w", err)
	}
	if s.sessions != nil {
		s.sessions.revokeOrganizationSessions(ctx, cur.rowID, nil)
	}
	cur.IsActive = false
	return cur, nil
}

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

// requireApplicationUser confirms the user belongs to the scope's application.
// The answer for "no such user" and "another application's user" is the same,
// so a scope cannot enumerate a sibling application's user ids.
func requireApplicationUser(ctx context.Context, q queryRower, sc OrganizationScope, userID int64) error {
	var ok bool
	if err := q.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM users
		               WHERE id = $1 AND tenant_id = $2 AND application_id = $3
		                 AND deleted_at IS NULL)
	`, userID, sc.TenantID, sc.AppRowID).Scan(&ok); err != nil {
		return fmt.Errorf("verify application user: %w", err)
	}
	if !ok {
		return ErrUserNotInApplication
	}
	return nil
}

// AddMember adds a user of the application to an organisation, optionally with
// organisation roles. Adding an existing member is not an error: it returns the
// membership unchanged apart from any additional roles, so a retried request is
// harmless. created reports whether a membership was made.
func (s *OrganizationService) AddMember(ctx context.Context, sc OrganizationScope, ref string, userID int64, roles []string, invitedBy *int64) (member *OrganizationMember, created bool, err error) {
	if err := s.guard(); err != nil {
		return nil, false, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("begin add member: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	org, err := s.getOrganization(ctx, tx, sc, ref, true)
	if err != nil {
		return nil, false, err
	}
	created, err = s.addMemberTx(ctx, tx, sc, org.rowID, userID, invitedBy)
	if err != nil {
		return nil, false, err
	}
	if len(normaliseRoleNames(roles)) > 0 {
		if _, _, err := s.assignRolesTx(ctx, tx, sc, org.rowID, userID, roles, false, invitedBy); err != nil {
			return nil, false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf("commit add member: %w", err)
	}
	if !created && len(roles) > 0 && s.sessions != nil {
		s.sessions.DenyUserSessions(ctx, userID, sc.TenantID)
	}
	m, err := s.getMember(ctx, s.pool, sc, org.rowID, userID)
	return m, created, err
}

// addMemberTx inserts the membership row inside the caller's transaction,
// enforcing the per-organisation member cap. The organisation row must already
// be locked by the caller.
func (s *OrganizationService) addMemberTx(ctx context.Context, tx pgx.Tx, sc OrganizationScope, orgRowID, userID int64, invitedBy *int64) (bool, error) {
	if err := requireApplicationUser(ctx, tx, sc, userID); err != nil {
		return false, err
	}
	var count int64
	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT COUNT(*), COALESCE(BOOL_OR(user_id = $2), false)
		FROM organization_members WHERE organization_id = $1
	`, orgRowID, userID).Scan(&count, &exists); err != nil {
		return false, fmt.Errorf("count members: %w", err)
	}
	if exists {
		return false, nil
	}
	if count >= MaxMembersPerOrganization {
		return false, ErrOrganizationMemberLimitReached
	}
	ct, err := tx.Exec(ctx, `
		INSERT INTO organization_members (organization_id, application_id, user_id, tenant_id, invited_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (organization_id, user_id) DO NOTHING
	`, orgRowID, sc.AppRowID, userID, sc.TenantID, invitedBy)
	if err != nil {
		if isCheckViolation(err) {
			return false, ErrUserNotInApplication
		}
		return false, fmt.Errorf("insert member: %w", err)
	}
	return ct.RowsAffected() > 0, nil
}

func (s *OrganizationService) getMember(ctx context.Context, q queryRower, sc OrganizationScope, orgRowID, userID int64) (*OrganizationMember, error) {
	var m OrganizationMember
	var uid int64
	err := q.QueryRow(ctx, `
		SELECT u.id, u.email, COALESCE(u.first_name, ''), COALESCE(u.last_name, ''), m.status, m.joined_at,
		       COALESCE((SELECT ARRAY_AGG(r.name ORDER BY omr.granted_at, r.id)
		                 FROM organization_member_roles omr
		                 JOIN roles r ON r.id = omr.role_id AND r.deleted_at IS NULL
		                 WHERE omr.organization_id = m.organization_id AND omr.user_id = m.user_id),
		                '{}')
		FROM organization_members m
		JOIN users u ON u.id = m.user_id
		WHERE m.organization_id = $1 AND m.user_id = $2
		  AND m.tenant_id = $3 AND m.application_id = $4
	`, orgRowID, userID, sc.TenantID, sc.AppRowID).Scan(&uid, &m.Email, &m.FirstName, &m.LastName,
		&m.Status, &m.JoinedAt, &m.Roles)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrOrganizationMemberNotFound
		}
		return nil, fmt.Errorf("load member: %w", err)
	}
	m.UserID = strconv.FormatInt(uid, 10)
	return &m, nil
}

// GetMember returns one member of an organisation.
func (s *OrganizationService) GetMember(ctx context.Context, sc OrganizationScope, ref string, userID int64) (*OrganizationMember, error) {
	if err := s.guard(); err != nil {
		return nil, err
	}
	org, err := s.getOrganization(ctx, s.pool, sc, ref, false)
	if err != nil {
		return nil, err
	}
	return s.getMember(ctx, s.pool, sc, org.rowID, userID)
}

// ListMembers pages through an organisation's members, oldest first. Search
// matches email or name.
func (s *OrganizationService) ListMembers(ctx context.Context, sc OrganizationScope, ref string, p PageParams) (*OrganizationMembersPage, error) {
	if err := s.guard(); err != nil {
		return nil, err
	}
	org, err := s.getOrganization(ctx, s.pool, sc, ref, false)
	if err != nil {
		return nil, err
	}
	p = p.normalised()
	pattern := "%" + escapeLike(p.Search) + "%"

	var total int64
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM organization_members m JOIN users u ON u.id = m.user_id
		WHERE m.organization_id = $1
		  AND ($2 = '%%' OR u.email ILIKE $2 OR u.first_name ILIKE $2 OR u.last_name ILIKE $2)
	`, org.rowID, pattern).Scan(&total); err != nil {
		return nil, fmt.Errorf("count members: %w", err)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT u.id, u.email, COALESCE(u.first_name, ''), COALESCE(u.last_name, ''), m.status, m.joined_at,
		       COALESCE((SELECT ARRAY_AGG(r.name ORDER BY omr.granted_at, r.id)
		                 FROM organization_member_roles omr
		                 JOIN roles r ON r.id = omr.role_id AND r.deleted_at IS NULL
		                 WHERE omr.organization_id = m.organization_id AND omr.user_id = m.user_id),
		                '{}')
		FROM organization_members m JOIN users u ON u.id = m.user_id
		WHERE m.organization_id = $1
		  AND ($2 = '%%' OR u.email ILIKE $2 OR u.first_name ILIKE $2 OR u.last_name ILIKE $2)
		ORDER BY m.joined_at, m.user_id
		LIMIT $3 OFFSET $4
	`, org.rowID, pattern, p.Limit, p.Offset)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	defer rows.Close()
	items := []OrganizationMember{}
	for rows.Next() {
		var m OrganizationMember
		var uid int64
		if err := rows.Scan(&uid, &m.Email, &m.FirstName, &m.LastName, &m.Status, &m.JoinedAt, &m.Roles); err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		m.UserID = strconv.FormatInt(uid, 10)
		items = append(items, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate members: %w", err)
	}
	return &OrganizationMembersPage{Items: items, Total: total, Limit: p.Limit, Offset: p.Offset}, nil
}

// SetMemberStatus suspends or reactivates a member. Suspension revokes the
// member's sessions in this organisation; reactivation takes effect at their
// next sign-in.
func (s *OrganizationService) SetMemberStatus(ctx context.Context, sc OrganizationScope, ref string, userID int64, status string) (*OrganizationMember, error) {
	if err := s.guard(); err != nil {
		return nil, err
	}
	if status != OrganizationMemberActive && status != OrganizationMemberSuspended {
		return nil, ErrInvalidOrganizationMemberStatus
	}
	org, err := s.getOrganization(ctx, s.pool, sc, ref, false)
	if err != nil {
		return nil, err
	}
	ct, err := s.pool.Exec(ctx, `
		UPDATE organization_members SET status = $3, updated_at = NOW()
		WHERE organization_id = $1 AND user_id = $2
	`, org.rowID, userID, status)
	if err != nil {
		return nil, fmt.Errorf("update member status: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return nil, ErrOrganizationMemberNotFound
	}
	if status == OrganizationMemberSuspended && s.sessions != nil {
		s.sessions.revokeOrganizationSessions(ctx, org.rowID, &userID)
	}
	return s.getMember(ctx, s.pool, sc, org.rowID, userID)
}

// RemoveMember deletes a membership and its organisation roles, and revokes the
// member's sessions in this organisation.
func (s *OrganizationService) RemoveMember(ctx context.Context, sc OrganizationScope, ref string, userID int64) error {
	if err := s.guard(); err != nil {
		return err
	}
	org, err := s.getOrganization(ctx, s.pool, sc, ref, false)
	if err != nil {
		return err
	}
	ct, err := s.pool.Exec(ctx, `
		DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2
	`, org.rowID, userID)
	if err != nil {
		return fmt.Errorf("remove member: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrOrganizationMemberNotFound
	}
	if s.sessions != nil {
		s.sessions.revokeOrganizationSessions(ctx, org.rowID, &userID)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Organisation roles
// ---------------------------------------------------------------------------

// AssignMemberRoles grants organisation roles to a member. replace discards the
// roles the member holds in this organisation first. Roles are names of live,
// non-system roles in the application; anything else refuses the whole call.
//
// The member's access tokens are invalidated after the commit, so the change
// reaches them at their next refresh rather than when the token expires.
func (s *OrganizationService) AssignMemberRoles(ctx context.Context, sc OrganizationScope, ref string, userID int64, roles []string, replace bool, grantedBy *int64) (*MemberRolesResult, error) {
	if err := s.guard(); err != nil {
		return nil, err
	}
	if len(normaliseRoleNames(roles)) == 0 && !replace {
		return nil, ErrNoRolesRequested
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin assign member roles: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	org, err := s.getOrganization(ctx, tx, sc, ref, true)
	if err != nil {
		return nil, err
	}
	assigned, removed, err := s.assignRolesTx(ctx, tx, sc, org.rowID, userID, roles, replace, grantedBy)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit assign member roles: %w", err)
	}
	if (len(assigned) > 0 || len(removed) > 0) && s.sessions != nil {
		s.sessions.DenyUserSessions(ctx, userID, sc.TenantID)
	}
	m, err := s.getMember(ctx, s.pool, sc, org.rowID, userID)
	if err != nil {
		return nil, err
	}
	return &MemberRolesResult{UserID: m.UserID, Roles: m.Roles, Assigned: assigned, Removed: removed}, nil
}

// resolveApplicationRoles maps role names to ids within the application. Every
// name must be a live, non-system role of the application, or the call fails
// naming the ones that are not — the caller authenticated as the application,
// so it is being told about its own configuration.
func resolveApplicationRoles(ctx context.Context, tx pgx.Tx, sc OrganizationScope, names []string) (map[string]int64, error) {
	ids := make(map[string]int64, len(names))
	if len(names) == 0 {
		return ids, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT id, name FROM roles
		WHERE tenant_id = $1 AND application_id = $2 AND name = ANY($3)
		  AND is_system = false AND deleted_at IS NULL
	`, sc.TenantID, sc.AppRowID, names)
	if err != nil {
		return nil, fmt.Errorf("resolve roles: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		ids[name] = id
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate roles: %w", err)
	}
	var missing []string
	for _, n := range names {
		if _, ok := ids[n]; !ok {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrRoleNotInApplication, strings.Join(missing, ", "))
	}
	return ids, nil
}

func (s *OrganizationService) assignRolesTx(ctx context.Context, tx pgx.Tx, sc OrganizationScope, orgRowID, userID int64, roles []string, replace bool, grantedBy *int64) (assigned, removed []string, err error) {
	names := normaliseRoleNames(roles)
	ids, err := resolveApplicationRoles(ctx, tx, sc, names)
	if err != nil {
		return nil, nil, err
	}

	var isMember bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM organization_members
		               WHERE organization_id = $1 AND user_id = $2 AND application_id = $3)
	`, orgRowID, userID, sc.AppRowID).Scan(&isMember); err != nil {
		return nil, nil, fmt.Errorf("verify member: %w", err)
	}
	if !isMember {
		return nil, nil, ErrOrganizationMemberNotFound
	}

	held := map[string]int64{}
	rows, err := tx.Query(ctx, `
		SELECT r.id, r.name FROM organization_member_roles omr
		JOIN roles r ON r.id = omr.role_id
		WHERE omr.organization_id = $1 AND omr.user_id = $2
	`, orgRowID, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("load member roles: %w", err)
	}
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			return nil, nil, fmt.Errorf("scan member role: %w", err)
		}
		held[name] = id
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate member roles: %w", err)
	}

	if replace {
		keep := make(map[string]struct{}, len(names))
		for _, n := range names {
			keep[n] = struct{}{}
		}
		var drop []int64
		for name, id := range held {
			if _, ok := keep[name]; !ok {
				drop = append(drop, id)
				removed = append(removed, name)
				delete(held, name)
			}
		}
		if len(drop) > 0 {
			if _, err := tx.Exec(ctx, `
				DELETE FROM organization_member_roles
				WHERE organization_id = $1 AND user_id = $2 AND role_id = ANY($3)
			`, orgRowID, userID, drop); err != nil {
				return nil, nil, fmt.Errorf("remove member roles: %w", err)
			}
		}
	}

	for _, n := range names {
		if _, ok := held[n]; ok {
			continue
		}
		assigned = append(assigned, n)
		held[n] = ids[n]
	}
	if len(held) > MaxOrganizationRolesPerMember {
		return nil, nil, ErrOrganizationRoleLimitReached
	}
	for _, n := range assigned {
		if _, err := tx.Exec(ctx, `
			INSERT INTO organization_member_roles
			    (organization_id, user_id, role_id, application_id, tenant_id, granted_by)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT DO NOTHING
		`, orgRowID, userID, ids[n], sc.AppRowID, sc.TenantID, grantedBy); err != nil {
			if isCheckViolation(err) {
				return nil, nil, fmt.Errorf("%w: %s", ErrRoleNotInApplication, n)
			}
			return nil, nil, fmt.Errorf("grant member role: %w", err)
		}
	}
	if assigned == nil {
		assigned = []string{}
	}
	if removed == nil {
		removed = []string{}
	}
	return assigned, removed, nil
}

// RemoveMemberRole removes one organisation role from a member.
func (s *OrganizationService) RemoveMemberRole(ctx context.Context, sc OrganizationScope, ref string, userID int64, roleName string) (*MemberRolesResult, error) {
	if err := s.guard(); err != nil {
		return nil, err
	}
	org, err := s.getOrganization(ctx, s.pool, sc, ref, false)
	if err != nil {
		return nil, err
	}
	if _, err := s.getMember(ctx, s.pool, sc, org.rowID, userID); err != nil {
		return nil, err
	}
	ct, err := s.pool.Exec(ctx, `
		DELETE FROM organization_member_roles omr
		USING roles r
		WHERE omr.role_id = r.id AND omr.organization_id = $1 AND omr.user_id = $2 AND r.name = $3
	`, org.rowID, userID, strings.TrimSpace(roleName))
	if err != nil {
		return nil, fmt.Errorf("remove member role: %w", err)
	}
	removed := []string{}
	if ct.RowsAffected() > 0 {
		removed = append(removed, strings.TrimSpace(roleName))
		if s.sessions != nil {
			s.sessions.DenyUserSessions(ctx, userID, sc.TenantID)
		}
	}
	m, err := s.getMember(ctx, s.pool, sc, org.rowID, userID)
	if err != nil {
		return nil, err
	}
	return &MemberRolesResult{UserID: m.UserID, Roles: m.Roles, Assigned: []string{}, Removed: removed}, nil
}

// ListUserMemberships returns every organisation in the application the user
// belongs to, with status and roles. activeOnly drops suspended memberships and
// deactivated organisations — the set a user may actually sign in to.
func (s *OrganizationService) ListUserMemberships(ctx context.Context, sc OrganizationScope, userID int64, activeOnly bool) ([]OrganizationMembership, error) {
	if err := s.guard(); err != nil {
		return nil, err
	}
	if err := requireApplicationUser(ctx, s.pool, sc, userID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT o.public_id, o.slug, o.display_name, m.status, m.joined_at,
		       COALESCE((SELECT ARRAY_AGG(r.name ORDER BY omr.granted_at, r.id)
		                 FROM organization_member_roles omr
		                 JOIN roles r ON r.id = omr.role_id AND r.deleted_at IS NULL
		                 WHERE omr.organization_id = m.organization_id AND omr.user_id = m.user_id),
		                '{}')
		FROM organization_members m
		JOIN organizations o ON o.id = m.organization_id AND o.deleted_at IS NULL
		WHERE m.user_id = $1 AND m.tenant_id = $2 AND m.application_id = $3
		  AND (NOT $4 OR (m.status = 'active' AND o.is_active = true))
		ORDER BY o.display_name, o.id
	`, userID, sc.TenantID, sc.AppRowID, activeOnly)
	if err != nil {
		return nil, fmt.Errorf("list memberships: %w", err)
	}
	defer rows.Close()
	out := []OrganizationMembership{}
	for rows.Next() {
		var m OrganizationMembership
		if err := rows.Scan(&m.Organization.ID, &m.Organization.Slug, &m.Organization.DisplayName,
			&m.Status, &m.JoinedAt, &m.Roles); err != nil {
			return nil, fmt.Errorf("scan membership: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate memberships: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Mint support — read by AuthService on every organisation-aware token mint.
// ---------------------------------------------------------------------------

// mintOrganization is the organisation half of a token: who the session is
// signed in to, and what the user may do there.
type mintOrganization struct {
	rowID       int64
	publicID    string
	slug        string
	roles       []string
	permissions []string
}

// resolveOrganizationRowID maps a public id or slug to an active organisation of
// the application. Every failure is ErrOrganizationAccessDenied.
func (s *OrganizationService) resolveOrganizationRowID(ctx context.Context, appRowID int64, ref string) (int64, error) {
	byID, value := organizationRefArgs(ref)
	if value == "" {
		return 0, ErrOrganizationAccessDenied
	}
	var id int64
	err := s.pool.QueryRow(ctx, `
		SELECT id FROM organizations
		WHERE application_id = $1 AND deleted_at IS NULL AND is_active = true
		  AND `+map[bool]string{true: "public_id = $2", false: "slug = $2"}[byID],
		appRowID, value).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrOrganizationAccessDenied
		}
		return 0, fmt.Errorf("%w: resolve organization: %v", ErrOrganizationUnavailable, err)
	}
	return id, nil
}

// loadMintOrganization returns the organisation claims for a user, re-checking
// everything a session depends on: the organisation is live and active, belongs
// to the application, and the user is an active member. Any miss is
// ErrOrganizationAccessDenied; a read failure is ErrOrganizationUnavailable.
func (s *OrganizationService) loadMintOrganization(ctx context.Context, orgRowID, userID, appRowID int64) (*mintOrganization, error) {
	m := &mintOrganization{rowID: orgRowID}
	err := s.pool.QueryRow(ctx, `
		SELECT o.public_id, o.slug
		FROM organizations o
		JOIN organization_members mem ON mem.organization_id = o.id
		WHERE o.id = $1 AND o.application_id = $3
		  AND o.deleted_at IS NULL AND o.is_active = true
		  AND mem.user_id = $2 AND mem.status = 'active'
	`, orgRowID, userID, appRowID).Scan(&m.publicID, &m.slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrOrganizationAccessDenied
		}
		return nil, fmt.Errorf("%w: load organization: %v", ErrOrganizationUnavailable, err)
	}

	if err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(ARRAY_AGG(r.name ORDER BY omr.granted_at, r.id), '{}')
		FROM organization_member_roles omr
		JOIN roles r ON r.id = omr.role_id AND r.deleted_at IS NULL
		WHERE omr.organization_id = $1 AND omr.user_id = $2
	`, orgRowID, userID).Scan(&m.roles); err != nil {
		return nil, fmt.Errorf("%w: load organization roles: %v", ErrOrganizationUnavailable, err)
	}

	if err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(ARRAY_AGG(DISTINCT p.name ORDER BY p.name), '{}')
		FROM organization_member_roles omr
		JOIN roles r            ON r.id = omr.role_id AND r.deleted_at IS NULL
		JOIN role_permissions rp ON rp.role_id = r.id
		JOIN permissions p       ON p.id = rp.permission_id AND p.deleted_at IS NULL
		WHERE omr.organization_id = $1 AND omr.user_id = $2
	`, orgRowID, userID).Scan(&m.permissions); err != nil {
		return nil, fmt.Errorf("%w: load organization permissions: %v", ErrOrganizationUnavailable, err)
	}
	return m, nil
}

// activeMembershipRefs lists the organisations a user may sign in to.
func (s *OrganizationService) activeMembershipRefs(ctx context.Context, userID, appRowID int64) ([]OrganizationRef, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT o.id, o.public_id, o.slug, o.display_name
		FROM organization_members m
		JOIN organizations o ON o.id = m.organization_id
		WHERE m.user_id = $1 AND m.application_id = $2 AND m.status = 'active'
		  AND o.deleted_at IS NULL AND o.is_active = true
		ORDER BY o.display_name, o.id
	`, userID, appRowID)
	if err != nil {
		return nil, fmt.Errorf("%w: list memberships: %v", ErrOrganizationUnavailable, err)
	}
	defer rows.Close()
	var out []OrganizationRef
	for rows.Next() {
		var r OrganizationRef
		if err := rows.Scan(&r.rowID, &r.ID, &r.Slug, &r.DisplayName); err != nil {
			return nil, fmt.Errorf("%w: scan membership: %v", ErrOrganizationUnavailable, err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate memberships: %v", ErrOrganizationUnavailable, err)
	}
	return out, nil
}

// userApplicationID returns the application a user belongs to, nil for a
// tenant-level user.
func (s *OrganizationService) userApplicationID(ctx context.Context, userID int64) (*int64, error) {
	var appID *int64
	if err := s.pool.QueryRow(ctx, `SELECT application_id FROM users WHERE id = $1`, userID).Scan(&appID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrOrganizationAccessDenied
		}
		return nil, fmt.Errorf("%w: load user application: %v", ErrOrganizationUnavailable, err)
	}
	return appID, nil
}

// OrganizationDecision is the outcome of resolving which organisation a new
// session belongs to.
type OrganizationDecision struct {
	// OrgRowID is the organisation the session is bound to; nil for none.
	OrgRowID *int64
	// Choices is non-empty when the user must pick one.
	Choices []OrganizationRef

	// applies is false when organisations do not apply to this sign-in at all
	// (mode 'off' or a tenant-level user), so the mint can keep its metrics
	// silent for every application that has not opted in.
	applies bool
}

// DecideOrganization resolves the organisation a NEW session for userID in
// appRowID belongs to.
//
//   - Deployment switch off, mode 'off', or a tenant-level user (not one of the
//     application's own users): no organisation. A requested one is ignored
//     and counted, never an error, so a client sending the parameter early
//     cannot break sign-in.
//   - A requested organisation must be one the user may sign in to.
//   - personal asks for no organisation explicitly; refused in 'required'.
//   - Nothing requested: 'optional' gives no organisation; 'required' picks the
//     only membership, asks for a choice among several, and refuses with none.
func (s *OrganizationService) DecideOrganization(ctx context.Context, userID, appRowID int64, requested string, personal bool) (*OrganizationDecision, error) {
	requested = strings.TrimSpace(requested)
	mode, err := s.ApplicationMode(ctx, appRowID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOrganizationUnavailable, err)
	}
	if mode == OrganizationsModeOff {
		if requested != "" {
			countOrganizationParamIgnored()
		}
		return &OrganizationDecision{}, nil
	}
	userApp, err := s.userApplicationID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if userApp == nil || *userApp != appRowID {
		if requested != "" {
			countOrganizationParamIgnored()
		}
		return &OrganizationDecision{}, nil
	}

	if requested != "" {
		orgRowID, err := s.resolveOrganizationRowID(ctx, appRowID, requested)
		if err != nil {
			return nil, err
		}
		if _, err := s.loadMintOrganization(ctx, orgRowID, userID, appRowID); err != nil {
			return nil, err
		}
		return &OrganizationDecision{OrgRowID: &orgRowID, applies: true}, nil
	}
	if personal {
		if mode == OrganizationsModeRequired {
			return nil, ErrOrganizationAccessDenied
		}
		return &OrganizationDecision{applies: true}, nil
	}
	if mode == OrganizationsModeOptional {
		return &OrganizationDecision{applies: true}, nil
	}

	refs, err := s.activeMembershipRefs(ctx, userID, appRowID)
	if err != nil {
		return nil, err
	}
	switch len(refs) {
	case 0:
		return nil, ErrOrganizationAccessDenied
	case 1:
		id := refs[0].rowID
		return &OrganizationDecision{OrgRowID: &id, applies: true}, nil
	default:
		return &OrganizationDecision{Choices: refs, applies: true}, nil
	}
}

// RowID is the organisation's internal id, for audit attribution
// (audit.Event.OrganizationID). It never appears in an API response.
func (o *Organization) RowID() int64 { return o.rowID }
