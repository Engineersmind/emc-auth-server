package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

const (
	// ClientIDPrefix is prepended to every generated client_id so they are
	// immediately recognisable and distinguishable from other token types.
	ClientIDPrefix = "app_"

	clientIDBytes     = 16 // 16 random bytes → 22-char base64url client_id
	clientSecretBytes = 32 // 32 random bytes → 43-char base64url client_secret
)

// ErrInvalidClient is returned when client_id or client_secret do not match a
// live application record.
var ErrInvalidClient = errors.New("invalid client credentials")

// ErrAppNotFound is returned when an application does not exist within the
// caller's tenant (or has been deactivated).
var ErrAppNotFound = errors.New("application not found")

// ErrInvalidAppType is returned when an unknown application type is supplied.
var ErrInvalidAppType = errors.New("invalid app_type — must be one of: web, spa, m2m, native")

// ErrInvalidScope is returned when a scope string is neither a reserved OIDC
// scope nor a resource:action permission scope, or the list exceeds limits.
var ErrInvalidScope = errors.New("invalid scope — each scope must be a reserved OIDC scope (openid, profile, email, offline_access) or a resource:action string (max 50 scopes, 100 chars each)")

// validAppTypes mirrors the CHECK constraint on oauth_clients.app_type.
var validAppTypes = map[string]bool{"web": true, "spa": true, "m2m": true, "native": true}

const (
	maxScopesPerApp = 50
	maxScopeLen     = 100
)

// OIDC scope names (OIDC Core §5.4). These have no colon and therefore cannot
// satisfy the resource:action rule below — which is why, before issue #6,
// validateScopes rejected the very values migration 00032 sets as the DEFAULT
// for oauth_clients.scopes. The column's own default was unwritable through the
// API. Two namespaces share this column and both are legal:
//
//	OIDC scopes        openid, profile, email, offline_access
//	                   → decide which claims appear in the ID token and userinfo
//	Permission scopes  users:read, apps:write
//	                   → become the permissions claim on a client_credentials token
//
// Kept in one column rather than split: service.go's client_credentials path
// already reads `scopes` for permissions, and forking the storage would mean
// forking that read too. The token minter routes each namespace to the right
// claim instead.
const (
	// ScopeOpenID is the marker that turns an OAuth request into an OIDC one.
	// Its presence is what makes an ID token appear in the token response.
	ScopeOpenID = "openid"
	// ScopeProfile releases name, given_name, family_name and updated_at.
	ScopeProfile = "profile"
	// ScopeEmail releases email and email_verified.
	ScopeEmail = "email"
	// ScopeOfflineAccess requests a refresh token. Recorded and echoed back, but
	// refresh-token issuance is currently governed by the client's grant_types
	// rather than by this scope — see the #6 plan, §9.
	ScopeOfflineAccess = "offline_access"
)

// reservedOIDCScopes is the allow-list checked before the resource:action rule.
// Closed on purpose: an open "anything without a colon is an OIDC scope" rule
// would silently accept typos like "prof1le" and then never release the claims
// the caller expected, failing as missing data rather than as an error.
var reservedOIDCScopes = map[string]bool{
	ScopeOpenID:        true,
	ScopeProfile:       true,
	ScopeEmail:         true,
	ScopeOfflineAccess: true,
}

// IsOIDCScope reports whether a scope belongs to the reserved OIDC namespace.
func IsOIDCScope(scope string) bool { return reservedOIDCScopes[scope] }

// validateScopes accepts a reserved OIDC scope, or a resource:action string in
// the shape the permission system expects so scopes flow into the permissions
// claim in the format permission guards already read. A nil/empty slice is
// valid (no scopes).
func validateScopes(scopes []string) error {
	if len(scopes) > maxScopesPerApp {
		return ErrInvalidScope
	}
	for _, sc := range scopes {
		if sc == "" || len(sc) > maxScopeLen {
			return ErrInvalidScope
		}
		if reservedOIDCScopes[sc] {
			continue
		}
		resource, action, found := strings.Cut(sc, ":")
		if !found || resource == "" || action == "" {
			return ErrInvalidScope
		}
	}
	return nil
}

// maxRedirectURIs bounds the allow-list so a misbehaving admin cannot turn the
// exact-match scan at /oauth/authorize into an unbounded loop. Matches the
// limit identityprovider.go already applies to redirect_allow.
const maxRedirectURIs = 20

// ErrInvalidClientRedirectURI is returned when an entry in a client's
// registered redirect_uris is not an absolute http(s) URL, carries a fragment,
// or the list exceeds maxRedirectURIs.
//
// Named apart from identityprovider.go's ErrInvalidRedirectURI because the two
// govern different columns: this one oauth_clients.redirect_uris (the
// authorization code flow), that one identity_provider_configs.redirect_allow
// (where a social login hands back a login_code).
var ErrInvalidClientRedirectURI = errors.New("invalid redirect_uri — each entry must be an absolute http(s) URL without a fragment (max 20 entries)")

// validateRedirectURIs checks the values stored in oauth_clients.redirect_uris,
// the exact-match allow-list for GET /oauth/authorize.
//
// The column has existed since migration 00032 and was never written or read
// until issue #6. It is NOT identity_provider_configs.redirect_allow, which is
// per social provider and governs where a login_code is handed back.
//
// Fragments are rejected because RFC 6749 §3.1.2 forbids them in a registered
// redirection endpoint, and because a fragment never reaches the server — an
// entry carrying one could never be matched, so accepting it would register a
// URI that silently fails every comparison.
func validateRedirectURIs(uris []string) error {
	if len(uris) > maxRedirectURIs {
		return ErrInvalidClientRedirectURI
	}
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil {
			return ErrInvalidClientRedirectURI
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return ErrInvalidClientRedirectURI
		}
		if u.Host == "" {
			return ErrInvalidClientRedirectURI
		}
		if u.Fragment != "" || strings.Contains(raw, "#") {
			return ErrInvalidClientRedirectURI
		}
	}
	return nil
}

// normalizeAppType applies the default type and validates against validAppTypes.
func normalizeAppType(appType string) (string, error) {
	if appType == "" {
		return "web", nil
	}
	if !validAppTypes[appType] {
		return "", ErrInvalidAppType
	}
	return appType, nil
}

// ApplicationService manages OAuth2 client application lifecycle.
// Each tenant registers applications that receive a client_id / client_secret pair.
// The raw client_secret is returned once at creation and never stored — only its
// SHA-256 hash is persisted (same policy as API keys and refresh tokens).
type ApplicationService struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger
}

// NewApplicationService constructs an ApplicationService.
func NewApplicationService(pool *pgxpool.Pool, logger zerolog.Logger) *ApplicationService {
	return &ApplicationService{pool: pool, logger: logger}
}

// AppResult is returned by CreateApplication and RotateSecret.
// ClientSecret is shown exactly once and never stored in plaintext.
type AppResult struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	AppType      string    `json:"app_type"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	Scopes       []string  `json:"scopes"`
	RedirectURIs []string  `json:"redirect_uris"`
	RequirePKCE  bool      `json:"require_pkce"`
	FirstParty   bool      `json:"first_party"`
	CreatedAt    time.Time `json:"created_at"`
}

// AppSummary is returned by ListApplications — no secret ever included.
type AppSummary struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	AppType   string    `json:"app_type"`
	ClientID  string    `json:"client_id"`
	CreatedAt time.Time `json:"created_at"`
}

// AppDetail is the full public representation of one application — no secret.
type AppDetail struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	AppType  string   `json:"app_type"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
	// RedirectURIs is the exact-match allow-list for GET /oauth/authorize
	// (issue #6). Empty means the application cannot use the authorization
	// code flow at all — which is the correct default for the m2m app_type.
	RedirectURIs []string `json:"redirect_uris"`
	// RequirePKCE defaults true for every client type, confidential included.
	RequirePKCE bool `json:"require_pkce"`
	// FirstParty false means a consent screen is required before a code may be
	// issued. No consent screen exists yet, so /oauth/authorize refuses such a
	// client outright rather than skipping consent silently.
	FirstParty bool      `json:"first_party"`
	IsActive   bool      `json:"is_active"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// AppFilter holds optional filter and pagination params for ListApplicationsPaginated.
type AppFilter struct {
	Search string // ILIKE match on name and client_id; empty = no filter
	Type   string // "web", "spa", "m2m", "native", or "" for all
	Status string // "active", "inactive", or "" for all
	Page   int    // 1-based; defaults to 1
	Limit  int    // rows per page; defaults to 25, max 100
	// OnlyIDs restricts the page to these application ids. It is the server-side
	// half of application-scoped administration (issue #97): a co-owner may list
	// the tenant's applications, but must see only the ones granted to them.
	//
	// nil means unrestricted. An EMPTY non-nil slice means nothing matches — the
	// fail-closed reading, and the right one for a co-owner whose last grant was
	// revoked. Do not collapse the two.
	OnlyIDs []int64
}

// AppsPage wraps a paginated application list.
type AppsPage struct {
	Data       []AppDetail `json:"data"`
	Total      int         `json:"total"`
	Page       int         `json:"page"`
	TotalPages int         `json:"total_pages"`
	PerPage    int         `json:"per_page"`
}

// generateClientCredentials mints a fresh client_id + client_secret pair.
func generateClientCredentials() (clientID, rawSecret string, err error) {
	cidbuf := make([]byte, clientIDBytes)
	if _, err := rand.Read(cidbuf); err != nil {
		return "", "", fmt.Errorf("generate client_id: %w", err)
	}
	secbuf := make([]byte, clientSecretBytes)
	if _, err := rand.Read(secbuf); err != nil {
		return "", "", fmt.Errorf("generate client_secret: %w", err)
	}
	return ClientIDPrefix + base64.RawURLEncoding.EncodeToString(cidbuf),
		base64.RawURLEncoding.EncodeToString(secbuf), nil
}

// CreateApplication registers a new application for a tenant and returns its
// client credentials. The raw client_secret must be stored by the caller; it
// cannot be recovered after this call. appType defaults to "web" when empty.
// Scopes become the permissions claim of client_credentials tokens; nil/empty
// means the app's tokens carry no grants until scopes are set via update.
func (s *ApplicationService) CreateApplication(ctx context.Context, tenantID int64, name, appType string, scopes []string) (*AppResult, error) {
	return s.CreateApplicationWithOptions(ctx, tenantID, name, appType, scopes, AppUpdate{})
}

// CreateApplicationWithOptions is CreateApplication plus the OAuth
// authorization-server fields added in issue #6. A nil AppUpdate field takes
// the column default: no redirect URIs, PKCE required, first-party.
func (s *ApplicationService) CreateApplicationWithOptions(ctx context.Context, tenantID int64, name, appType string, scopes []string, opts AppUpdate) (*AppResult, error) {
	if name == "" {
		return nil, fmt.Errorf("application name is required")
	}
	normType, err := normalizeAppType(appType)
	if err != nil {
		return nil, err
	}
	if err := validateScopes(scopes); err != nil {
		return nil, err
	}
	if err := validateRedirectURIs(opts.RedirectURIs); err != nil {
		return nil, err
	}
	if scopes == nil {
		scopes = []string{}
	}
	redirectURIs := opts.RedirectURIs
	if redirectURIs == nil {
		redirectURIs = []string{}
	}
	// Defaults mirror the column defaults in migration 00067 rather than being
	// re-derived here, so there is one answer to "what does a new client get".
	requirePKCE := true
	if opts.RequirePKCE != nil {
		requirePKCE = *opts.RequirePKCE
	}
	firstParty := true
	if opts.FirstParty != nil {
		firstParty = *opts.FirstParty
	}

	clientID, rawSecret, err := generateClientCredentials()
	if err != nil {
		return nil, err
	}
	secretHash := HashToken(rawSecret)

	var rowID int64
	var createdAt time.Time
	err = s.pool.QueryRow(ctx, `
		INSERT INTO oauth_clients
		    (tenant_id, name, app_type, client_id, client_secret_hash, scopes,
		     redirect_uris, require_pkce, first_party, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
		RETURNING id, created_at
	`, tenantID, name, normType, clientID, secretHash, scopes,
		redirectURIs, requirePKCE, firstParty).Scan(&rowID, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("insert application: %w", err)
	}

	return &AppResult{
		ID:           strconv.FormatInt(rowID, 10),
		Name:         name,
		AppType:      normType,
		ClientID:     clientID,
		ClientSecret: rawSecret,
		Scopes:       scopes,
		RedirectURIs: redirectURIs,
		RequirePKCE:  requirePKCE,
		FirstParty:   firstParty,
		CreatedAt:    createdAt,
	}, nil
}

// ListApplications returns all active applications for a tenant, without secrets.
func (s *ApplicationService) ListApplications(ctx context.Context, tenantID int64) ([]AppSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, app_type, client_id, created_at
		FROM   oauth_clients
		WHERE  tenant_id = $1 AND deleted_at IS NULL
		ORDER  BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list applications: %w", err)
	}
	defer rows.Close()

	apps := []AppSummary{}
	for rows.Next() {
		var a AppSummary
		var id int64
		if err := rows.Scan(&id, &a.Name, &a.AppType, &a.ClientID, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan application: %w", err)
		}
		a.ID = strconv.FormatInt(id, 10)
		apps = append(apps, a)
	}
	return apps, rows.Err()
}

// ListApplicationsPaginated returns a filtered, paginated page of a tenant's
// applications (active and inactive), without secrets.
func (s *ApplicationService) ListApplicationsPaginated(ctx context.Context, tenantID int64, f AppFilter) (*AppsPage, error) {
	if f.Page < 1 {
		f.Page = 1
	}
	if f.Limit < 1 {
		f.Limit = 25
	}
	if f.Limit > 100 {
		f.Limit = 100
	}
	if f.Type != "" && !validAppTypes[f.Type] {
		return nil, ErrInvalidAppType
	}

	// Dynamic WHERE clause built exclusively from positional parameters.
	where := "WHERE tenant_id = $1"
	args := []interface{}{tenantID}

	if f.Search != "" {
		args = append(args, "%"+f.Search+"%")
		n := strconv.Itoa(len(args))
		where += " AND (name ILIKE $" + n + " OR client_id ILIKE $" + n + ")"
	}
	if f.Type != "" {
		args = append(args, f.Type)
		where += " AND app_type = $" + strconv.Itoa(len(args))
	}
	// Applied to the COUNT as well as the page, so an app-scoped administrator's
	// total reflects what they can actually see rather than the tenant's size.
	if f.OnlyIDs != nil {
		args = append(args, f.OnlyIDs)
		where += " AND id = ANY($" + strconv.Itoa(len(args)) + ")"
	}
	switch f.Status {
	case "active":
		where += " AND deleted_at IS NULL"
	case "inactive":
		where += " AND deleted_at IS NOT NULL"
	case "":
		// no status filter — include both
	default:
		return nil, fmt.Errorf("invalid status — must be \"active\", \"inactive\", or empty")
	}

	var total int
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM oauth_clients "+where, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count applications: %w", err)
	}

	args = append(args, f.Limit, (f.Page-1)*f.Limit)
	query := `
		SELECT id, name, app_type, client_id, (deleted_at IS NULL) AS is_active, created_at, updated_at
		FROM   oauth_clients ` + where + `
		ORDER  BY created_at DESC
		LIMIT  $` + strconv.Itoa(len(args)-1) + ` OFFSET $` + strconv.Itoa(len(args))
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list applications page: %w", err)
	}
	defer rows.Close()

	data := []AppDetail{}
	for rows.Next() {
		var a AppDetail
		var id int64
		if err := rows.Scan(&id, &a.Name, &a.AppType, &a.ClientID, &a.IsActive, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan application page: %w", err)
		}
		a.ID = strconv.FormatInt(id, 10)
		data = append(data, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate applications page: %w", err)
	}

	totalPages := (total + f.Limit - 1) / f.Limit
	if totalPages == 0 {
		totalPages = 1
	}
	return &AppsPage{
		Data:       data,
		Total:      total,
		Page:       f.Page,
		TotalPages: totalPages,
		PerPage:    f.Limit,
	}, nil
}

// GetApplication returns one application (active or inactive) by ID within a tenant.
func (s *ApplicationService) GetApplication(ctx context.Context, tenantID, appID int64) (*AppDetail, error) {
	var a AppDetail
	var id int64
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, app_type, client_id, scopes, redirect_uris, require_pkce, first_party,
		       (deleted_at IS NULL) AS is_active, created_at, updated_at
		FROM   oauth_clients
		WHERE  id = $1 AND tenant_id = $2
	`, appID, tenantID).Scan(&id, &a.Name, &a.AppType, &a.ClientID, &a.Scopes,
		&a.RedirectURIs, &a.RequirePKCE, &a.FirstParty, &a.IsActive, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAppNotFound
		}
		return nil, fmt.Errorf("get application: %w", err)
	}
	if a.Scopes == nil {
		a.Scopes = []string{}
	}
	if a.RedirectURIs == nil {
		a.RedirectURIs = []string{}
	}
	a.ID = strconv.FormatInt(id, 10)
	return &a, nil
}

// UpdateApplication updates an active application's name, app_type, and/or
// scopes. Empty name/app_type are left unchanged; a nil scopes slice leaves
// scopes unchanged, while an empty non-nil slice clears them. Returns the
// updated application. Scope changes affect tokens issued from then on —
// already-issued tokens keep their permissions until they expire (≤15 min).
// AppUpdate carries the optional fields of UpdateApplication that were added
// after its original signature. A struct rather than more positional
// parameters: RequirePKCE and FirstParty are booleans whose "leave unchanged"
// state is distinct from both true and false, which positional bools cannot
// express.
type AppUpdate struct {
	// RedirectURIs nil leaves the list unchanged; an empty non-nil slice clears
	// it, matching how scopes already behaves.
	RedirectURIs []string
	// RequirePKCE / FirstParty nil leaves the flag unchanged.
	RequirePKCE *bool
	FirstParty  *bool
}

// UpdateApplication updates name, app_type and/or scopes only. Retained with
// its original signature so the many existing callers are untouched; new
// fields go through UpdateApplicationWithOptions.
func (s *ApplicationService) UpdateApplication(ctx context.Context, tenantID, appID int64, name, appType string, scopes []string) (*AppDetail, error) {
	return s.UpdateApplicationWithOptions(ctx, tenantID, appID, name, appType, scopes, AppUpdate{})
}

// UpdateApplicationWithOptions is UpdateApplication plus the OAuth
// authorization-server fields added in issue #6.
func (s *ApplicationService) UpdateApplicationWithOptions(ctx context.Context, tenantID, appID int64, name, appType string, scopes []string, upd AppUpdate) (*AppDetail, error) {
	if name == "" && appType == "" && scopes == nil &&
		upd.RedirectURIs == nil && upd.RequirePKCE == nil && upd.FirstParty == nil {
		return nil, fmt.Errorf("nothing to update — provide name, app_type, scopes, redirect_uris, require_pkce, and/or first_party")
	}
	if appType != "" {
		if _, err := normalizeAppType(appType); err != nil {
			return nil, err
		}
	}
	if err := validateScopes(scopes); err != nil {
		return nil, err
	}
	if err := validateRedirectURIs(upd.RedirectURIs); err != nil {
		return nil, err
	}

	tag, err := s.pool.Exec(ctx, `
		UPDATE oauth_clients
		SET    name          = COALESCE(NULLIF($1, ''), name),
		       app_type      = COALESCE(NULLIF($2, ''), app_type),
		       scopes        = COALESCE($3, scopes),
		       redirect_uris = COALESCE($6, redirect_uris),
		       require_pkce  = COALESCE($7, require_pkce),
		       first_party   = COALESCE($8, first_party),
		       updated_at    = NOW()
		WHERE  id = $4 AND tenant_id = $5 AND deleted_at IS NULL
	`, name, appType, scopes, appID, tenantID, upd.RedirectURIs, upd.RequirePKCE, upd.FirstParty)
	if err != nil {
		return nil, fmt.Errorf("update application: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrAppNotFound
	}
	return s.GetApplication(ctx, tenantID, appID)
}

// RotateSecret replaces an active application's client_secret with a freshly
// generated one and returns it. The old secret stops working immediately; the
// new plaintext is shown exactly once (only its SHA-256 hash is stored).
// The client_id is left unchanged so integrations only swap the secret.
func (s *ApplicationService) RotateSecret(ctx context.Context, tenantID, appID int64) (*AppResult, error) {
	secbuf := make([]byte, clientSecretBytes)
	if _, err := rand.Read(secbuf); err != nil {
		return nil, fmt.Errorf("generate client_secret: %w", err)
	}
	rawSecret := base64.RawURLEncoding.EncodeToString(secbuf)

	var result AppResult
	var id int64
	// redirect_uris / require_pkce / first_party are returned too: AppResult
	// carries them since issue #6, and scanning only the original columns would
	// report require_pkce=false and first_party=false for every rotation —
	// a response body that contradicts the row it just wrote.
	err := s.pool.QueryRow(ctx, `
		UPDATE oauth_clients
		SET    client_secret_hash = $1, updated_at = NOW()
		WHERE  id = $2 AND tenant_id = $3 AND deleted_at IS NULL
		RETURNING id, name, app_type, client_id, scopes, redirect_uris,
		          require_pkce, first_party, created_at
	`, HashToken(rawSecret), appID, tenantID).Scan(&id, &result.Name, &result.AppType,
		&result.ClientID, &result.Scopes, &result.RedirectURIs,
		&result.RequirePKCE, &result.FirstParty, &result.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAppNotFound
		}
		return nil, fmt.Errorf("rotate client_secret: %w", err)
	}
	if result.Scopes == nil {
		result.Scopes = []string{}
	}
	if result.RedirectURIs == nil {
		result.RedirectURIs = []string{}
	}
	result.ID = strconv.FormatInt(id, 10)
	result.ClientSecret = rawSecret
	return &result, nil
}

// DeactivateApplication soft-deletes an application by setting deleted_at.
// The application's client_id immediately stops being accepted on login/register.
func (s *ApplicationService) DeactivateApplication(ctx context.Context, tenantID, appID int64) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE oauth_clients
		SET    deleted_at = NOW()
		WHERE  id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`, appID, tenantID)
	if err != nil {
		return fmt.Errorf("deactivate application: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAppNotFound
	}
	return nil
}

// ValidateClientID confirms that a client_id belongs to the given tenant and is
// active. Returns the application's row id so callers can stamp it into the JWT.
func (s *ApplicationService) ValidateClientID(ctx context.Context, tenantID int64, clientID string) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `
		SELECT id
		FROM   oauth_clients
		WHERE  tenant_id = $1 AND client_id = $2 AND deleted_at IS NULL
	`, tenantID, clientID).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("invalid client_id")
		}
		return 0, fmt.Errorf("validate client_id: %w", err)
	}
	return id, nil
}

// ResolveClient looks up an application by its public client_id alone (no
// secret check), returning the tenant id and application row id. Used only to
// attribute audit events for application-scoped flows — including failures —
// so the trail always carries the tenant + application the request targeted.
// Cheap indexed lookup; ok=false when the client_id is unknown.
func (s *ApplicationService) ResolveClient(ctx context.Context, clientID string) (tenantID, appID int64, ok bool) {
	if clientID == "" {
		return 0, 0, false
	}
	err := s.pool.QueryRow(ctx, `
		SELECT tenant_id, id
		FROM   oauth_clients
		WHERE  client_id = $1 AND deleted_at IS NULL
	`, clientID).Scan(&tenantID, &appID)
	if err != nil {
		return 0, 0, false
	}
	return tenantID, appID, true
}

// AuthenticateClient validates client_id + client_secret for the
// client_credentials grant. Returns the tenant id and application row id.
func (s *ApplicationService) AuthenticateClient(ctx context.Context, clientID, clientSecret string) (tenantID, appID int64, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT id, tenant_id
		FROM   oauth_clients
		WHERE  client_id = $1 AND client_secret_hash = $2 AND deleted_at IS NULL
	`, clientID, HashToken(clientSecret)).Scan(&appID, &tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, 0, ErrInvalidClient
		}
		return 0, 0, fmt.Errorf("authenticate client: %w", err)
	}
	return tenantID, appID, nil
}
