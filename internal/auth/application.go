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

	"github.com/engineersmind/emc-auth-server/internal/mailer"
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

// appTypeM2M is the machine-to-machine client type: a backend service with no
// user and no redirect, authenticating with client_credentials. It is the default
// for new applications here.
const appTypeM2M = "m2m"

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

// grantTypesForAppType derives the OAuth grants a client type may use.
//
// Until now every application took the column default
// {authorization_code, refresh_token} whatever its declared type, so an
// application created as "m2m" could not perform the client_credentials grant at
// all: /oauth/token refused it at the GrantTypes check, with nothing pointing at
// the type as the cause. The failure appeared only when a backend service tried
// to fetch its first token.
//
//   - m2m has no user and no redirect, so client_credentials is the only grant
//     that applies. refresh_token is excluded deliberately -- RFC 6749 §4.4.3 says
//     a client_credentials response MUST NOT include a refresh token, and the
//     client can request a new access token with credentials it already holds.
//   - web, spa and native are user-facing redirect flows: authorization_code,
//     plus refresh_token so the user is not re-prompted.
func grantTypesForAppType(appType string) []string {
	if appType == appTypeM2M {
		return []string{"client_credentials"}
	}
	return []string{"authorization_code", "refresh_token"}
}

// isPublicClient reports whether a client type cannot keep a secret.
//
// spa runs in a browser and native ships to a user's device, so any embedded
// secret is readable by that user; RFC 8252 §8.1 and the OAuth browser-app BCP
// treat both as public clients that authenticate with PKCE alone. web and m2m run
// on servers the operator controls and are confidential.
func isPublicClient(appType string) bool {
	return appType == "spa" || appType == "native"
}

// normalizeAppType applies the default type and validates against validAppTypes.
//
// The default is m2m: every application registered in this system is a backend
// service using the client_credentials grant. Defaulting to web instead handed
// such a service authorization_code + refresh_token -- grants it can never
// exercise -- so an omitted app_type produced a client that could not get a token.
func normalizeAppType(appType string) (string, error) {
	if appType == "" {
		return appTypeM2M, nil
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
	ID   string `json:"id"`
	Name string `json:"name"`
	// DisplayName is the optional end-user-facing label. Empty means fall back to
	// Name, which is what every read does — so a consumer can render DisplayName
	// or Name without checking which is set.
	DisplayName string   `json:"display_name"`
	AppType     string   `json:"app_type"`
	ClientID    string   `json:"client_id"`
	Scopes      []string `json:"scopes"`
	// RedirectURIs is the exact-match allow-list for GET /oauth/authorize
	// (issue #6). Empty means the application cannot use the authorization
	// code flow at all — which is the correct default for the m2m app_type.
	RedirectURIs []string `json:"redirect_uris"`
	// RequirePKCE defaults true for every client type, confidential included.
	RequirePKCE bool `json:"require_pkce"`
	// FirstParty false means a consent screen is required before a code may be
	// issued. No consent screen exists yet, so /oauth/authorize refuses such a
	// client outright rather than skipping consent silently.
	FirstParty bool `json:"first_party"`
	// GrantTypes is derived from AppType, never set directly: /oauth/token
	// enforces it, so it is the field that decides whether the application can get
	// a token at all. Exposed read-only because an operator debugging a refused
	// token request has no other way to see it.
	GrantTypes []string  `json:"grant_types"`
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
	// Defaults follow from the declared type rather than from the column
	// defaults, so choosing a type yields a client that can actually perform that
	// type's flow.
	//
	// PKCE: a public client has no secret, so PKCE is the only thing binding an
	// authorization code to the client that requested it -- not overridable there.
	// m2m has no authorization code at all, so PKCE does not apply and claiming
	// otherwise would misdescribe the row. Only the confidential redirect flow
	// leaves the choice to the caller.
	requirePKCE := true
	switch {
	case normType == appTypeM2M:
		requirePKCE = false
	case isPublicClient(normType):
		requirePKCE = true
	case opts.RequirePKCE != nil:
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

	// One transaction: the application and its email suppression rows are the same
	// fact. Inserting the client and then failing to seed would leave an
	// application sending all thirteen kinds of mail — the exact state this is
	// meant to prevent, and invisible until a user registered.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin create application tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var rowID int64
	var createdAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO oauth_clients
		    (tenant_id, name, app_type, client_id, client_secret_hash, scopes,
		     redirect_uris, require_pkce, first_party, grant_types, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
		RETURNING id, created_at
	`, tenantID, name, normType, clientID, secretHash, scopes,
		redirectURIs, requirePKCE, firstParty, grantTypesForAppType(normType)).Scan(&rowID, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("insert application: %w", err)
	}

	if err = seedSuppressedEmailTemplates(ctx, tx, tenantID, rowID); err != nil {
		return nil, err
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit create application tx: %w", err)
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
		-- is_active must reflect BOTH conditions that make a client unusable: the
		-- stored suspension flag AND the soft delete. Reading the column alone
		-- reported a deleted application as active, because DeactivateApplication
		-- sets deleted_at and never touches is_active.
		SELECT id, name, app_type, client_id, (is_active AND deleted_at IS NULL) AS is_active,
		       created_at, updated_at
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
		SELECT id, name, COALESCE(NULLIF(display_name, ''), name) AS display_name,
		       app_type, client_id, scopes, redirect_uris, require_pkce, first_party,
		       grant_types, (is_active AND deleted_at IS NULL) AS is_active,
		       created_at, updated_at
		FROM   oauth_clients
		WHERE  id = $1 AND tenant_id = $2
	`, appID, tenantID).Scan(&id, &a.Name, &a.DisplayName, &a.AppType, &a.ClientID, &a.Scopes,
		&a.RedirectURIs, &a.RequirePKCE, &a.FirstParty, &a.GrantTypes, &a.IsActive, &a.CreatedAt, &a.UpdatedAt)
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
	// DisplayName empty leaves it unchanged. Clearing it back to "fall back to
	// name" is therefore not expressible here yet; that needs a *string tri-state,
	// the same limitation UpdateTenant carries.
	DisplayName string
	// RequirePKCE / FirstParty nil leaves the flag unchanged.
	RequirePKCE *bool
	FirstParty  *bool
	// IsActive nil leaves the flag unchanged. False suspends the application:
	// its client credentials stop authenticating, while the row, its client_id
	// and its audit history are preserved — unlike DeactivateApplication, which
	// soft-deletes. Reversible by setting it back to true.
	IsActive *bool
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
		upd.RedirectURIs == nil && upd.RequirePKCE == nil && upd.FirstParty == nil &&
		upd.IsActive == nil && upd.DisplayName == "" {
		return nil, fmt.Errorf("nothing to update — provide name, display_name, app_type, scopes, redirect_uris, require_pkce, first_party, and/or is_active")
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

	// Changing the type re-derives grant_types, because the two cannot disagree:
	// a row left as authorization_code after being switched to m2m describes a
	// client /oauth/token will refuse. nil when the type is unchanged, so COALESCE
	// keeps whatever the row already had.
	var newGrantTypes []string
	if appType != "" {
		newGrantTypes = grantTypesForAppType(appType)
	}

	// A type change re-derives require_pkce for the same reason it re-derives
	// grant_types: the flag describes a property of the type's flow, not a
	// standalone preference. Converting a web/spa client to m2m used to leave
	// require_pkce = true on a row with no authorization-code flow at all — the
	// exact contradiction CreateApplicationWithOptions forces false to avoid — and
	// converting m2m to spa left it false on a public client that has nothing else
	// binding a code to its requester.
	//
	// The rule matches the create path exactly: m2m false, public true, and only
	// the confidential redirect flow (web) leaves the choice to the caller. An
	// explicit upd.RequirePKCE therefore still wins on a web type change and is
	// still honoured when the type is unchanged (pkceOverride nil), so no existing
	// caller loses control of the flag.
	pkceOverride := upd.RequirePKCE
	if appType != "" {
		derived := true
		switch {
		case appType == appTypeM2M:
			derived = false
			pkceOverride = &derived
		case isPublicClient(appType):
			pkceOverride = &derived
		}
	}

	tag, err := s.pool.Exec(ctx, `
		UPDATE oauth_clients
		SET    name          = COALESCE(NULLIF($1, ''), name),
		       app_type      = COALESCE(NULLIF($2, ''), app_type),
		       scopes        = COALESCE($3, scopes),
		       redirect_uris = COALESCE($6, redirect_uris),
		       require_pkce  = COALESCE($7, require_pkce),
		       first_party   = COALESCE($8, first_party),
		       is_active     = COALESCE($9, is_active),
		       grant_types   = COALESCE($10, grant_types),
		       display_name  = COALESCE(NULLIF($11, ''), display_name),
		       updated_at    = NOW()
		WHERE  id = $4 AND tenant_id = $5 AND deleted_at IS NULL
	`, name, appType, scopes, appID, tenantID, upd.RedirectURIs, pkceOverride, upd.FirstParty, upd.IsActive, newGrantTypes, upd.DisplayName)
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
//
// Deliberately does NOT filter on is_active. A suspended application's rejected
// token attempts still have to be attributed to their tenant and application —
// dropping them from the audit trail would blind the operator exactly when a
// suspended client starts retrying. Callers that must refuse a suspended client
// (AuthenticateClient, LookupClient, the social-login resolve) enforce that
// themselves.
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
		WHERE  client_id = $1 AND client_secret_hash = $2 AND deleted_at IS NULL AND is_active
	`, clientID, HashToken(clientSecret)).Scan(&appID, &tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, 0, ErrInvalidClient
		}
		return 0, 0, fmt.Errorf("authenticate client: %w", err)
	}
	return tenantID, appID, nil
}

// seedSuppressedEmailTemplates disables every customizable email type for a
// newly created application.
//
// Email delivery is opt-in per application (migration 00073). A new application
// is a blank slate: it sends nothing until its operator turns a template on.
// Without these rows, absence in email_templates means "send the built-in
// default" (migration 00060), so creating an application silently switched on
// every kind of outbound mail — verification, reset, MFA codes, invitations —
// before anyone had configured a sender or asked for it.
//
// The rows carry EMPTY bodies rather than a copy of the built-in default, and
// that distinction is the whole design:
//
//   - EmailTemplateService.Resolve filters is_active = true, so an inactive row
//     is invisible to content resolution. Enabling the row later returns the
//     MAINTAINED default, which keeps receiving improvements.
//   - Seeding the default's content instead would fork it at today's wording,
//     permanently — the trap the admin UI warns about when disabling a default.
//   - IsTypeEnabled reads is_active alone, so suppression works regardless of
//     what the bodies hold.
//
// mailer.AllTemplateTypes is the source of truth: it already excludes types that
// are not operator-customizable, and a type added there is suppressed here
// automatically rather than quietly defaulting to on.
//
// Takes a tx because it must commit with the application row. An application
// that exists while its suppression rows do not is precisely the state this
// prevents, and it would be invisible until a user registered.
func seedSuppressedEmailTemplates(ctx context.Context, tx pgx.Tx, tenantID, appRowID int64) error {
	types := make([]string, 0, len(mailer.AllTemplateTypes))
	for _, tt := range mailer.AllTemplateTypes {
		types = append(types, string(tt))
	}

	// One statement over the whole set: thirteen round trips inside the
	// application-creation transaction would hold it open for no reason.
	//
	// ON CONFLICT DO NOTHING for idempotency. The partial unique index
	// email_templates_app_key covers exactly this shape, so a retry — or a caller
	// that seeds twice — cannot fail on a duplicate and cannot overwrite a
	// template an operator has already configured.
	if _, err := tx.Exec(ctx, `
		INSERT INTO email_templates
		    (tenant_id, application_id, template_type, subject, html_body, text_body, is_active)
		SELECT $1, $2, t, '', '', '', false
		FROM unnest($3::text[]) AS t
		ON CONFLICT DO NOTHING
	`, tenantID, appRowID, types); err != nil {
		return fmt.Errorf("seed suppressed email templates: %w", err)
	}
	return nil
}
