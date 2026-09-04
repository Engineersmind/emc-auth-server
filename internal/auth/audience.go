package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// Per-application audiences and the explicit grants that permit them —
// issue #131, part 2 of 3 for CLAUDE.md deferred #10.
//
// WHAT THIS CLOSES
//
// Before #131 the "aud" claim was byte-identical across every application in a
// tenant, so a Marketing Site token passed a Payroll API's textbook validation:
// signature ok (same tenant signing key), iss ok, exp ok, aud ok. The only claim
// that could have caught it was "app_id", and no JWT library knows to check a
// vendor claim. emc-insurance-platform hand-rolled middleware for exactly this
// reason, because we gave them no other option.
//
// #130 freed "aud" by moving the token type to "gty". This file puts a real
// audience in it, so the application boundary is enforced by every standard JWT
// library for free: one `audience:` config line replaces custom middleware.
//
// THE ONE RULE THAT DECIDES EVERYTHING
//
// Mandatory is not the same as caller-supplied. See ResolveMintAudience: a
// client that authenticates as itself needs no audience parameter, and a
// first-party portal flow carries no client identity at all and so cannot
// supply one. Getting this wrong is how the cutover breaks a live integrator
// and locks operators out of their own console.

const (
	// AudienceSchemeDefault is the scheme every audience identifier carries.
	//
	// The "://" is mandatory and the value is NOT fetchable: an audience is an
	// identifier, and nothing in this server or any resource server resolves it.
	// The scheme exists so it can never be mistaken for a URL that might be
	// dereferenced, which is the mistake that turns an audience check into an
	// SSRF.
	AudienceSchemeDefault = "api://"

	// audienceLabelMax bounds each of the two labels (tenant slug, app slug).
	// 40 characters each keeps a full identifier inside 100 characters, which is
	// short enough to read in a log line and to sit in a config file unwrapped.
	audienceLabelMax = 40

	// maxGrantsPerClient bounds how many audiences one client may hold grants
	// for. Not a security boundary — every grant is explicit and administrator-
	// created — but an unbounded list would be copied into memory on every token
	// mint, and a resource-server topology needing more than this is asking a
	// different question than "which APIs may this client call".
	maxGrantsPerClient = 50
)

var (
	// ErrInvalidAudienceFormat is returned when an audience identifier does not
	// match the required shape.
	ErrInvalidAudienceFormat = errors.New("invalid audience — must be <scheme><tenant-slug>/<app-slug>, lowercase alphanumeric and hyphens, each label 1-40 characters (e.g. api://acme/payroll-api)")

	// ErrReservedAudience is returned when a caller tries to register an
	// audience inside this server's own namespace.
	//
	// Refused in the service layer AS WELL AS by the CHECK constraint in
	// migration 00087, so an operator gets a sentence rather than a constraint
	// name. The constraint is what makes the invariant true for every writer
	// including psql; this is what makes the refusal legible.
	//
	// It is the highest-stakes validation in this file. Without it a tenant
	// registers api://emc-auth, receives a legitimately signed token bearing
	// this server's own management audience, and reaches the admin surface with
	// it — issue #84 reopened in a new form.
	ErrReservedAudience = errors.New("audience is reserved — the " + ReservedAudiencePrefix + " namespace belongs to the authorization server and cannot be registered by a tenant")

	// ErrAudienceTaken is returned when an audience identifier is already in
	// use, by a live client or by a deleted one.
	//
	// "or by a deleted one" is the whole point of the FULL unique index in
	// migration 00087: an audience is never recycled, because grants and tokens
	// outlive the client row and a reissued identifier would silently redirect
	// them to a different application.
	ErrAudienceTaken = errors.New("audience is already in use by another application")

	// ErrInvalidTarget is the RFC 8707 §2 error for a requested audience the
	// client may not have.
	//
	// ONE sentinel for every reason, deliberately: not granted, does not exist,
	// belongs to another tenant, client is deleted. Distinguishing them would
	// make this endpoint an oracle for which audiences exist across the whole
	// deployment — a caller could enumerate every tenant's API inventory by
	// diffing error messages. See resolveTargetGrant, which has exactly one
	// failure return for that reason.
	ErrInvalidTarget = errors.New("invalid_target: the requested audience is not granted to this client")

	// ErrGrantNotFound is returned by the admin API when a grant row does not
	// exist within the caller's tenant. Distinct from ErrInvalidTarget: this one
	// answers an authenticated administrator asking about their own tenant's
	// configuration, where a 404 leaks nothing they cannot already list.
	ErrGrantNotFound = errors.New("grant not found")

	// ErrTooManyGrants is returned when a client already holds maxGrantsPerClient.
	ErrTooManyGrants = fmt.Errorf("too many grants — a client may hold at most %d audience grants", maxGrantsPerClient)

	// ErrAudienceRequired is returned when a client has require_audience = true
	// but no audience could be resolved for the token about to be minted.
	//
	// This is the per-client enforcement switch from issue #131 §10, and it
	// defaults to false on every client so this migration changes no token that
	// is issued today. Rollback of the whole feature is flipping it back.
	ErrAudienceRequired = errors.New("this client requires an audience but none was resolved — grant the client an audience or pass one explicitly")
)

// AudienceService owns audience identifiers and the oauth_client_grants table.
type AudienceService struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger
	// scheme prefixes every generated and validated identifier. Held here rather
	// than read from a package global so the value is injected once at startup
	// (AUDIENCE_SCHEME) and a test can construct a service with its own.
	scheme string
	// pattern is the compiled format check for `scheme`. Compiled once at
	// construction: it is consulted on every audience write and on every
	// explicit audience request at the token endpoint.
	pattern *regexp.Regexp
}

// NewAudienceService constructs an AudienceService using AudienceSchemeDefault.
func NewAudienceService(pool *pgxpool.Pool, logger zerolog.Logger) *AudienceService {
	return &AudienceService{
		pool:    pool,
		logger:  logger,
		scheme:  AudienceSchemeDefault,
		pattern: audiencePattern(AudienceSchemeDefault),
	}
}

// WithScheme overrides the identifier scheme (AUDIENCE_SCHEME).
//
// An empty or malformed value is IGNORED rather than applied. The scheme is
// part of every audience already stored: accepting a bad one would mint tokens
// whose audience no resource server recognises, and every existing identifier
// would fail validation on its next write. A misconfiguration here must degrade
// to the default, not to an outage.
func (s *AudienceService) WithScheme(scheme string) *AudienceService {
	if !validAudienceScheme(scheme) {
		if scheme != "" {
			s.logger.Warn().Str("scheme", scheme).
				Msg("audience: ignoring malformed AUDIENCE_SCHEME, keeping " + AudienceSchemeDefault)
		}
		return s
	}
	s.scheme = scheme
	s.pattern = audiencePattern(scheme)
	return s
}

// Scheme returns the configured identifier scheme.
func (s *AudienceService) Scheme() string { return s.scheme }

// validAudienceScheme accepts only a lowercase alphanumeric scheme followed by
// "://" — the shape that cannot be confused with a path, a bare hostname, or a
// permission scope.
func validAudienceScheme(scheme string) bool {
	return regexp.MustCompile(`^[a-z][a-z0-9+.-]{0,15}://$`).MatchString(scheme)
}

// audiencePattern builds the format check for one scheme.
//
// Two labels separated by "/", each 1-40 characters of lowercase alphanumerics
// and interior hyphens. No underscores, no uppercase, no empty label, no
// leading or trailing hyphen — the same shape a DNS label allows, so an
// identifier can be pasted into a config file, a log query or a URL path
// without escaping.
func audiencePattern(scheme string) *regexp.Regexp {
	label := fmt.Sprintf(`[a-z0-9](?:[a-z0-9-]{0,%d}[a-z0-9])?`, audienceLabelMax-2)
	return regexp.MustCompile(`^` + regexp.QuoteMeta(scheme) + label + `/` + label + `$`)
}

// nonAlnumRun and edgeHyphens mirror migration 00087's backfill expression
// exactly:
//
//	lower(regexp_replace(regexp_replace(name, '[^a-zA-Z0-9]+', '-', 'g'),
//	                     '(^-+|-+$)', '', 'g'))
//
// They must stay in step. A Go slug that disagreed with the SQL one would mean
// an application created through the API got a different audience than the same
// name would have been backfilled to — the sort of divergence that is invisible
// until a resource server rejects a token nobody can explain.
var (
	nonAlnumRun  = regexp.MustCompile(`[^a-zA-Z0-9]+`)
	edgeHyphens  = regexp.MustCompile(`(^-+|-+$)`)
	audienceSlug = func(raw string) string {
		return edgeHyphens.ReplaceAllString(
			strings.ToLower(nonAlnumRun.ReplaceAllString(raw, "-")), "")
	}
)

// AudienceSlug renders one label of an audience identifier from free text.
//
// Exported for the admin API and the tests, which both need to predict what an
// application's audience will be before it is created.
func AudienceSlug(raw string) string { return audienceSlug(raw) }

// GenerateAudience builds the immutable identifier for one application.
//
// The app slug is TRUNCATED to audienceLabelMax rather than refused. Refusing
// would make a long application name un-creatable, which worked fine before
// #131 — a validation added for a new claim must not take away an existing
// ability. Truncation can collide with another long name sharing a prefix; the
// full unique index catches that and CreateApplicationWithOptions reports
// ErrAudienceTaken, which is a readable answer to a rare case.
//
// The tenant slug is NOT truncated. It identifies the tenant, and silently
// shortening it would put two tenants in one namespace — the one failure this
// whole scheme exists to prevent. An over-long tenant slug is an error.
func (s *AudienceService) GenerateAudience(tenantSlug, appName string) (string, error) {
	tenant := audienceSlug(tenantSlug)
	if tenant == "" || len(tenant) > audienceLabelMax {
		return "", ErrInvalidAudienceFormat
	}
	app := audienceSlug(appName)
	if len(app) > audienceLabelMax {
		app = strings.TrimRight(app[:audienceLabelMax], "-")
	}
	if app == "" {
		// A name that is entirely punctuation. Not an error at the application
		// level — the name itself is legal and the row is fine — so the caller
		// treats this as "no audience", exactly like a pre-#131 row. The token
		// simply carries no audience claim, which is valid while
		// require_audience is false.
		return "", nil
	}
	candidate := s.scheme + tenant + "/" + app
	if err := s.ValidateAudience(candidate); err != nil {
		return "", err
	}
	return candidate, nil
}

// ValidateAudience checks format and the reserved namespace, in that order.
//
// Order matters for the error the caller sees: a malformed value inside the
// reserved namespace should read as malformed, because that is the thing the
// caller has to fix first.
func (s *AudienceService) ValidateAudience(audience string) error {
	if !s.pattern.MatchString(audience) {
		return ErrInvalidAudienceFormat
	}
	if IsReservedAudience(audience) {
		return ErrReservedAudience
	}
	return nil
}

// IsReservedAudience reports whether an identifier falls inside the namespace
// reserved for this authorization server.
//
// Prefix, not equality, matching ReservedAudiencePrefix's own contract and the
// CHECK constraint in migration 00087: api://emc-auth-anything must be refused
// too, because a resource server comparing on a prefix would be fooled by it.
func IsReservedAudience(audience string) bool {
	return strings.HasPrefix(audience, ReservedAudiencePrefix)
}

// ---------------------------------------------------------------------------
// Grants — the admin surface (issue #131 stage C)
// ---------------------------------------------------------------------------

// ClientGrant is one row of oauth_client_grants: permission for one client to
// request one audience, and the scopes that grant carries.
type ClientGrant struct {
	ID string `json:"id"`
	// ApplicationID is the grantee — the client that may REQUEST this audience,
	// which is not necessarily the application that owns it.
	ApplicationID string   `json:"application_id"`
	Audience      string   `json:"audience"`
	Scopes        []string `json:"scopes"`
	// ResourceName is the name of the application that OWNS the audience, for
	// display. Read through the composite key, so it is always populated.
	ResourceName string    `json:"resource_name"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// AudienceEntry is one row of the tenant's audience catalogue — what an
// administrator picks from when creating a grant.
type AudienceEntry struct {
	Audience      string `json:"audience"`
	ApplicationID string `json:"application_id"`
	Name          string `json:"name"`
	// RequireAudience reports whether that application enforces audiences on
	// its own tokens. Surfaced because it is the switch an operator flips during
	// the #132 rollout and there is otherwise no way to read it back.
	RequireAudience bool `json:"require_audience"`
}

// ListAudiences returns every audience registered within one tenant.
//
// Scoped to the tenant, with no cross-tenant read: the catalogue is what an
// administrator grants FROM, and a tenant has no business enumerating another
// tenant's APIs. Soft-deleted applications are excluded — their identifiers
// stay reserved forever (the unique index) but they are not grantable.
func (s *AudienceService) ListAudiences(ctx context.Context, tenantID int64) ([]AudienceEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT audience, id, name, require_audience
		FROM   oauth_clients
		WHERE  tenant_id = $1 AND audience IS NOT NULL AND deleted_at IS NULL
		ORDER  BY audience
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list audiences: %w", err)
	}
	defer rows.Close()

	out := []AudienceEntry{}
	for rows.Next() {
		var e AudienceEntry
		var id int64
		if err := rows.Scan(&e.Audience, &id, &e.Name, &e.RequireAudience); err != nil {
			return nil, fmt.Errorf("scan audience: %w", err)
		}
		e.ApplicationID = strconv.FormatInt(id, 10)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListGrants returns the audiences one client is permitted to request.
func (s *AudienceService) ListGrants(ctx context.Context, tenantID, appRowID int64) ([]ClientGrant, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT g.id, g.client_id, g.audience, g.scopes, g.created_at, g.updated_at,
		       COALESCE(owner.name, '')
		FROM   oauth_client_grants g
		LEFT   JOIN oauth_clients owner
		       ON owner.tenant_id = g.tenant_id AND owner.audience = g.audience
		WHERE  g.tenant_id = $1 AND g.client_id = $2
		ORDER  BY g.audience
	`, tenantID, appRowID)
	if err != nil {
		return nil, fmt.Errorf("list client grants: %w", err)
	}
	defer rows.Close()

	out := []ClientGrant{}
	for rows.Next() {
		var g ClientGrant
		var id, clientID int64
		if err := rows.Scan(&id, &clientID, &g.Audience, &g.Scopes,
			&g.CreatedAt, &g.UpdatedAt, &g.ResourceName); err != nil {
			return nil, fmt.Errorf("scan client grant: %w", err)
		}
		g.ID = strconv.FormatInt(id, 10)
		g.ApplicationID = strconv.FormatInt(clientID, 10)
		if g.Scopes == nil {
			g.Scopes = []string{}
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// CreateGrant permits a client to request an audience.
//
// tenantID comes from the authenticated administrator, never from the request
// body, and is written into the row. The composite foreign key added in
// migration 00087 then makes a cross-tenant grant impossible at the database
// level: (tenant_id, audience) must name a real oauth_clients row, so a client
// in tenant A cannot be granted an audience owned by tenant B even if an
// operator writes the row by hand.
func (s *AudienceService) CreateGrant(ctx context.Context, tenantID, appRowID int64, audience string, scopes []string) (*ClientGrant, error) {
	if err := s.ValidateAudience(audience); err != nil {
		return nil, err
	}
	if err := validateScopes(scopes); err != nil {
		return nil, err
	}
	if scopes == nil {
		scopes = []string{}
	}

	var count int
	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM oauth_client_grants WHERE client_id = $1`, appRowID).Scan(&count); err != nil {
		return nil, fmt.Errorf("count client grants: %w", err)
	}
	if count >= maxGrantsPerClient {
		return nil, ErrTooManyGrants
	}

	var g ClientGrant
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO oauth_client_grants (tenant_id, client_id, audience, scopes)
		VALUES ($1, $2, $3, $4)
		RETURNING id, audience, scopes, created_at, updated_at
	`, tenantID, appRowID, audience, scopes).Scan(&id, &g.Audience, &g.Scopes, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		// The composite FK is the cross-tenant guard and a unique violation is a
		// duplicate grant. Both are caller errors, not server faults, so they are
		// translated rather than logged as failures.
		switch {
		case isForeignKeyViolation(err):
			return nil, ErrInvalidTarget
		case isUniqueViolation(err):
			return nil, fmt.Errorf("this client already has a grant for %s", audience)
		}
		return nil, fmt.Errorf("create client grant: %w", err)
	}
	g.ID = strconv.FormatInt(id, 10)
	g.ApplicationID = strconv.FormatInt(appRowID, 10)
	if g.Scopes == nil {
		g.Scopes = []string{}
	}
	return &g, nil
}

// UpdateGrant changes a grant's scopes.
//
// Only the scopes. The audience on an existing grant is not editable: an
// operator who wants a client to reach a different API creates that grant and
// deletes this one, which leaves an audit trail of two explicit decisions
// rather than one silent re-point of a grant a resource server may already be
// relying on.
func (s *AudienceService) UpdateGrant(ctx context.Context, tenantID, appRowID, grantID int64, scopes []string) (*ClientGrant, error) {
	if err := validateScopes(scopes); err != nil {
		return nil, err
	}
	if scopes == nil {
		scopes = []string{}
	}
	var g ClientGrant
	var id int64
	err := s.pool.QueryRow(ctx, `
		UPDATE oauth_client_grants
		SET    scopes = $1, updated_at = NOW()
		WHERE  id = $2 AND client_id = $3 AND tenant_id = $4
		RETURNING id, audience, scopes, created_at, updated_at
	`, scopes, grantID, appRowID, tenantID).Scan(&id, &g.Audience, &g.Scopes, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrGrantNotFound
		}
		return nil, fmt.Errorf("update client grant: %w", err)
	}
	g.ID = strconv.FormatInt(id, 10)
	g.ApplicationID = strconv.FormatInt(appRowID, 10)
	if g.Scopes == nil {
		g.Scopes = []string{}
	}
	return &g, nil
}

// DeleteGrant removes a grant.
//
// Tokens already minted for that audience keep working until they expire (15
// minutes for an access token). Revoking a grant is therefore not an immediate
// cut-off, and cannot be: an access token is self-contained and has no
// server-side record to invalidate. What it does stop is the next mint and
// every refresh — see ResolveMintAudience, which re-reads the grant on every
// rotation rather than trusting the pinned value alone.
func (s *AudienceService) DeleteGrant(ctx context.Context, tenantID, appRowID, grantID int64) error {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM oauth_client_grants
		WHERE id = $1 AND client_id = $2 AND tenant_id = $3
	`, grantID, appRowID, tenantID)
	if err != nil {
		return fmt.Errorf("delete client grant: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrGrantNotFound
	}
	return nil
}

// ---------------------------------------------------------------------------
// Resolution and enforcement (issue #131 stages D and E)
// ---------------------------------------------------------------------------

// MintAudience is the resolved audience for one token, and how it was reached.
type MintAudience struct {
	// Value is the "aud" claim to sign. EMPTY means omit the claim — the
	// pre-#131 behaviour, still valid while require_audience is false.
	Value string
	// GrantedScopes is the grant's scope list when an explicit audience was
	// requested, and nil otherwise. nil means "no grant-level narrowing
	// applies", which is NOT the same as an empty slice: an empty slice from a
	// real grant means the grant permits no scopes at all.
	GrantedScopes []string
	// Source records which case of the resolution table applied, for logs and
	// for the tests that assert the table is actually implemented.
	Source AudienceSource
}

// AudienceSource enumerates the four resolution cases. See ResolveMintAudience.
type AudienceSource string

const (
	// AudienceSourceRequested — the caller passed `audience` or RFC 8707
	// `resource`, and holds a grant for it.
	AudienceSourceRequested AudienceSource = "requested"
	// AudienceSourceClientSelf — a client authenticated as itself and asked for
	// nothing, so it gets its own API's identifier. This is the case that keeps
	// a live integrator working with zero changes.
	AudienceSourceClientSelf AudienceSource = "client_self"
	// AudienceSourceServer — no client identity on the request at all, so the
	// server assigns its own audience. The admin console signs in this way.
	AudienceSourceServer AudienceSource = "server"
	// AudienceSourceNone — the client has no stored audience (a pre-migration
	// row, or a name that slugified to nothing). The claim is omitted.
	AudienceSourceNone AudienceSource = "none"
	// AudienceSourcePinned — a refresh rotation reusing the audience its chain
	// was issued with. A refresh can never change an audience.
	AudienceSourcePinned AudienceSource = "pinned"
)

// AudienceRequest is what ResolveMintAudience needs to decide.
type AudienceRequest struct {
	// AppRowID is oauth_clients.id, or 0 when no client identity is present.
	AppRowID int64
	// Requested is the explicit `audience` / `resource` parameter. Empty when
	// the caller did not ask for one — which is the common case and must not be
	// treated as an error.
	Requested string
	// Pinned is the audience already recorded on a refresh-token chain. When
	// set it wins over everything except an explicit request that matches it,
	// so a rotation cannot widen or move the audience.
	Pinned string
}

// ResolveMintAudience implements the resolution table from the issue #131 plan
// §7. It is the single most important function in this file.
//
//	| # | Case                                        | Audience used            |
//	|---|---------------------------------------------|--------------------------|
//	| 1 | explicit `audience` / `resource` parameter   | that value, if granted   |
//	| 2 | client authenticates as itself, no parameter | its own stored audience  |
//	| 3 | no client_id at all (first-party portal)     | AudienceSelf, server-set |
//	| 4 | client has no stored audience                | omit the claim           |
//
// Case 3 is not optional. The admin console signs in through
// POST /api/v1/auth/session with an email and a password, no client_id and no
// audience parameter, and never calls /oauth/token. It CANNOT supply an
// audience, so the server must assign one — where no client identity is on the
// request, the audience is the server's to assign.
//
// Case 2 is what keeps emc-insurance-platform working with zero changes.
//
// A pinned audience (a refresh rotation) short-circuits cases 2-4 but is still
// re-validated against the grant table when it was originally requested, so
// deleting a grant stops the chain at its next rotation rather than only at the
// next fresh login.
func (s *AudienceService) ResolveMintAudience(ctx context.Context, req AudienceRequest) (MintAudience, error) {
	// Case 3, checked first because it is decided by the ABSENCE of a client and
	// therefore cannot be confused with any of the others. A request with no
	// application context has nothing to look up and nothing to grant.
	if req.AppRowID == 0 {
		if req.Requested != "" && req.Requested != AudienceSelf {
			// A caller with no client identity asking for a tenant's audience.
			// There is no client to hold a grant, so there is nothing that could
			// permit it. Refused with the same sentinel as every other denial.
			s.countDenial("none", req.Requested)
			return MintAudience{}, ErrInvalidTarget
		}
		return MintAudience{Value: AudienceSelf, Source: AudienceSourceServer}, nil
	}

	client, err := s.loadClientAudience(ctx, req.AppRowID)
	if err != nil {
		return MintAudience{}, err
	}

	// Case 1 — an explicit request, or a pinned value that was itself explicit.
	// Both go through the grant check: the pinned path re-checks so a revoked
	// grant is enforced on the next rotation.
	requested := req.Requested
	if requested == "" && req.Pinned != "" && req.Pinned != client.audience {
		requested = req.Pinned
	}
	if requested != "" {
		if req.Pinned != "" && req.Requested != "" && req.Requested != req.Pinned {
			// A refresh that names a DIFFERENT audience than the chain holds.
			// Refused rather than honoured: the refresh token was issued for one
			// API, and letting a rotation move it would make the audience a
			// property of the last request rather than of the grant, which is
			// exactly the boundary #131 exists to draw.
			s.countDenial(client.clientID, req.Requested)
			return MintAudience{}, ErrInvalidTarget
		}
		scopes, err := s.resolveTargetGrant(ctx, req.AppRowID, client.clientID, requested)
		if err != nil {
			return MintAudience{}, err
		}
		source := AudienceSourceRequested
		if req.Requested == "" {
			source = AudienceSourcePinned
		}
		return MintAudience{Value: requested, GrantedScopes: scopes, Source: source}, nil
	}

	// Case 2 — the client's own audience. No grant lookup: the self-grant that
	// migration 00087 backfilled exists for the admin API's benefit, and
	// requiring it here would mean a client whose self-grant an operator deleted
	// could no longer authenticate to its own API, which is a foot-gun with no
	// upside.
	if client.audience != "" {
		return MintAudience{Value: client.audience, Source: AudienceSourceClientSelf}, nil
	}

	// Case 4 — nothing to put in the claim. Enforced only if the client asked
	// for enforcement.
	if client.requireAudience {
		return MintAudience{}, ErrAudienceRequired
	}
	return MintAudience{Source: AudienceSourceNone}, nil
}

// clientAudience is the audience-relevant part of an oauth_clients row.
type clientAudience struct {
	clientID        string
	audience        string
	requireAudience bool
	firstParty      bool
}

// loadClientAudience reads one client's audience configuration.
//
// deleted_at IS NULL is deliberately NOT filtered here. The caller has already
// authenticated this client (or redeemed a code bound to it), and a client
// soft-deleted in the microseconds since should fail on the authentication path
// rather than silently lose its audience and mint an unscoped token. Failing
// closed means the row is read as it stands.
func (s *AudienceService) loadClientAudience(ctx context.Context, appRowID int64) (clientAudience, error) {
	var c clientAudience
	var audience *string
	err := s.pool.QueryRow(ctx, `
		SELECT client_id, audience, require_audience, first_party
		FROM   oauth_clients
		WHERE  id = $1
	`, appRowID).Scan(&c.clientID, &audience, &c.requireAudience, &c.firstParty)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c, ErrAppNotFound
		}
		return c, fmt.Errorf("load client audience: %w", err)
	}
	if audience != nil {
		c.audience = *audience
	}
	return c, nil
}

// resolveTargetGrant is the enforcement point for an explicitly requested
// audience, and it has exactly ONE failure return.
//
// That is the design, not an accident of shape. RFC 8707 §2 gives one error
// code — invalid_target — and the response for "you have no grant for this"
// must be byte-identical to the response for "no such audience exists
// anywhere". Two distinguishable answers would let any client with credentials
// enumerate every audience in the deployment by diffing the errors, which is a
// map of every tenant's internal API surface.
//
// The counter is incremented HERE rather than at the caller, so no denial path
// can be added later that forgets it. A declared-but-never-incremented counter
// is exactly the state CLAUDE.md deferred #12 has been in for months.
func (s *AudienceService) resolveTargetGrant(ctx context.Context, appRowID int64, clientID, audience string) ([]string, error) {
	if !s.pattern.MatchString(audience) || IsReservedAudience(audience) {
		// Malformed or reserved: refused with the SAME error as an ungranted
		// one. Telling a caller "that is malformed" versus "that is not yours"
		// is itself a distinguishable answer, and the format is documented, so
		// a legitimate client learns nothing here it could not read in the docs.
		s.countDenial(clientID, audience)
		return nil, ErrInvalidTarget
	}
	var scopes []string
	err := s.pool.QueryRow(ctx, `
		SELECT g.scopes
		FROM   oauth_client_grants g
		JOIN   oauth_clients c ON c.id = g.client_id
		WHERE  g.client_id = $1
		  AND  g.audience  = $2
		  AND  g.tenant_id = c.tenant_id
	`, appRowID, audience).Scan(&scopes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			s.countDenial(clientID, audience)
			return nil, ErrInvalidTarget
		}
		return nil, fmt.Errorf("resolve audience grant: %w", err)
	}
	if scopes == nil {
		scopes = []string{}
	}
	return scopes, nil
}

// countDenial increments the grant-denial counter.
//
// The audience label carries the REQUESTED value, which is caller-controlled.
// That is a deliberate, bounded risk: Prometheus label cardinality is the cost,
// and without the value the counter cannot answer the only question worth
// asking of it — which audience is being refused to whom. The value is format-
// checked before most denials reach here, and an unbounded-cardinality attack
// on this series is visible in the same scrape it pollutes.
func (s *AudienceService) countDenial(clientID, audience string) {
	if clientID == "" {
		clientID = "none"
	}
	if audience == "" {
		audience = "none"
	}
	metrics.AudienceGrantDenials.WithLabelValues(clientID, audience).Inc()
}

// FilterPermissionsForClient narrows the internal permissions array for a
// non-first-party client — CLAUDE.md deferred #23.
//
// An OAuth access token minted by issueScopedTokenPair carries both the OAuth
// `scope` claim and the complete internal `permissions` array. That is harmless
// only while /oauth/authorize refuses first_party = false, so every grant
// belongs to a client the tenant owns. The moment the consent screen lands
// (deferred #19) and genuinely third-party clients become possible, shipping
// the full array is a data-leakage path: an external client receives internal
// permission strings that appeared on no consent screen and describe
// capabilities it was never granted.
//
// A THIRD-PARTY CLIENT GETS NOTHING, not a filtered subset. Intersecting
// permissions with granted scopes sounds tighter but is the wrong model: the
// two namespaces overlap only by coincidence (both can look like
// resource:action), so an intersection would leak whichever internal
// permissions happen to share a spelling with a granted scope. A third-party
// client's authority is its scopes; `permissions` is this server's own
// vocabulary and is not part of the contract with an external client.
func FilterPermissionsForClient(perms []string, firstParty bool) []string {
	if firstParty {
		return perms
	}
	return []string{}
}

// isForeignKeyViolation reports whether err is SQLSTATE 23503.
//
// On oauth_client_grants that means exactly one thing: the composite key
// (tenant_id, audience) named no oauth_clients row — a cross-tenant grant, or
// an audience that does not exist. Both are ErrInvalidTarget, and the database
// is the authority because it holds the invariant for every writer.
func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

// isCheckViolation reports whether err is SQLSTATE 23514.
//
// On oauth_clients that is oauth_clients_audience_not_reserved: something tried
// to write an audience inside the reserved namespace. The service layer refuses
// it first (ValidateAudience), so reaching here means a caller found another
// path to the column — which is precisely why the constraint exists.
func isCheckViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23514"
}

// IsFirstParty reports whether a client is first-party, for callers that hold
// only a row id. Errs towards FALSE — the narrower answer — on any failure, so
// a lookup fault strips permissions rather than leaking them.
func (s *AudienceService) IsFirstParty(ctx context.Context, appRowID int64) bool {
	if appRowID == 0 {
		// No client at all is a first-party portal flow, which is the one case
		// where a full permissions array is correct.
		return true
	}
	c, err := s.loadClientAudience(ctx, appRowID)
	if err != nil {
		s.logger.Warn().Err(err).Int64("app_row_id", appRowID).
			Msg("audience: first-party lookup failed, treating client as third-party")
		return false
	}
	return c.firstParty
}
