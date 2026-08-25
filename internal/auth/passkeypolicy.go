package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// ---------------------------------------------------------------------------
// Passkey policy — per-tenant and per-application WebAuthn configuration.
//
// Two things live here, and they are together because they are the same
// decision: WHETHER a passkey ceremony may run, and WHICH relying party it runs
// as. A credential is bound to an RP ID by the browser, so the second question
// is not configuration trivia — it is what keeps one tenant's passkeys from
// being offered on another tenant's domain.
//
// See migration 00072 for the table and for why the platform default is off.
// ---------------------------------------------------------------------------

// PasskeyPolicy is the resolved, ready-to-use policy for one scope. Every field
// is already merged with the server configuration, so a caller never has to
// decide whether a zero value means "inherit" — that is resolved here, once.
// Every field is tagged. This type is not internal-only: it is embedded as
// `effective` in PasskeyPolicyRecord, which the admin API returns, so untagged
// fields would ship Go identifiers (AllowPasskeys, RPID) on the wire instead of
// the snake_case names PASSKEY_API_CONTRACT.md documents and the console reads.
type PasskeyPolicy struct {
	// AllowPasskeys is the master switch. False refuses registration and
	// passwordless sign-in alike.
	AllowPasskeys bool `json:"allow_passkeys"`
	// AllowPasswordless gates sign-in specifically. False still permits
	// registration and management, so a tenant can hold passkeys as a
	// second factor without accepting them as the whole credential.
	AllowPasswordless bool `json:"allow_passwordless"`
	// RequireUserVerification demands a biometric or PIN gesture.
	RequireUserVerification bool `json:"require_user_verification"`
	// RPID is the relying-party ID actually in force: the registrable domain,
	// no scheme and no port.
	RPID string `json:"rp_id"`
	// RPDisplayName is what the authenticator shows the user.
	RPDisplayName string `json:"rp_display_name"`
	// Origins is the exact-match allow-list of page origins permitted to run a
	// ceremony, including scheme and port.
	Origins []string `json:"origins"`
	// MaxCredentialsPerUser caps live credentials per account.
	MaxCredentialsPerUser int `json:"max_credentials_per_user"`
	// Source records which row won resolution — "application", "tenant",
	// "platform", or "server" when no row matched at all. An operator debugging
	// "why is my RP ID wrong" needs to know which row answered, which is why it
	// is on the ADMIN response; it is never part of an end-user payload.
	Source string `json:"source"`
}

// AllowsOrigin reports whether a page origin may run a ceremony under this
// policy. Exact match including scheme and port, by design: a prefix or suffix
// match here is the whole attack — "https://acme.com.evil.net" ends with the
// tenant's domain and "https://acme.com" is a prefix of it.
func (p PasskeyPolicy) AllowsOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	for _, o := range p.Origins {
		if o == origin {
			return true
		}
	}
	return false
}

var (
	// ErrPasskeysNotAllowed is returned when policy forbids passkeys for the
	// caller's scope. Deliberately distinguishable from an authentication
	// failure: the ticket's acceptance criterion is that a disabled tenant gets
	// a clear error code rather than a generic 401, because "your organisation
	// has not enabled this" is actionable and "unauthorized" is not.
	ErrPasskeysNotAllowed = errors.New("passkeys are not enabled for this account")

	// ErrPasswordlessNotAllowed is returned when a tenant permits passkeys but
	// not as a standalone sign-in credential.
	ErrPasswordlessNotAllowed = errors.New("passkey sign-in is not enabled for this account")

	// ErrOriginNotAllowed is returned when the page running the ceremony is not
	// on the policy's origin allow-list. Caught here, before the ceremony
	// starts, because the alternative is a credential created for the wrong
	// relying party that the browser then silently never offers — a dead end the
	// user cannot diagnose.
	ErrOriginNotAllowed = errors.New("this origin is not permitted to use passkeys")

	// ErrTooManyCredentials is returned when the account is at its policy
	// ceiling. Not a security boundary on its own — it bounds what a stolen
	// session can quietly enrol, and keeps the user's own list reviewable.
	ErrTooManyCredentials = errors.New("this account has the maximum number of passkeys")
)

// PasskeyPolicyService resolves and caches passkey policy.
//
// Cached for the same reason session policy is: Resolve sits on the login page
// path, and a policy change measured in a minute is fast enough for a setting
// whose effect is measured in months. Unlike session policy, a failed lookup
// FAILS CLOSED — see Resolve.
type PasskeyPolicyService struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger

	// serverDefault is the WEBAUTHN_* environment configuration, used for any
	// field a matching row leaves NULL or empty.
	serverDefault WebAuthnConfig

	mu    sync.RWMutex
	cache map[passkeyPolicyKey]cachedPasskeyPolicy
	ttl   time.Duration
}

type passkeyPolicyKey struct {
	tenantID      int64
	applicationID int64  // 0 = no application scope
	origin        string // set only for origin-keyed lookups; empty otherwise
}

type cachedPasskeyPolicy struct {
	policy   PasskeyPolicy
	found    bool
	cachedAt time.Time
}

// passkeyPolicyCacheTTL is short on purpose. This gates an authentication
// method: an operator switching it off during an incident must see it take
// effect while they are still looking at the screen, and 30s of stale "allowed"
// is the outer bound of how wrong we are willing to be about that.
const passkeyPolicyCacheTTL = 30 * time.Second

// defaultMaxCredentialsPerUser mirrors the column default in migration 00072.
// Duplicated in Go because the origin-resolution path answers without reading a
// row at all, and a zero ceiling there would refuse every registration.
const defaultMaxCredentialsPerUser = 10

// NewPasskeyPolicyService creates a resolver over the given pool. serverDefault
// supplies the inherited RP configuration.
func NewPasskeyPolicyService(pool *pgxpool.Pool, serverDefault WebAuthnConfig, logger zerolog.Logger) *PasskeyPolicyService {
	return &PasskeyPolicyService{
		pool:          pool,
		logger:        logger,
		serverDefault: serverDefault,
		cache:         make(map[passkeyPolicyKey]cachedPasskeyPolicy),
		ttl:           passkeyPolicyCacheTTL,
	}
}

// Resolve returns the policy in force for a scope, most-specific-wins:
// application row → tenant row → platform-default row.
//
// Returns an error rather than a default when the table cannot be read, and
// callers refuse the request. This is the opposite of SessionPolicyService,
// which falls back to platform defaults, and the difference is deliberate:
// falling back there keeps people signed in, while falling back HERE would mean
// guessing at whether a tenant enabled an authentication method. Guessing
// "enabled" bypasses a tenant's MFA policy; guessing "disabled" costs a user
// their passkey button and leaves password login working. So we do not guess —
// we fail, and the failure degrades to the password form.
func (s *PasskeyPolicyService) Resolve(ctx context.Context, tenantID int64, applicationID *int64) (PasskeyPolicy, error) {
	if s == nil || s.pool == nil {
		return PasskeyPolicy{}, ErrWebAuthnNotConfigured
	}

	key := passkeyPolicyKey{tenantID: tenantID}
	if applicationID != nil {
		key.applicationID = *applicationID
	}

	s.mu.RLock()
	entry, ok := s.cache[key]
	s.mu.RUnlock()
	if ok && time.Since(entry.cachedAt) < s.ttl {
		return entry.policy, nil
	}

	row, source, err := s.loadByScope(ctx, tenantID, applicationID)
	if err != nil {
		return PasskeyPolicy{}, err
	}
	policy := s.merge(row, source)

	s.mu.Lock()
	s.cache[key] = cachedPasskeyPolicy{policy: policy, found: true, cachedAt: time.Now()}
	s.mu.Unlock()
	return policy, nil
}

// ResolveByOrigin returns the policy for the page running a ceremony, found by
// its origin.
//
// This exists because passwordless sign-in has no user to resolve a scope from:
// login/begin takes no email and no hint — that is what removes the enumeration
// oracle — so at that moment the only thing identifying the relying party is
// where the request came from. Which is also the correct answer: the RP IS the
// origin, as far as the browser is concerned.
//
// A row whose origins array contains the origin wins, most specific first. When
// nothing matches, the server configuration answers, but only if the origin is
// on the server's own allow-list — an unknown origin gets ErrOriginNotAllowed
// rather than the platform policy, so an unlisted domain cannot start ceremonies
// under whatever RP happens to be configured.
func (s *PasskeyPolicyService) ResolveByOrigin(ctx context.Context, origin string) (PasskeyPolicy, error) {
	if s == nil || s.pool == nil {
		return PasskeyPolicy{}, ErrWebAuthnNotConfigured
	}
	if origin == "" {
		return PasskeyPolicy{}, ErrOriginNotAllowed
	}

	key := passkeyPolicyKey{origin: origin}
	s.mu.RLock()
	entry, ok := s.cache[key]
	s.mu.RUnlock()
	if ok && time.Since(entry.cachedAt) < s.ttl {
		if !entry.found {
			return PasskeyPolicy{}, ErrOriginNotAllowed
		}
		return entry.policy, nil
	}

	row, source, err := s.loadByOrigin(ctx, origin)
	if err != nil {
		return PasskeyPolicy{}, err
	}

	var policy PasskeyPolicy
	found := true
	switch {
	case source != "":
		policy = s.merge(row, source)
	case s.originOnServerList(origin):
		// No tenant declared its own relying party for this origin, but the
		// deployment allows it — the single-RP case, where every tenant shares
		// the server's RP ID and therefore its origins.
		//
		// There is no tenant to resolve here and there cannot be: login/begin
		// takes no user identifier, which is what removes the enumeration
		// oracle. So the question this answers is deliberately weaker than
		// "is this tenant allowed" — it is "could ANYONE on this relying party
		// sign in with a passkey". If nobody can, there is no point minting a
		// challenge; if somebody can, we mint one and decide properly at
		// login/complete, against the tenant that owns the credential the
		// authenticator actually presents (see WebAuthnService.LoginComplete).
		//
		// That split is the design, not a shortcut. A permissive begin leaks
		// nothing — the challenge is a random nonce and the response reveals no
		// account — while the authoritative check happens where an account is
		// finally named.
		anyPasskeys, anyPasswordless, aerr := s.availabilityOnServerRP(ctx)
		if aerr != nil {
			return PasskeyPolicy{}, aerr
		}
		policy = PasskeyPolicy{
			// Reported as two separate answers rather than one combined "allowed",
			// so the caller can tell a tenant that has passkeys switched off from
			// one that keeps them as a second factor only. Collapsing them into a
			// single boolean made every refusal read as "passkeys_disabled", which
			// sends a user looking for the wrong setting.
			AllowPasskeys:     anyPasskeys,
			AllowPasswordless: anyPasswordless,
			// The server value, which merge() treats as a floor. The binding UV
			// decision is made at complete against the credential's own policy,
			// so a laxer value here cannot weaken a stricter tenant.
			RequireUserVerification: s.serverDefault.RequireUserVerification,
			RPID:                    s.serverDefault.RPID,
			RPDisplayName:           s.serverDefault.RPDisplayName,
			Origins:                 s.serverDefault.Origins,
			MaxCredentialsPerUser:   defaultMaxCredentialsPerUser,
			Source:                  "server",
		}
		if policy.RPDisplayName == "" {
			policy.RPDisplayName = policy.RPID
		}
	default:
		found = false
	}

	s.mu.Lock()
	s.cache[key] = cachedPasskeyPolicy{policy: policy, found: found, cachedAt: time.Now()}
	s.mu.Unlock()

	if !found {
		return PasskeyPolicy{}, ErrOriginNotAllowed
	}
	return policy, nil
}

// InvalidateCache drops every cached policy. Called by the admin write path so a
// tenant switching passkeys off does not have to wait out the TTL — the case
// that matters is switching OFF, during an incident.
//
// Drops everything rather than one key: a tenant-level change affects every
// application key beneath it and every origin key that resolved through it, and
// that set is not tracked. The cache refills within one request.
func (s *PasskeyPolicyService) InvalidateCache() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.cache = make(map[passkeyPolicyKey]cachedPasskeyPolicy)
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Administration
// ---------------------------------------------------------------------------

// PasskeyPolicyRecord is a stored policy row as an administrator sees it, with
// inherited fields left empty rather than filled in.
//
// Deliberately distinct from PasskeyPolicy: an admin editing a tenant row needs
// to see which fields that row actually sets and which it inherits, and a merged
// view cannot express the difference. Handing back a merged view would make
// every read look like an explicit override, and the next write would persist
// values the operator never chose.
type PasskeyPolicyRecord struct {
	// Scope is "platform", "tenant", or "application".
	Scope                   string `json:"scope"`
	TenantID                *int64 `json:"tenant_id,omitempty"`
	ApplicationID           *int64 `json:"application_id,omitempty"`
	Exists                  bool   `json:"exists"`
	AllowPasskeys           bool   `json:"allow_passkeys"`
	AllowPasswordless       bool   `json:"allow_passwordless"`
	RequireUserVerification bool   `json:"require_user_verification"`
	// RPID and Origins are empty when the row inherits them.
	RPID                  string   `json:"rp_id,omitempty"`
	RPDisplayName         string   `json:"rp_display_name,omitempty"`
	Origins               []string `json:"origins"`
	MaxCredentialsPerUser int      `json:"max_credentials_per_user"`
	// Effective is what the scope actually resolves to right now, after
	// inheritance. An operator needs both: what this row says, and what it means.
	Effective PasskeyPolicy `json:"effective"`
	UpdatedAt *time.Time    `json:"updated_at,omitempty"`
}

// ErrInvalidPasskeyPolicy is returned when a policy write is internally
// inconsistent — the same conditions the CHECK constraints in migration 00072
// enforce, caught here so an operator gets a sentence instead of a constraint
// name.
var ErrInvalidPasskeyPolicy = errors.New("origins may only be set together with rp_id, and max_credentials_per_user must be 1-100")

// PasskeyPolicyUpdate is a partial write. Nil fields keep their stored value, so
// an admin toggling one switch cannot silently reset the RP ID they never sent.
type PasskeyPolicyUpdate struct {
	AllowPasskeys           *bool
	AllowPasswordless       *bool
	RequireUserVerification *bool
	// RPID, RPDisplayName, and Origins use a pointer-to-value so that "" is a
	// deliberate clear-to-inherit and absent is leave-alone. A tenant reverting
	// to the server's relying party needs a way to say so.
	RPID                  *string
	RPDisplayName         *string
	Origins               *[]string
	MaxCredentialsPerUser *int
}

// GetPolicyRecord returns the stored row for exactly one scope, plus what that
// scope currently resolves to.
func (s *PasskeyPolicyService) GetPolicyRecord(ctx context.Context, tenantID *int64, applicationID *int64) (*PasskeyPolicyRecord, error) {
	rec := &PasskeyPolicyRecord{
		Scope: scopeName(tenantID, applicationID), TenantID: tenantID, ApplicationID: applicationID,
		Origins: []string{},
	}

	var row policyRow
	var updatedAt time.Time
	err := scanPolicyRow(s.pool.QueryRow(ctx, `
		SELECT `+passkeyPolicyColumns+`, updated_at
		FROM passkey_policies
		WHERE tenant_id IS NOT DISTINCT FROM $1
		  AND application_id IS NOT DISTINCT FROM $2
	`, tenantID, applicationID), &row, &updatedAt)
	switch {
	case err == nil:
		rec.Exists = true
		rec.AllowPasskeys = row.allowPasskeys
		rec.AllowPasswordless = row.allowPasswordless
		rec.RequireUserVerification = row.requireUV
		if row.rpID != nil {
			rec.RPID = *row.rpID
		}
		if row.rpDisplayName != nil {
			rec.RPDisplayName = *row.rpDisplayName
		}
		if row.origins != nil {
			rec.Origins = row.origins
		}
		rec.MaxCredentialsPerUser = row.maxCredentials
		rec.UpdatedAt = &updatedAt
	case errors.Is(err, pgx.ErrNoRows):
		// No row at this scope: everything is inherited. Reported honestly as
		// Exists=false rather than as a row full of zero values, which would read
		// as "explicitly disabled with no RP".
	default:
		return nil, fmt.Errorf("load passkey policy record: %w", err)
	}

	// The effective view resolves through inheritance. The platform scope has no
	// tenant to resolve for, so it reports its own row merged with server config.
	if tenantID != nil {
		eff, err := s.Resolve(ctx, *tenantID, applicationID)
		if err != nil {
			return nil, err
		}
		rec.Effective = eff
	} else {
		platform, err := s.loadPlatformDefault(ctx)
		if err != nil {
			return nil, err
		}
		rec.Effective = s.merge(platform, "platform")
	}
	return rec, nil
}

// SetPolicy upserts one scope's policy and drops the cache.
//
// The write is scoped by tenant_id in the conflict clause for the same reason
// the MFA policy write is: an application row that belongs to another tenant
// must filter the update to zero rows rather than being overwritten. Callers
// must still have verified that applicationID belongs to tenantID — this is a
// backstop, not the authorization check.
func (s *PasskeyPolicyService) SetPolicy(ctx context.Context, tenantID *int64, applicationID *int64, upd PasskeyPolicyUpdate) (*PasskeyPolicyRecord, error) {
	if applicationID != nil && tenantID == nil {
		return nil, ErrInvalidPasskeyPolicy
	}
	if upd.MaxCredentialsPerUser != nil && (*upd.MaxCredentialsPerUser < 1 || *upd.MaxCredentialsPerUser > 100) {
		return nil, ErrInvalidPasskeyPolicy
	}
	// Setting origins while clearing rp_id in the SAME call is contradictory, and
	// it is the caller's contradiction rather than an inherited-state problem — so
	// it is refused with the sentence ErrInvalidPasskeyPolicy carries instead of
	// being silently resolved one way or the other.
	if upd.RPID != nil && *upd.RPID == "" && upd.Origins != nil && len(*upd.Origins) > 0 {
		return nil, ErrInvalidPasskeyPolicy
	}

	// Normalise origins before they are stored, so the exact-match comparison at
	// ceremony time is against a canonical form rather than against whatever an
	// operator pasted. An entry that does not parse as an origin is rejected
	// rather than silently dropped: a half-saved allow-list is how a tenant ends
	// up with passkeys that work on one of their two domains.
	var origins *[]string
	if upd.Origins != nil {
		clean := make([]string, 0, len(*upd.Origins))
		for _, raw := range *upd.Origins {
			o := NormalizeOrigin(raw)
			if o == "" {
				return nil, fmt.Errorf("%w: %q is not a valid origin", ErrInvalidPasskeyPolicy, raw)
			}
			clean = append(clean, o)
		}
		origins = &clean
	}

	// Clearing rp_id clears the origins pair with it, whether or not the caller
	// mentioned origins.
	//
	// The two are one setting as far as the schema is concerned: constraint
	// passkey_policies_origins_need_rp_id (migration 00072) forbids a row with
	// origins and no rp_id, because an origin allow-list means nothing without
	// the relying party it is an allow-list FOR. So the documented
	// clear-to-inherit call — {"rp_id": ""} — would otherwise fail the constraint
	// on every row that has custom origins, and an operator reverting a tenant to
	// the server's relying party would get a database error for a legal request.
	// Clearing both is also the only coherent reading: a row that inherits its
	// relying party cannot keep a hand-written allow-list for a different one.
	if upd.RPID != nil && *upd.RPID == "" && origins == nil {
		empty := []string{}
		origins = &empty
	}

	// UPDATE then INSERT rather than one ON CONFLICT.
	//
	// The three scopes are enforced by three PARTIAL unique indexes (migration
	// 00072), and a single ON CONFLICT clause can only name one target — so an
	// upsert written that way would silently only work for whichever scope the
	// clause happened to name. Doing it in two statements inside a transaction is
	// longer and correct for all three.
	//
	// IS NOT DISTINCT FROM, not "=": the platform row has NULL in both columns
	// and equality never matches NULL, so a plain "=" would fail to find the row
	// it is meant to update and then fail to insert over it.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin passkey policy write: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tag, err := tx.Exec(ctx, `
		UPDATE passkey_policies SET
			allow_passkeys            = COALESCE($3::BOOLEAN, allow_passkeys),
			allow_passwordless        = COALESCE($4::BOOLEAN, allow_passwordless),
			require_user_verification = COALESCE($5::BOOLEAN, require_user_verification),
			rp_id                     = CASE WHEN $6::TEXT IS NULL THEN rp_id
			                                 ELSE NULLIF($6::TEXT, '') END,
			rp_display_name           = CASE WHEN $7::TEXT IS NULL THEN rp_display_name
			                                 ELSE NULLIF($7::TEXT, '') END,
			origins                   = COALESCE($8::TEXT[], origins),
			max_credentials_per_user  = COALESCE($9::INTEGER, max_credentials_per_user),
			updated_at                = NOW()
		WHERE tenant_id IS NOT DISTINCT FROM $1
		  AND application_id IS NOT DISTINCT FROM $2
	`, tenantID, applicationID, upd.AllowPasskeys, upd.AllowPasswordless,
		upd.RequireUserVerification, upd.RPID, upd.RPDisplayName, origins,
		upd.MaxCredentialsPerUser)
	if err != nil {
		return nil, fmt.Errorf("update passkey policy: %w", err)
	}

	if tag.RowsAffected() == 0 {
		// No row at this scope yet. Absent fields take the platform's shipping
		// defaults rather than being inherited: a row that exists is an explicit
		// override, and a half-explicit row whose meaning changed when the server
		// config changed would be the worst of both.
		if _, err := tx.Exec(ctx, `
			INSERT INTO passkey_policies (
				tenant_id, application_id, allow_passkeys, allow_passwordless,
				require_user_verification, rp_id, rp_display_name, origins,
				max_credentials_per_user, updated_at
			) VALUES (
				$1, $2,
				COALESCE($3::BOOLEAN, false), COALESCE($4::BOOLEAN, true),
				COALESCE($5::BOOLEAN, true),
				NULLIF($6::TEXT, ''), NULLIF($7::TEXT, ''),
				COALESCE($8::TEXT[], '{}'::TEXT[]), COALESCE($9::INTEGER, 10), NOW()
			)
		`, tenantID, applicationID, upd.AllowPasskeys, upd.AllowPasswordless,
			upd.RequireUserVerification, upd.RPID, upd.RPDisplayName, origins,
			upd.MaxCredentialsPerUser); err != nil {
			if isUniqueViolation(err) {
				// Another writer created the row between our UPDATE and our
				// INSERT. Reported rather than retried: the caller's own write
				// is a full statement of intent, and silently re-applying it
				// over somebody else's concurrent edit is how two admins in one
				// console produce a policy neither of them chose.
				return nil, fmt.Errorf("passkey policy was modified concurrently, please retry")
			}
			return nil, fmt.Errorf("insert passkey policy: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit passkey policy write: %w", err)
	}

	s.InvalidateCache()
	return s.GetPolicyRecord(ctx, tenantID, applicationID)
}

// DeletePolicy removes a scope's row so it inherits again. Reports whether a row
// was actually there, so an admin who expected an override to exist is told it
// did not rather than being shown a success for a no-op.
func (s *PasskeyPolicyService) DeletePolicy(ctx context.Context, tenantID *int64, applicationID *int64) (bool, error) {
	if tenantID == nil {
		// The platform row is what every other scope inherits from and what
		// resolution falls back to; deleting it would make every lookup fail
		// closed and switch passkeys off platform-wide. Reset it with SetPolicy
		// instead.
		return false, ErrInvalidPasskeyPolicy
	}
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM passkey_policies
		WHERE tenant_id IS NOT DISTINCT FROM $1
		  AND application_id IS NOT DISTINCT FROM $2
	`, tenantID, applicationID)
	if err != nil {
		return false, fmt.Errorf("delete passkey policy: %w", err)
	}
	s.InvalidateCache()
	return tag.RowsAffected() > 0, nil
}

func scopeName(tenantID, applicationID *int64) string {
	switch {
	case applicationID != nil:
		return "application"
	case tenantID != nil:
		return "tenant"
	default:
		return "platform"
	}
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

// policyRow is one passkey_policies row with its NULLs intact, before merging
// with server configuration.
type policyRow struct {
	allowPasskeys     bool
	allowPasswordless bool
	requireUV         bool
	rpID              *string
	rpDisplayName     *string
	origins           []string
	maxCredentials    int
}

const passkeyPolicyColumns = `allow_passkeys, allow_passwordless, require_user_verification,
	       rp_id, rp_display_name, origins, max_credentials_per_user`

func scanPolicyRow(row pgx.Row, out *policyRow, extra ...any) error {
	dest := []any{&out.allowPasskeys, &out.allowPasswordless, &out.requireUV,
		&out.rpID, &out.rpDisplayName, &out.origins, &out.maxCredentials}
	dest = append(dest, extra...)
	return row.Scan(dest...)
}

// loadByScope reads the most specific matching row.
//
// One query rather than up to three round trips: ORDER BY places the
// application row first, then the tenant row, then the platform default, and
// LIMIT 1 takes the winner. The CASE gives back which one won, because "your RP
// ID came from the tenant row, not the application row you just edited" is the
// first thing anybody needs when this is misconfigured.
func (s *PasskeyPolicyService) loadByScope(ctx context.Context, tenantID int64, applicationID *int64) (policyRow, string, error) {
	var row policyRow
	var source string
	err := scanPolicyRow(s.pool.QueryRow(ctx, `
		SELECT `+passkeyPolicyColumns+`,
		       CASE WHEN application_id IS NOT NULL THEN 'application'
		            WHEN tenant_id      IS NOT NULL THEN 'tenant'
		            ELSE 'platform' END
		FROM passkey_policies
		WHERE (application_id = $2 AND tenant_id = $1)
		   OR (application_id IS NULL AND tenant_id = $1)
		   OR (application_id IS NULL AND tenant_id IS NULL)
		ORDER BY application_id NULLS LAST, tenant_id NULLS LAST
		LIMIT 1
	`, tenantID, applicationID), &row, &source)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The platform-default row is seeded by migration 00072, so this
			// means somebody deleted it. Refuse rather than invent a policy: an
			// absent switch must not read as "on".
			return row, "", fmt.Errorf("no passkey policy row matched (platform default missing?): %w", ErrPasskeysNotAllowed)
		}
		return row, "", fmt.Errorf("load passkey policy: %w", err)
	}
	return row, source, nil
}

// loadByOrigin finds the most specific row that claims the given origin. An
// empty source means no row claimed it, which is not an error.
func (s *PasskeyPolicyService) loadByOrigin(ctx context.Context, origin string) (policyRow, string, error) {
	var row policyRow
	var source string
	err := scanPolicyRow(s.pool.QueryRow(ctx, `
		SELECT `+passkeyPolicyColumns+`,
		       CASE WHEN application_id IS NOT NULL THEN 'application'
		            ELSE 'tenant' END
		FROM passkey_policies
		WHERE $1 = ANY(origins)
		ORDER BY application_id NULLS LAST, tenant_id NULLS LAST
		LIMIT 1
	`, origin), &row, &source)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return row, "", nil
		}
		return row, "", fmt.Errorf("load passkey policy by origin: %w", err)
	}
	return row, source, nil
}

// availabilityOnServerRP reports whether ANY scope running under the SERVER's
// relying party permits passkeys at all, and whether any permits passwordless
// sign-in.
//
// rp_id IS NULL is the filter that means "inherits the server's relying party".
// A tenant that declared its own RP ID is a different relying party and its
// credentials are not assertable here, so including it would mint challenges on
// behalf of tenants whose users could never answer them.
//
// No rows at all yields false, false, which switches passkeys off rather than
// erroring. That is the direction to fail in, and it is not the confusing
// failure it looks like — a deployment with no policy rows has not enabled the
// feature.
func (s *PasskeyPolicyService) availabilityOnServerRP(ctx context.Context) (anyPasskeys, anyPasswordless bool, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT COALESCE(bool_or(allow_passkeys), false),
		       COALESCE(bool_or(allow_passkeys AND allow_passwordless), false)
		FROM passkey_policies
		WHERE rp_id IS NULL
	`).Scan(&anyPasskeys, &anyPasswordless)
	if err != nil {
		return false, false, fmt.Errorf("check passkey availability on server relying party: %w", err)
	}
	return anyPasskeys, anyPasswordless, nil
}

// loadPlatformDefault reads the NULL/NULL row.
func (s *PasskeyPolicyService) loadPlatformDefault(ctx context.Context) (policyRow, error) {
	var row policyRow
	err := scanPolicyRow(s.pool.QueryRow(ctx, `
		SELECT `+passkeyPolicyColumns+`
		FROM passkey_policies
		WHERE tenant_id IS NULL AND application_id IS NULL
	`), &row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return row, fmt.Errorf("platform passkey policy row missing: %w", ErrPasskeysNotAllowed)
		}
		return row, fmt.Errorf("load platform passkey policy: %w", err)
	}
	return row, nil
}

// originOnServerList reports whether the deployment itself allows this origin.
func (s *PasskeyPolicyService) originOnServerList(origin string) bool {
	for _, o := range s.serverDefault.Origins {
		if o == origin {
			return true
		}
	}
	return false
}

// merge fills a row's inherited fields from server configuration.
//
// RP ID and origins are inherited as a pair, never mixed. A tenant that sets
// rp_id has declared its own relying party, and the server's origins belong to a
// different one — inheriting them would let a page on the deployment's own
// domain mint credentials for the tenant's RP. When a tenant sets rp_id and
// leaves origins empty, the origin is derived as https://<rp_id>, which is the
// only origin that could serve that relying party over a secure context anyway.
func (s *PasskeyPolicyService) merge(row policyRow, source string) PasskeyPolicy {
	p := PasskeyPolicy{
		AllowPasskeys:           row.allowPasskeys,
		AllowPasswordless:       row.allowPasswordless,
		RequireUserVerification: row.requireUV,
		MaxCredentialsPerUser:   row.maxCredentials,
		Source:                  source,
	}

	switch {
	case row.rpID != nil && *row.rpID != "":
		p.RPID = *row.rpID
		if len(row.origins) > 0 {
			p.Origins = row.origins
		} else {
			p.Origins = []string{"https://" + *row.rpID}
		}
	default:
		p.RPID = s.serverDefault.RPID
		p.Origins = s.serverDefault.Origins
	}

	switch {
	case row.rpDisplayName != nil && *row.rpDisplayName != "":
		p.RPDisplayName = *row.rpDisplayName
	case s.serverDefault.RPDisplayName != "":
		p.RPDisplayName = s.serverDefault.RPDisplayName
	default:
		p.RPDisplayName = p.RPID
	}

	// The server-level WEBAUTHN_REQUIRE_UV is a floor, not a default. An
	// operator who demanded user verification for the deployment must not have
	// it relaxed by a tenant row: policy here can only ever be as strict or
	// stricter than the deployment's.
	if s.serverDefault.RequireUserVerification {
		p.RequireUserVerification = true
	}

	if p.MaxCredentialsPerUser <= 0 {
		p.MaxCredentialsPerUser = defaultMaxCredentialsPerUser
	}
	return p
}

// NormalizeOrigin trims a browser-supplied Origin header to the exact form the
// allow-list stores: scheme, host, and port, lowercased, with no trailing slash
// and no path.
//
// Comparison is exact, so normalisation has to happen somewhere; doing it here
// means the allow-list is compared against one canonical shape rather than
// against whatever a particular browser or proxy sent. Anything that does not
// look like an origin returns empty, which every caller treats as "not
// allowed" — a value we cannot parse is not a value we should match loosely.
func NormalizeOrigin(raw string) string {
	o := strings.TrimSpace(raw)
	if o == "" || o == "null" {
		// "null" is what a browser sends for a sandboxed or file:// document.
		// It is a real value and it must never match an allow-list entry.
		return ""
	}
	o = strings.TrimSuffix(o, "/")

	scheme := ""
	switch {
	case strings.HasPrefix(strings.ToLower(o), "https://"):
		scheme, o = "https://", o[len("https://"):]
	case strings.HasPrefix(strings.ToLower(o), "http://"):
		scheme, o = "http://", o[len("http://"):]
	default:
		return ""
	}
	// A path, query, or fragment means this is a URL and not an origin. Cutting
	// it off rather than rejecting keeps a slightly wrong caller working; what
	// must not happen is comparing "https://a.com/login" against "https://a.com"
	// and calling it a mismatch.
	if i := strings.IndexAny(o, "/?#"); i >= 0 {
		o = o[:i]
	}
	if o == "" {
		return ""
	}
	return scheme + strings.ToLower(o)
}
