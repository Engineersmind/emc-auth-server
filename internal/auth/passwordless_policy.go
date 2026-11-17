package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"golang.org/x/sync/singleflight"
)

// ---------------------------------------------------------------------------
// Passwordless sign-in policy (issue #203, docs/plans/passwordless-email-otp.md
// section 4.1).
//
// One resolved view per (tenant, application): application row, else tenant row,
// else platform row, else the built-in default, FIELD BY FIELD. A row records only
// what an administrator overrode; NULL inherits. Platform values double as
// ceilings, so a tenant or application can tighten but never exceed them.
//
// The built-in default is "password only": with no row anywhere the platform
// behaves exactly as it did before this feature existed.
// ---------------------------------------------------------------------------

// Errors returned by the policy service. Handlers map these to HTTP statuses.
var (
	// ErrPasswordlessNoFirstFactor is returned when a write would leave the
	// resolved policy with neither a password nor an email-code first factor.
	ErrPasswordlessNoFirstFactor = errors.New("at least one first factor must stay enabled: password or email code")
	// ErrPasswordlessMFAConflict is returned when email codes are enabled for an
	// application whose MFA policy is 'required' with only the email method
	// allowed. The inbox that signs the user in would be the "second factor" too.
	ErrPasswordlessMFAConflict = errors.New("passwordless_mfa_conflict: the application requires MFA with only the email method, which an email-code sign-in cannot satisfy")
	// ErrPasswordlessCeiling is returned when a value exceeds a platform ceiling.
	ErrPasswordlessCeiling = errors.New("value is outside the limit set by the platform policy")
	// ErrPasswordlessVersionConflict is returned when the version sent with a PUT
	// is not the stored one: another administrator changed the policy first.
	ErrPasswordlessVersionConflict = errors.New("the policy was changed by someone else; reload and retry")
	// ErrPasswordlessInvalid is returned for a malformed value.
	ErrPasswordlessInvalid = errors.New("invalid passwordless policy value")
	// ErrPasswordlessTemplateDisabled is returned when email codes are enabled
	// while the sign-in-code email template is switched off at that scope.
	ErrPasswordlessTemplateDisabled = errors.New("the sign-in code email template is disabled for this scope")
	// ErrPasswordlessPolicyNotFound is returned when no row exists at the scope.
	ErrPasswordlessPolicyNotFound = errors.New("no passwordless policy is set at this scope")
	// ErrPasswordlessNoPasswordUsers is returned when switching to password-only
	// would strand active users that have no stored password.
	ErrPasswordlessNoPasswordUsers = errors.New("active users without a password exist; they could not sign in under password only")
)

// Built-in defaults, applied when no row at any level sets a field.
const (
	defaultPasswordlessCodeTTL        = 300
	defaultPasswordlessMaxAttempts    = 5
	defaultPasswordlessMaxResends     = 3
	defaultPasswordlessResendCooldown = 30
	defaultPasswordlessStartsPerHour  = 5
)

// PasswordlessPolicyRow is one stored row. Every tunable is a pointer: nil
// means "inherit from the next level up".
type PasswordlessPolicyRow struct {
	TenantID      *int64 `json:"tenant_id,omitempty"`
	ApplicationID *int64 `json:"application_id,omitempty"`

	EmailOTPEnabled     *bool    `json:"email_otp_enabled"`
	SignupEnabled       *bool    `json:"signup_enabled"`
	PasswordEnabled     *bool    `json:"password_enabled"`
	AllowedEmailDomains []string `json:"allowed_email_domains"`
	BlockedEmailDomains []string `json:"blocked_email_domains"`
	CodeTTLSeconds      *int     `json:"code_ttl_seconds"`
	MaxAttempts         *int     `json:"max_attempts"`
	MaxResends          *int     `json:"max_resends"`
	ResendCooldownSecs  *int     `json:"resend_cooldown_secs"`
	StartsPerHour       *int     `json:"starts_per_hour"`
	DailyEmailBudget    *int     `json:"daily_email_budget"`
	AllowPersistent     *bool    `json:"allow_persistent"`
	WelcomeEmailEnabled *bool    `json:"welcome_email_enabled"`

	Version   int       `json:"version"`
	UpdatedBy *int64    `json:"updated_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// PasswordlessSettings is the resolved policy for one scope. Nothing here is
// nullable: inheritance has already been applied.
type PasswordlessSettings struct {
	EmailOTPEnabled     bool     `json:"email_otp_enabled"`
	SignupEnabled       bool     `json:"signup_enabled"`
	PasswordEnabled     bool     `json:"password_enabled"`
	AllowedEmailDomains []string `json:"allowed_email_domains"`
	BlockedEmailDomains []string `json:"blocked_email_domains"`
	CodeTTLSeconds      int      `json:"code_ttl_seconds"`
	MaxAttempts         int      `json:"max_attempts"`
	MaxResends          int      `json:"max_resends"`
	ResendCooldownSecs  int      `json:"resend_cooldown_secs"`
	StartsPerHour       int      `json:"starts_per_hour"`
	DailyEmailBudget    int      `json:"daily_email_budget"`
	AllowPersistent     bool     `json:"allow_persistent"`
	WelcomeEmailEnabled bool     `json:"welcome_email_enabled"`

	// Sources names, per field, which level supplied the value: "application",
	// "tenant", "platform" or "default". Shown first by the console.
	Sources map[string]string `json:"sources"`
}

// Passwordless authentication modes derived from the settings.
const (
	PasswordlessModePasswordOnly = "password_only"
	PasswordlessModeBoth         = "both"
	PasswordlessModeOnly         = "passwordless_only"
)

// Mode reports the resulting authentication mode.
func (s PasswordlessSettings) Mode() string {
	switch {
	case s.EmailOTPEnabled && !s.PasswordEnabled:
		return PasswordlessModeOnly
	case s.EmailOTPEnabled:
		return PasswordlessModeBoth
	default:
		return PasswordlessModePasswordOnly
	}
}

// DefaultPasswordlessSettings is password only: the behaviour of every
// application that has not opted in. It is also what a policy read failure
// degrades to, which is the safe direction: an unreadable settings table can
// neither switch passwordless on nor lock anyone out of passwords.
func DefaultPasswordlessSettings() PasswordlessSettings {
	return PasswordlessSettings{
		PasswordEnabled:     true,
		AllowedEmailDomains: []string{},
		BlockedEmailDomains: []string{},
		CodeTTLSeconds:      defaultPasswordlessCodeTTL,
		MaxAttempts:         defaultPasswordlessMaxAttempts,
		MaxResends:          defaultPasswordlessMaxResends,
		ResendCooldownSecs:  defaultPasswordlessResendCooldown,
		StartsPerHour:       defaultPasswordlessStartsPerHour,
		WelcomeEmailEnabled: true,
		Sources:             map[string]string{},
	}
}

// PasswordlessScope identifies a policy row. Both nil is the platform row; a
// tenant alone is a tenant row; both is an application row.
type PasswordlessScope struct {
	TenantID      *int64
	ApplicationID *int64
}

// Level names the scope.
func (sc PasswordlessScope) Level() string {
	switch {
	case sc.ApplicationID != nil:
		return "application"
	case sc.TenantID != nil:
		return "tenant"
	default:
		return "platform"
	}
}

// PasswordlessMFAConfigFunc reads an application's MFA mode and allowed methods.
type PasswordlessMFAConfigFunc func(ctx context.Context, appRowID int64) (mode string, methods []string, err error)

// PasswordlessTemplateEnabledFunc reports whether the sign-in-code template is
// enabled at a scope.
type PasswordlessTemplateEnabledFunc func(ctx context.Context, tenantID int64, appRowID *int64) bool

// PasswordlessPolicyService resolves, caches and edits passwordless policy.
type PasswordlessPolicyService struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger

	mfaConfig       PasswordlessMFAConfigFunc
	templateEnabled PasswordlessTemplateEnabledFunc

	mu    sync.RWMutex
	cache map[passwordlessKey]cachedPasswordless
	ttl   time.Duration
	gen   atomic.Uint64
	group singleflight.Group
}

type passwordlessKey struct {
	tenantID, applicationID int64
}

type cachedPasswordless struct {
	settings PasswordlessSettings
	cachedAt time.Time
}

// passwordlessPolicyCacheTTL bounds how stale a resolved policy can be. A mode
// change applies to new requests within this window (plan section 4.11).
const passwordlessPolicyCacheTTL = 30 * time.Second

// NewPasswordlessPolicyService creates the policy service.
func NewPasswordlessPolicyService(pool *pgxpool.Pool, logger zerolog.Logger) *PasswordlessPolicyService {
	return &PasswordlessPolicyService{
		pool:   pool,
		logger: logger,
		cache:  make(map[passwordlessKey]cachedPasswordless),
		ttl:    passwordlessPolicyCacheTTL,
	}
}

// WithMFAConfig supplies the application MFA reader used by write validation.
func (s *PasswordlessPolicyService) WithMFAConfig(f PasswordlessMFAConfigFunc) *PasswordlessPolicyService {
	s.mfaConfig = f
	return s
}

// WithTemplateEnabled supplies the template-suppression check used by write
// validation.
func (s *PasswordlessPolicyService) WithTemplateEnabled(f PasswordlessTemplateEnabledFunc) *PasswordlessPolicyService {
	s.templateEnabled = f
	return s
}

// Resolve returns the settings in force for a scope. It never fails: a read
// error degrades to DefaultPasswordlessSettings (password only), logged.
func (s *PasswordlessPolicyService) Resolve(ctx context.Context, tenantID int64, applicationID *int64) PasswordlessSettings {
	if s == nil || s.pool == nil {
		return DefaultPasswordlessSettings()
	}
	key := passwordlessKey{tenantID: tenantID}
	if applicationID != nil {
		key.applicationID = *applicationID
	}
	s.mu.RLock()
	entry, ok := s.cache[key]
	s.mu.RUnlock()
	if ok && time.Since(entry.cachedAt) < s.ttl {
		return entry.settings
	}

	res, err, _ := s.group.Do(fmt.Sprintf("%d:%d", key.tenantID, key.applicationID), func() (any, error) {
		startGen := s.gen.Load()
		st, lErr := s.load(ctx, tenantID, applicationID)
		if lErr != nil {
			return nil, lErr
		}
		s.mu.Lock()
		if s.gen.Load() == startGen {
			s.cache[key] = cachedPasswordless{settings: st, cachedAt: time.Now()}
		}
		s.mu.Unlock()
		return st, nil
	})
	if err != nil {
		s.logger.Warn().Err(err).Int64("tenant_id", tenantID).
			Msg("passwordless policy: resolve failed, using password-only defaults")
		return DefaultPasswordlessSettings()
	}
	st, ok := res.(PasswordlessSettings)
	if !ok {
		return DefaultPasswordlessSettings()
	}
	return st
}

// InvalidateCache drops every cached resolution. Called after any policy write.
func (s *PasswordlessPolicyService) InvalidateCache() {
	if s == nil {
		return
	}
	s.gen.Add(1)
	s.mu.Lock()
	s.cache = make(map[passwordlessKey]cachedPasswordless)
	s.mu.Unlock()
}

const passwordlessRowColumns = `tenant_id, application_id, email_otp_enabled, signup_enabled,
	password_enabled, allowed_email_domains, blocked_email_domains, code_ttl_seconds,
	max_attempts, max_resends, resend_cooldown_secs, starts_per_hour, daily_email_budget,
	allow_persistent, welcome_email_enabled, version, updated_by, created_at, updated_at`

func scanPasswordlessRow(row pgx.Row) (PasswordlessPolicyRow, error) {
	var r PasswordlessPolicyRow
	err := row.Scan(&r.TenantID, &r.ApplicationID, &r.EmailOTPEnabled, &r.SignupEnabled,
		&r.PasswordEnabled, &r.AllowedEmailDomains, &r.BlockedEmailDomains, &r.CodeTTLSeconds,
		&r.MaxAttempts, &r.MaxResends, &r.ResendCooldownSecs, &r.StartsPerHour, &r.DailyEmailBudget,
		&r.AllowPersistent, &r.WelcomeEmailEnabled, &r.Version, &r.UpdatedBy, &r.CreatedAt, &r.UpdatedAt)
	return r, err
}

// chain reads the platform, tenant and application rows that apply to a scope.
// Any of them may be nil.
func (s *PasswordlessPolicyService) chain(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, tenantID int64, applicationID *int64) (platform, tenant, app *PasswordlessPolicyRow, err error) {
	get := func(t, a *int64) (*PasswordlessPolicyRow, error) {
		r, e := scanPasswordlessRow(q.QueryRow(ctx,
			`SELECT `+passwordlessRowColumns+` FROM passwordless_policies
			 WHERE tenant_id IS NOT DISTINCT FROM $1 AND application_id IS NOT DISTINCT FROM $2`, t, a))
		if errors.Is(e, pgx.ErrNoRows) {
			return nil, nil
		}
		if e != nil {
			return nil, e
		}
		return &r, nil
	}
	if platform, err = get(nil, nil); err != nil {
		return
	}
	if tenant, err = get(&tenantID, nil); err != nil {
		return
	}
	if applicationID != nil {
		app, err = get(&tenantID, applicationID)
	}
	return
}

func (s *PasswordlessPolicyService) load(ctx context.Context, tenantID int64, applicationID *int64) (PasswordlessSettings, error) {
	platform, tenant, app, err := s.chain(ctx, s.pool, tenantID, applicationID)
	if err != nil {
		return DefaultPasswordlessSettings(), fmt.Errorf("load passwordless policy: %w", err)
	}
	return MergePasswordlessPolicy(platform, tenant, app), nil
}

// MergePasswordlessPolicy resolves rows (any may be nil) over the built-in
// defaults, then clamps to the platform ceilings. Exported for the admin API and
// for tests.
func MergePasswordlessPolicy(platform, tenant, app *PasswordlessPolicyRow) PasswordlessSettings {
	out := DefaultPasswordlessSettings()
	levels := []struct {
		name string
		row  *PasswordlessPolicyRow
	}{{"platform", platform}, {"tenant", tenant}, {"application", app}}

	for _, lv := range levels {
		r := lv.row
		if r == nil {
			continue
		}
		setB := func(field string, dst *bool, v *bool) {
			if v != nil {
				*dst, out.Sources[field] = *v, lv.name
			}
		}
		setI := func(field string, dst *int, v *int) {
			if v != nil {
				*dst, out.Sources[field] = *v, lv.name
			}
		}
		setB("email_otp_enabled", &out.EmailOTPEnabled, r.EmailOTPEnabled)
		setB("signup_enabled", &out.SignupEnabled, r.SignupEnabled)
		setB("password_enabled", &out.PasswordEnabled, r.PasswordEnabled)
		setB("allow_persistent", &out.AllowPersistent, r.AllowPersistent)
		setB("welcome_email_enabled", &out.WelcomeEmailEnabled, r.WelcomeEmailEnabled)
		setI("code_ttl_seconds", &out.CodeTTLSeconds, r.CodeTTLSeconds)
		setI("max_attempts", &out.MaxAttempts, r.MaxAttempts)
		setI("max_resends", &out.MaxResends, r.MaxResends)
		setI("resend_cooldown_secs", &out.ResendCooldownSecs, r.ResendCooldownSecs)
		setI("starts_per_hour", &out.StartsPerHour, r.StartsPerHour)
		setI("daily_email_budget", &out.DailyEmailBudget, r.DailyEmailBudget)
		// The allow list is overridden by the most specific non-empty list.
		if len(r.AllowedEmailDomains) > 0 {
			out.AllowedEmailDomains, out.Sources["allowed_email_domains"] = append([]string(nil), r.AllowedEmailDomains...), lv.name
		}
		// The block list only ever grows down the chain: a tenant cannot
		// unblock a domain the platform blocked.
		if len(r.BlockedEmailDomains) > 0 {
			out.BlockedEmailDomains = unionDomains(out.BlockedEmailDomains, r.BlockedEmailDomains)
			out.Sources["blocked_email_domains"] = lv.name
		}
	}

	// Platform ceilings. A child row written before a ceiling was tightened must
	// not keep exceeding it.
	if platform != nil {
		clampMax := func(dst *int, ceil *int) {
			if ceil != nil && *dst > *ceil {
				*dst = *ceil
			}
		}
		clampMax(&out.CodeTTLSeconds, platform.CodeTTLSeconds)
		clampMax(&out.MaxAttempts, platform.MaxAttempts)
		clampMax(&out.MaxResends, platform.MaxResends)
		clampMax(&out.StartsPerHour, platform.StartsPerHour)
		if platform.ResendCooldownSecs != nil && out.ResendCooldownSecs < *platform.ResendCooldownSecs {
			out.ResendCooldownSecs = *platform.ResendCooldownSecs
		}
		if platform.DailyEmailBudget != nil && *platform.DailyEmailBudget > 0 &&
			(out.DailyEmailBudget == 0 || out.DailyEmailBudget > *platform.DailyEmailBudget) {
			out.DailyEmailBudget = *platform.DailyEmailBudget
		}
	}
	return out
}

func unionDomains(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	var out []string
	for _, d := range append(append([]string(nil), a...), b...) {
		if _, ok := seen[d]; !ok {
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	return out
}

// ---------------------------------------------------------------------------
// Domain handling
// ---------------------------------------------------------------------------

var passwordlessDomainRE = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// NormalizePasswordlessDomains lower-cases, trims and validates a domain list.
// Only ASCII hostnames are accepted: IDN and homograph domains are rejected
// (plan threat T13).
func NormalizePasswordlessDomains(in []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(d), "@")))
		if d == "" {
			continue
		}
		if !passwordlessDomainRE.MatchString(d) {
			return nil, fmt.Errorf("%w: %q is not a valid ASCII domain", ErrPasswordlessInvalid, d)
		}
		if _, dup := seen[d]; !dup {
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	return out, nil
}

// DomainPermitted reports whether an address may SIGN UP under these settings:
// not on a blocked domain (or a subdomain of one), and on the allow list when
// one is set.
func (s PasswordlessSettings) DomainPermitted(email string) bool {
	at := strings.LastIndexByte(email, '@')
	if at < 0 || at == len(email)-1 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	for _, b := range s.BlockedEmailDomains {
		if domain == b || strings.HasSuffix(domain, "."+b) {
			return false
		}
	}
	if len(s.AllowedEmailDomains) == 0 {
		return true
	}
	for _, a := range s.AllowedEmailDomains {
		if domain == a {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Admin reads and writes
// ---------------------------------------------------------------------------

// PasswordlessPolicyView is the admin read model: the stored row (nil when the
// scope has none), the resolved values and where each came from.
type PasswordlessPolicyView struct {
	Scope     string                 `json:"scope"`
	Row       *PasswordlessPolicyRow `json:"row"`
	Effective PasswordlessSettings   `json:"effective"`
	Mode      string                 `json:"mode"`
}

// View returns the admin read model for a scope.
func (s *PasswordlessPolicyService) View(ctx context.Context, sc PasswordlessScope) (*PasswordlessPolicyView, error) {
	var tenantID int64
	if sc.TenantID != nil {
		tenantID = *sc.TenantID
	}
	platform, tenant, app, err := s.chain(ctx, s.pool, tenantID, sc.ApplicationID)
	if err != nil {
		return nil, err
	}
	var row *PasswordlessPolicyRow
	switch sc.Level() {
	case "platform":
		row = platform
		tenant, app = nil, nil
	case "tenant":
		row = tenant
		app = nil
	default:
		row = app
	}
	eff := MergePasswordlessPolicy(platform, tenant, app)
	return &PasswordlessPolicyView{Scope: sc.Level(), Row: row, Effective: eff, Mode: eff.Mode()}, nil
}

// PasswordlessWriteInput is the full set of overrides to store at a scope. Nil
// fields inherit. Version is the version the caller read (0 for a new row).
type PasswordlessWriteInput struct {
	Row     PasswordlessPolicyRow
	Version int
	Actor   *int64
	// Action is recorded in the history; "" means create or update as found.
	Action string
}

// validateRow checks a row's own values and normalises its domain lists.
func validatePasswordlessRow(r *PasswordlessPolicyRow) error {
	var err error
	if r.AllowedEmailDomains, err = NormalizePasswordlessDomains(r.AllowedEmailDomains); err != nil {
		return err
	}
	if r.BlockedEmailDomains, err = NormalizePasswordlessDomains(r.BlockedEmailDomains); err != nil {
		return err
	}
	bounds := []struct {
		name   string
		v      *int
		lo, hi int
	}{
		{"code_ttl_seconds", r.CodeTTLSeconds, 300, 900},
		{"max_attempts", r.MaxAttempts, 3, 5},
		{"max_resends", r.MaxResends, 0, 5},
		{"resend_cooldown_secs", r.ResendCooldownSecs, 30, 300},
		{"starts_per_hour", r.StartsPerHour, 1, 10},
		{"daily_email_budget", r.DailyEmailBudget, 0, 1 << 30},
	}
	for _, b := range bounds {
		if b.v != nil && (*b.v < b.lo || *b.v > b.hi) {
			return fmt.Errorf("%w: %s must be between %d and %d", ErrPasswordlessInvalid, b.name, b.lo, b.hi)
		}
	}
	return nil
}

// checkPasswordlessCeilings rejects values that exceed a platform ceiling.
func checkPasswordlessCeilings(platform *PasswordlessPolicyRow, r *PasswordlessPolicyRow) error {
	if platform == nil {
		return nil
	}
	over := func(v, ceil *int) bool { return v != nil && ceil != nil && *v > *ceil }
	switch {
	case over(r.CodeTTLSeconds, platform.CodeTTLSeconds),
		over(r.MaxAttempts, platform.MaxAttempts),
		over(r.MaxResends, platform.MaxResends),
		over(r.StartsPerHour, platform.StartsPerHour),
		r.ResendCooldownSecs != nil && platform.ResendCooldownSecs != nil && *r.ResendCooldownSecs < *platform.ResendCooldownSecs,
		r.DailyEmailBudget != nil && platform.DailyEmailBudget != nil && *platform.DailyEmailBudget > 0 &&
			(*r.DailyEmailBudget == 0 || *r.DailyEmailBudget > *platform.DailyEmailBudget):
		return ErrPasswordlessCeiling
	}
	return nil
}

// Validate checks a proposed row at a scope against the resolved result: own
// values, ceilings, the first-factor rule, the MFA conflict and the template
// check. It does not write.
func (s *PasswordlessPolicyService) Validate(ctx context.Context, sc PasswordlessScope, in *PasswordlessPolicyRow) (PasswordlessSettings, error) {
	if err := validatePasswordlessRow(in); err != nil {
		return PasswordlessSettings{}, err
	}
	var tenantID int64
	if sc.TenantID != nil {
		tenantID = *sc.TenantID
	}
	platform, tenant, _, err := s.chain(ctx, s.pool, tenantID, sc.ApplicationID)
	if err != nil {
		return PasswordlessSettings{}, err
	}
	if sc.Level() != "platform" {
		if err := checkPasswordlessCeilings(platform, in); err != nil {
			return PasswordlessSettings{}, err
		}
	}
	// Substitute the proposed row for the one at this scope, then resolve.
	var app *PasswordlessPolicyRow
	switch sc.Level() {
	case "platform":
		platform, tenant, app = in, nil, nil
	case "tenant":
		tenant, app = in, nil
	default:
		app = in
	}
	eff := MergePasswordlessPolicy(platform, tenant, app)
	if !eff.EmailOTPEnabled && !eff.PasswordEnabled {
		return eff, ErrPasswordlessNoFirstFactor
	}
	if sc.Level() != "application" {
		if err := s.validateDescendants(ctx, sc, platform, tenant); err != nil {
			return eff, err
		}
	}
	if eff.EmailOTPEnabled && sc.ApplicationID != nil {
		if s.mfaConfig != nil {
			mode, methods, mErr := s.mfaConfig(ctx, *sc.ApplicationID)
			if mErr != nil {
				return eff, fmt.Errorf("read application MFA policy: %w", mErr)
			}
			if mode == MFAModeRequired && len(methods) == 1 && methods[0] == MFAMethodEmail {
				return eff, ErrPasswordlessMFAConflict
			}
		}
		if s.templateEnabled != nil && !s.templateEnabled(ctx, tenantID, sc.ApplicationID) {
			return eff, ErrPasswordlessTemplateDisabled
		}
	}
	return eff, nil
}

// validateDescendants checks that a proposed platform or tenant row leaves every
// override beneath it with a first factor. platform and tenant are the rows as
// they would be after the write. An application that overrode
// email_otp_enabled=false must not be left with no password either.
func (s *PasswordlessPolicyService) validateDescendants(ctx context.Context, sc PasswordlessScope, platform, tenant *PasswordlessPolicyRow) error {
	rows, err := s.pool.Query(ctx, `SELECT `+passwordlessRowColumns+` FROM passwordless_policies
		WHERE tenant_id IS NOT NULL AND ($1::BIGINT IS NULL OR tenant_id = $1)`, sc.TenantID)
	if err != nil {
		return fmt.Errorf("read descendant policies: %w", err)
	}
	defer rows.Close()
	var tenantRows = map[int64]*PasswordlessPolicyRow{}
	var appRows []PasswordlessPolicyRow
	for rows.Next() {
		r, err := scanPasswordlessRow(rows)
		if err != nil {
			return err
		}
		if r.ApplicationID == nil {
			rr := r
			tenantRows[*r.TenantID] = &rr
		} else {
			appRows = append(appRows, r)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	noFactor := func(e PasswordlessSettings) bool { return !e.EmailOTPEnabled && !e.PasswordEnabled }
	if sc.Level() == "platform" {
		for _, tr := range tenantRows {
			if noFactor(MergePasswordlessPolicy(platform, tr, nil)) {
				return ErrPasswordlessNoFirstFactor
			}
		}
	}
	for i := range appRows {
		ar := &appRows[i]
		t := tenant
		if sc.Level() == "platform" {
			t = tenantRows[*ar.TenantID]
		}
		eff := MergePasswordlessPolicy(platform, t, ar)
		if noFactor(eff) {
			return ErrPasswordlessNoFirstFactor
		}
		if eff.EmailOTPEnabled && s.mfaConfig != nil {
			mode, methods, mErr := s.mfaConfig(ctx, *ar.ApplicationID)
			if mErr != nil {
				return fmt.Errorf("read application MFA policy: %w", mErr)
			}
			if mode == MFAModeRequired && len(methods) == 1 && methods[0] == MFAMethodEmail {
				return ErrPasswordlessMFAConflict
			}
		}
	}
	return nil
}

// ProjectApp returns an application's effective policy before and after in
// replaces the row at sc (nil in removes it, i.e. a delete). sc may be the
// application, its tenant or the platform.
func (s *PasswordlessPolicyService) ProjectApp(ctx context.Context, sc PasswordlessScope, in *PasswordlessPolicyRow, tenantID, appID int64) (before, after PasswordlessSettings, err error) {
	platform, tenant, app, err := s.chain(ctx, s.pool, tenantID, &appID)
	if err != nil {
		return before, after, err
	}
	before = MergePasswordlessPolicy(platform, tenant, app)
	switch sc.Level() {
	case "platform":
		platform = in
	case "tenant":
		tenant = in
	default:
		app = in
	}
	return before, MergePasswordlessPolicy(platform, tenant, app), nil
}

// AppsInScope lists the applications a policy write at sc can change.
func (s *PasswordlessPolicyService) AppsInScope(ctx context.Context, sc PasswordlessScope) (map[int64]int64, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id FROM oauth_clients
		WHERE deleted_at IS NULL AND ($1::BIGINT IS NULL OR tenant_id = $1) AND ($2::BIGINT IS NULL OR id = $2)`,
		sc.TenantID, sc.ApplicationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int64{}
	for rows.Next() {
		var id, tid int64
		if err := rows.Scan(&id, &tid); err != nil {
			return nil, err
		}
		out[id] = tid
	}
	return out, rows.Err()
}

// Put creates or replaces the overrides at a scope, writing a history entry in
// the same transaction. in.Version must match the stored version (0 = none).
func (s *PasswordlessPolicyService) Put(ctx context.Context, sc PasswordlessScope, in PasswordlessWriteInput) (*PasswordlessPolicyRow, error) {
	row := in.Row
	if _, err := s.Validate(ctx, sc, &row); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	before, err := scanPasswordlessRow(tx.QueryRow(ctx,
		`SELECT `+passwordlessRowColumns+` FROM passwordless_policies
		 WHERE tenant_id IS NOT DISTINCT FROM $1 AND application_id IS NOT DISTINCT FROM $2 FOR UPDATE`,
		sc.TenantID, sc.ApplicationID))
	exists := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if exists && in.Version != before.Version {
		return nil, ErrPasswordlessVersionConflict
	}
	if !exists && in.Version != 0 {
		return nil, ErrPasswordlessVersionConflict
	}

	var saved PasswordlessPolicyRow
	if exists {
		saved, err = scanPasswordlessRow(tx.QueryRow(ctx, `
			UPDATE passwordless_policies SET
			  email_otp_enabled=$3, signup_enabled=$4, password_enabled=$5,
			  allowed_email_domains=$6, blocked_email_domains=$7, code_ttl_seconds=$8,
			  max_attempts=$9, max_resends=$10, resend_cooldown_secs=$11, starts_per_hour=$12,
			  daily_email_budget=$13, allow_persistent=$14, welcome_email_enabled=$15,
			  version=version+1, updated_by=$16, updated_at=NOW()
			WHERE tenant_id IS NOT DISTINCT FROM $1 AND application_id IS NOT DISTINCT FROM $2
			RETURNING `+passwordlessRowColumns,
			sc.TenantID, sc.ApplicationID, row.EmailOTPEnabled, row.SignupEnabled, row.PasswordEnabled,
			nilIfEmpty(row.AllowedEmailDomains), nilIfEmpty(row.BlockedEmailDomains), row.CodeTTLSeconds,
			row.MaxAttempts, row.MaxResends, row.ResendCooldownSecs, row.StartsPerHour,
			row.DailyEmailBudget, row.AllowPersistent, row.WelcomeEmailEnabled, in.Actor))
	} else {
		saved, err = scanPasswordlessRow(tx.QueryRow(ctx, `
			INSERT INTO passwordless_policies (tenant_id, application_id,
			  email_otp_enabled, signup_enabled, password_enabled, allowed_email_domains,
			  blocked_email_domains, code_ttl_seconds, max_attempts, max_resends,
			  resend_cooldown_secs, starts_per_hour, daily_email_budget, allow_persistent,
			  welcome_email_enabled, updated_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
			RETURNING `+passwordlessRowColumns,
			sc.TenantID, sc.ApplicationID, row.EmailOTPEnabled, row.SignupEnabled, row.PasswordEnabled,
			nilIfEmpty(row.AllowedEmailDomains), nilIfEmpty(row.BlockedEmailDomains), row.CodeTTLSeconds,
			row.MaxAttempts, row.MaxResends, row.ResendCooldownSecs, row.StartsPerHour,
			row.DailyEmailBudget, row.AllowPersistent, row.WelcomeEmailEnabled, in.Actor))
	}
	if err != nil {
		return nil, err
	}

	action := in.Action
	if action == "" {
		action = "update"
		if !exists {
			action = "create"
		}
	}
	var beforePtr *PasswordlessPolicyRow
	if exists {
		beforePtr = &before
	}
	if err := writePasswordlessHistory(ctx, tx, sc, saved.Version, action, in.Actor, &saved, beforePtr); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.InvalidateCache()
	return &saved, nil
}

// Delete removes the overrides at a scope (the scope then inherits everything).
func (s *PasswordlessPolicyService) Delete(ctx context.Context, sc PasswordlessScope, actor *int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	before, err := scanPasswordlessRow(tx.QueryRow(ctx,
		`SELECT `+passwordlessRowColumns+` FROM passwordless_policies
		 WHERE tenant_id IS NOT DISTINCT FROM $1 AND application_id IS NOT DISTINCT FROM $2 FOR UPDATE`,
		sc.TenantID, sc.ApplicationID))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPasswordlessPolicyNotFound
	}
	if err != nil {
		return err
	}
	// Removing an override can change the resolved result (for example, drop a
	// password_enabled=true that kept a first factor). Validate the result.
	empty := PasswordlessPolicyRow{}
	if _, vErr := s.Validate(ctx, sc, &empty); vErr != nil {
		return vErr
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM passwordless_policies WHERE tenant_id IS NOT DISTINCT FROM $1 AND application_id IS NOT DISTINCT FROM $2`,
		sc.TenantID, sc.ApplicationID); err != nil {
		return err
	}
	if err := writePasswordlessHistory(ctx, tx, sc, before.Version+1, "delete", actor, nil, &before); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.InvalidateCache()
	return nil
}

func nilIfEmpty(v []string) []string {
	if len(v) == 0 {
		return nil
	}
	return v
}

// PasswordlessHistoryEntry is one append-only history row.
type PasswordlessHistoryEntry struct {
	ID        int64                  `json:"id"`
	Version   int                    `json:"version"`
	Action    string                 `json:"action"`
	ChangedBy *int64                 `json:"changed_by,omitempty"`
	Snapshot  *PasswordlessPolicyRow `json:"snapshot,omitempty"`
	Change    map[string]FieldChange `json:"change"`
	CreatedAt time.Time              `json:"created_at"`
}

// FieldChange is the before and after of one field.
type FieldChange struct {
	Before any `json:"before"`
	After  any `json:"after"`
}

func passwordlessFieldMap(r *PasswordlessPolicyRow) map[string]any {
	m := map[string]any{}
	if r == nil {
		return m
	}
	b, _ := json.Marshal(r)
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"tenant_id", "application_id", "version", "updated_by", "created_at", "updated_at"} {
		delete(m, k)
	}
	return m
}

func diffPasswordless(before, after *PasswordlessPolicyRow) map[string]FieldChange {
	b, a := passwordlessFieldMap(before), passwordlessFieldMap(after)
	out := map[string]FieldChange{}
	keys := map[string]struct{}{}
	for k := range b {
		keys[k] = struct{}{}
	}
	for k := range a {
		keys[k] = struct{}{}
	}
	for k := range keys {
		bj, _ := json.Marshal(b[k])
		aj, _ := json.Marshal(a[k])
		if string(bj) != string(aj) {
			out[k] = FieldChange{Before: b[k], After: a[k]}
		}
	}
	return out
}

func writePasswordlessHistory(ctx context.Context, tx pgx.Tx, sc PasswordlessScope, version int, action string, actor *int64, after, before *PasswordlessPolicyRow) error {
	change, err := json.Marshal(diffPasswordless(before, after))
	if err != nil {
		return err
	}
	var snap []byte
	if after != nil {
		if snap, err = json.Marshal(after); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO passwordless_policy_history (tenant_id, application_id, version, action, changed_by, snapshot, change)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		sc.TenantID, sc.ApplicationID, version, action, actor, snap, change)
	return err
}

// History lists a scope's history, newest first.
func (s *PasswordlessPolicyService) History(ctx context.Context, sc PasswordlessScope, limit int) ([]PasswordlessHistoryEntry, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, version, action, changed_by, snapshot, change, created_at
		FROM passwordless_policy_history
		WHERE tenant_id IS NOT DISTINCT FROM $1 AND application_id IS NOT DISTINCT FROM $2
		ORDER BY id DESC LIMIT $3`, sc.TenantID, sc.ApplicationID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PasswordlessHistoryEntry{}
	for rows.Next() {
		var e PasswordlessHistoryEntry
		var snap, change []byte
		if err := rows.Scan(&e.ID, &e.Version, &e.Action, &e.ChangedBy, &snap, &change, &e.CreatedAt); err != nil {
			return nil, err
		}
		if len(snap) > 0 {
			var r PasswordlessPolicyRow
			if json.Unmarshal(snap, &r) == nil {
				e.Snapshot = &r
			}
		}
		_ = json.Unmarshal(change, &e.Change)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Restore writes a NEW version from an old history snapshot. History is never
// rewritten. currentVersion is the version the caller last saw.
func (s *PasswordlessPolicyService) Restore(ctx context.Context, sc PasswordlessScope, historyID int64, currentVersion int, actor *int64) (*PasswordlessPolicyRow, error) {
	row, err := s.Snapshot(ctx, sc, historyID)
	if err != nil {
		return nil, err
	}
	return s.Put(ctx, sc, PasswordlessWriteInput{Row: *row, Version: currentVersion, Actor: actor, Action: "restore"})
}

// Snapshot returns the policy row stored in a history entry at sc.
func (s *PasswordlessPolicyService) Snapshot(ctx context.Context, sc PasswordlessScope, historyID int64) (*PasswordlessPolicyRow, error) {
	var snap []byte
	err := s.pool.QueryRow(ctx, `
		SELECT snapshot FROM passwordless_policy_history
		WHERE id = $1 AND tenant_id IS NOT DISTINCT FROM $2 AND application_id IS NOT DISTINCT FROM $3`,
		historyID, sc.TenantID, sc.ApplicationID).Scan(&snap)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && len(snap) == 0) {
		return nil, ErrPasswordlessPolicyNotFound
	}
	if err != nil {
		return nil, err
	}
	var row PasswordlessPolicyRow
	if err := json.Unmarshal(snap, &row); err != nil {
		return nil, err
	}
	return &row, nil
}
