// Package audit provides structured audit logging for all auth and admin events.
// Every security-relevant action writes a row to the audit_logs table.
//
// Writes are asynchronous: Log() enqueues onto a bounded in-memory buffer and
// returns immediately; a single background worker batch-inserts via COPY
// (see writer.go). Under overload the pipeline drops events (counted in
// Prometheus) rather than ever blocking or failing an auth request.
//
// Two query surfaces are exposed:
//   - Tenant-scoped: admin sees only their own tenant's events
//   - System-wide:   super_admin sees events across all tenants
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// ---------------------------------------------------------------------------
// Action constants — every loggable event has a namespaced string key.
// Format: <domain>.<event>
// ---------------------------------------------------------------------------

const (
	// Auth events
	ActionAuthRegister           = "auth.register"
	ActionAuthLogin              = "auth.login"
	ActionAuthLoginFailed        = "auth.login_failed"
	ActionAuthLogout             = "auth.logout"
	ActionAuthTokenRefresh       = "auth.token_refresh"
	ActionAuthTokenRefreshFailed = "auth.token_refresh_failed"
	ActionAuthPasswordResetReq   = "auth.password_reset_requested"
	ActionAuthPasswordResetDone  = "auth.password_reset_completed"
	ActionAuthReplayDetected     = "auth.replay_detected"

	// Admin — tenant management
	ActionAdminTenantCreated     = "admin.tenant_created"
	ActionAdminTenantUpdated     = "admin.tenant_updated"
	ActionAdminTenantDeactivated = "admin.tenant_deactivated"

	// Admin — permission management
	ActionAdminPermissionCreated = "admin.permission_created"
	ActionAdminPermissionUpdated = "admin.permission_updated"
	ActionAdminPermissionDeleted = "admin.permission_deleted"

	// Admin — role management
	ActionAdminRoleCreated            = "admin.role_created"
	ActionAdminRoleUpdated            = "admin.role_updated"
	ActionAdminRolePermissionsUpdated = "admin.role_permissions_updated"
	ActionAdminRoleDeleted            = "admin.role_deleted"
	ActionAdminRoleDefaultSet         = "admin.role_default_set"

	// Admin — user pool management
	ActionAdminUserCreated        = "admin.user_created"
	ActionAdminUserUpdated        = "admin.user_updated"
	ActionAdminUserDeleted        = "admin.user_deleted"
	ActionAdminUserRoleAssigned   = "admin.user_role_assigned"
	ActionAdminForcePasswordReset = "admin.force_password_reset"
	ActionAdminUserBlocked        = "admin.user_blocked"
	ActionAdminUserUnblocked      = "admin.user_unblocked"
	ActionAdminUserSessionRevoked = "admin.user_session_revoked"
	ActionAdminUserSessionsPurged = "admin.user_sessions_purged"

	// Admin — per-app rate limit management (08-02)
	ActionAdminAppLimitCreated = "admin.app_limit_created"
	ActionAdminAppLimitUpdated = "admin.app_limit_updated"
	ActionAdminAppLimitDeleted = "admin.app_limit_deleted"

	// Admin — tenant CORS configuration
	ActionAdminCORSUpdated = "admin.cors_origins_updated"

	// Admin — application (OAuth2 client) management
	ActionAdminApplicationCreated       = "admin.application_created"
	ActionAdminApplicationUpdated       = "admin.application_updated"
	ActionAdminApplicationDeleted       = "admin.application_deleted"
	ActionAdminApplicationSecretRotated = "admin.application_secret_rotated"

	// Admin — multi-tenant administrative grants (migration 00071).
	//
	// Granting cross-tenant administrative access is among the most
	// security-sensitive events in the system, so each entry records the actor,
	// the target user, the tenant, and the application (or an explicit
	// "all applications" marker). Without the application dimension the log
	// cannot answer "who could reach this application last Tuesday", which is
	// the question an incident actually asks.
	ActionAdminGrantCreated   = "admin.grant_created"
	ActionAdminGrantActivated = "admin.grant_activated"
	ActionAdminGrantRevoked   = "admin.grant_revoked"
	ActionAdminGrantPromoted  = "admin.grant_promoted"
	// ActionAdminGrantDenied records a REFUSED grant write — an owner attempting
	// to mint a peer owner, or to act in a tenant they do not own. These are
	// privilege-escalation attempts and belong in the log even though nothing
	// changed.
	ActionAdminGrantDenied = "admin.grant_denied"
	// ActionAdminTenantSwitched is the only record that one identity acted across
	// a tenant boundary. Reconstructing a multi-tenant administrator's session is
	// impossible without it.
	ActionAdminTenantSwitched = "admin.tenant_switched"
	// ActionAdminIdentityMerged records Phase 0: duplicate administrator
	// identities collapsed into one, naming every retired user id.
	ActionAdminIdentityMerged = "admin.identity_merged"

	// Auth — machine-to-machine client_credentials grant
	ActionAuthClientCredentials       = "auth.client_credentials"
	ActionAuthClientCredentialsFailed = "auth.client_credentials_failed"

	// Auth — API key / management-token lifecycle (issue #66 follow-on)
	ActionAuthAPIKeyCreated         = "auth.api_key_created"
	ActionAuthAPIKeyRevoked         = "auth.api_key_revoked"
	ActionAuthManagementToken       = "auth.management_token_issued"
	ActionAuthManagementTokenFailed = "auth.management_token_failed"

	// Auth — MFA brute-force lockout + email-code delivery
	ActionAuthMFALockedOut     = "auth.mfa_locked_out"
	ActionAuthMFAEmailCodeSent = "auth.mfa_email_code_sent"

	// Auth — MFA/TOTP lifecycle (issue #63)
	ActionAuthMFAEnrolled         = "auth.mfa_enrolled"
	ActionAuthMFAActivated        = "auth.mfa_activated"
	ActionAuthMFADisabled         = "auth.mfa_disabled"
	ActionAuthMFAChallengeFailed  = "auth.mfa_challenge_failed"
	ActionAuthMFACodesRegenerated = "auth.mfa_backup_codes_regenerated"
	ActionAuthMFAEmailEnrolled    = "auth.mfa_email_enrolled"
	ActionAuthMFAEmailActivated   = "auth.mfa_email_activated"
	ActionAuthMFAEmailDisabled    = "auth.mfa_email_disabled"

	// Auth — passwordless magic-link sign-in (issue #63 follow-on)
	ActionAuthMagicLinkRequested = "auth.magic_link_requested"

	// Auth — invitations, email change, lockout, breached passwords
	ActionAdminUserInvited       = "admin.user_invited"
	ActionAuthInvitationAccepted = "auth.invitation_accepted"
	ActionAuthEmailChangeReq     = "auth.email_change_requested"
	ActionAuthEmailChanged       = "auth.email_changed"
	ActionAuthAccountBlocked     = "auth.account_blocked"
	// ActionAuthSuspiciousLogin is a risky sign-in the account owner was alerted
	// about. The sign-in SUCCEEDED and the account is untouched.
	//
	// Split out of ActionAuthAccountBlocked, which the risk-alert path used to emit.
	// That was actively misleading: the event landed on a successful login, against
	// an account that was never blocked, so an operator reading the activity feed saw
	// "account blocked" moments after "login succeeded" and had no way to reconcile
	// them — and any alert or compliance query counting blocks was counting logins.
	ActionAuthSuspiciousLogin     = "auth.suspicious_login"
	ActionAuthAccountUnblocked    = "auth.account_unblocked"
	ActionAuthPasswordBreachFound = "auth.password_breach_detected"

	// Admin — a privileged route refused the caller. Recorded because a refusal
	// is a security signal in its own right: somebody probing for access they do
	// not have leaves no other trace, since the handler never runs.
	ActionAdminAccessDenied = "admin.access_denied"

	// Notifications — the admin-activity emails raised by internal/notify.
	// Recorded so "was the owner actually told?" has an answer; that question is
	// asked after an incident, when reconstructing who knew what and when.
	//
	// The notify sink never treats its own actions as notable, or auditing a
	// notification would produce a notification.
	ActionNotificationSent       = "notification.sent"
	ActionNotificationSuppressed = "notification.suppressed"

	// Admin — tenant administration: owners and co-owners (issue #97)
	ActionAdminTenantAdminInvited   = "admin.tenant_admin_invited"
	ActionAdminTenantAdminGrantsSet = "admin.tenant_admin_grants_set"
	ActionAdminTenantAdminRemoved   = "admin.tenant_admin_removed"

	// Admin — per-application MFA policy management (issue #63)
	ActionAdminMFAPolicyUpdated = "admin.mfa_policy_updated"
	ActionAdminUserMFAReset     = "admin.user_mfa_reset"

	// Admin — white-label email sender management (issue #63 follow-on)
	ActionAdminEmailSenderUpdated = "admin.email_sender_updated"
	ActionAdminEmailSenderDeleted = "admin.email_sender_deleted"
	ActionAdminEmailTestSent      = "admin.email_test_sent"

	// Auth — a transactional email was suppressed because its template is
	// disabled at the resolved scope (application → tenant).
	ActionAuthEmailSuppressed = "auth.email_suppressed"

	// Admin — per-scope email template management
	ActionAdminEmailTemplateUpdated = "admin.email_template_updated"
	ActionAdminEmailTemplateDeleted = "admin.email_template_deleted"

	// Auth — social login (issue #64 Google, issue #66 GitHub). These
	// constants document the emitted action values; handlers derive them per
	// provider via SocialLoginAction and friends.
	ActionAuthGoogleLogin       = "auth.google_login"
	ActionAuthGoogleLoginFailed = "auth.google_login_failed"
	ActionAuthGoogleLinked      = "auth.google_account_linked"
	ActionAuthGitHubLogin       = "auth.github_login"
	ActionAuthGitHubLoginFailed = "auth.github_login_failed"
	ActionAuthGitHubLinked      = "auth.github_account_linked"

	// Admin — identity provider (social login) configuration
	ActionAdminIdPConfigUpdated = "admin.identity_provider_updated"
	ActionAdminIdPConfigDeleted = "admin.identity_provider_deleted"
	ActionAdminIdPConfigTested  = "admin.identity_provider_tested"

	// Admin — user identity management
	ActionAdminUserIdentityUnlinked = "admin.user_identity_unlinked"

	// Admin — audit maintenance (compliance)
	ActionAdminUserAuditErased = "admin.user_audit_erased"

	// Session lifecycle — how sessions END.
	//
	// Distinct actions rather than one "session.revoked" with the reason buried in
	// metadata, because these are asked about separately and by different people:
	// a compliance reviewer wants everything policy terminated, an incident
	// responder wants replays, and a support engineer wants "why was this user
	// signed out?". A JSON metadata field cannot be indexed or alerted on as
	// cheaply as the action column, which every audit query already filters by.
	//
	// Ordinary rotation is deliberately NOT audited: it happens every 15 minutes
	// per active session and would swamp the trail with the one session event that
	// carries no information. auth.token_refresh already records the exchange.
	ActionSessionEndedUser        = "session.ended_by_user"
	ActionSessionEndedIdle        = "session.expired_idle"
	ActionSessionEndedCapEvicted  = "session.evicted_at_cap"
	ActionSessionsReaped          = "session.rows_reaped"
	ActionAdminSessionPolicySet   = "admin.session_policy_updated"
	ActionAdminSessionPolicyReset = "admin.session_policy_reset"

	// Auth — passkeys / WebAuthn (issue #112).
	//
	// Names follow the ticket. passkey_clone_detected is the one that matters:
	// it fires when an assertion shows a credential's private key exists in more
	// than one place, and it is the only auth event in this file that implies
	// somebody extracted key material from an authenticator. It is accompanied
	// by an automatic revocation of the credential and every session the account
	// had, so an operator seeing it is reading about containment that has
	// already happened, not a decision they need to make.
	ActionAuthPasskeyRegistered    = "auth.passkey_registered"
	ActionAuthPasskeyLogin         = "auth.passkey_login"
	ActionAuthPasskeyLoginFailed   = "auth.passkey_login_failed"
	ActionAuthPasskeyRemoved       = "auth.passkey_removed"
	ActionAuthPasskeyRenamed       = "auth.passkey_renamed"
	ActionAuthPasskeyCloneDetected = "auth.passkey_clone_detected"

	// Admin — per-scope passkey policy management (issue #112).
	ActionAdminPasskeyPolicyUpdated = "admin.passkey_policy_updated"
)

// Event outcome — the `status` column. Derived from the action at enqueue time
// when the caller does not set it explicitly.
const (
	StatusSuccess = "success"
	StatusFailure = "failure"
)

// Auth method — the `auth_method` column. The credential/mechanism a caller
// used, mirroring Auth0's connection/strategy/grant_type dimension. Empty for
// events that are not a credential exchange (admin CRUD, config changes).
const (
	AuthMethodPassword          = "password"
	AuthMethodGoogle            = "google-oauth2"
	AuthMethodGitHub            = "github"
	AuthMethodMagicLink         = "magic_link"
	AuthMethodTOTP              = "totp"
	AuthMethodEmailOTP          = "email_otp"
	AuthMethodBackupCode        = "backup_code"
	AuthMethodMFA               = "mfa" // factor not distinguishable at the call site
	AuthMethodClientCredentials = "client_credentials"
	AuthMethodRefreshToken      = "refresh_token"
	AuthMethodAPIKey            = "api_key"
	AuthMethodAgent             = "agent"
	// AuthMethodPasskey is a WebAuthn assertion. One value covers both the
	// with-gesture and without-gesture cases: whether user verification actually
	// happened is recorded on the session's amr claim, which is derived from the
	// authenticator's response rather than from what we asked for, and splitting
	// it here would invite reading the audit row as evidence of the factor count.
	AuthMethodPasskey = "passkey"
)

// SocialLoginAction returns the audit action for a successful social login
// with the given provider (e.g. "auth.google_login", "auth.github_login").
// Callers must pass a validated provider name — never raw request input.
func SocialLoginAction(provider string) string {
	return "auth." + provider + "_login"
}

// SocialLoginFailedAction returns the audit action for a failed social login.
func SocialLoginFailedAction(provider string) string {
	return "auth." + provider + "_login_failed"
}

// SocialLinkedAction returns the audit action for a social identity being
// auto-linked to an existing local account.
func SocialLinkedAction(provider string) string {
	return "auth." + provider + "_account_linked"
}

// SocialAuthMethod maps a validated social provider name to its AuthMethod*
// constant for the audit_logs.auth_method column.
func SocialAuthMethod(provider string) string {
	switch provider {
	case "google":
		return AuthMethodGoogle
	case "github":
		return AuthMethodGitHub
	default:
		return provider
	}
}

// ---------------------------------------------------------------------------
// Event — input to Logger.Log()
// ---------------------------------------------------------------------------

// Event describes a single auditable action.
type Event struct {
	// TenantID is the tenant the action occurred in. Nil for system-level events.
	TenantID *int64
	// UserID is the user who performed the action. Nil for unauthenticated events.
	UserID *int64
	// AgentID is the agent that performed the action. Nil for human-initiated events (08-03).
	AgentID *uuid.UUID
	// ApplicationID is the oauth_clients.id the action occurred under.
	// Nil for tenant-level events with no application context.
	ApplicationID *int64
	// ActorEmail is the email of the actor (denormalized at log time).
	ActorEmail string
	// Action is one of the Action* constants above.
	Action string
	// ResourceType is the kind of resource affected (tenant, user, role, permission).
	ResourceType string
	// ResourceID is the ID (as string) of the affected resource.
	ResourceID string
	// IPAddress is the caller's remote IP.
	IPAddress string
	// UserAgent is the caller's User-Agent header.
	UserAgent string
	// Status is the outcome — StatusSuccess or StatusFailure. Empty is
	// treated as success by the writer.
	Status string
	// HTTPStatus is the HTTP response code served for this event (200/401/…).
	// Zero means "unknown" and is persisted as NULL. Auth0's response status.
	HTTPStatus int
	// AuthMethod is the credential/mechanism used — one of the AuthMethod*
	// constants (password, google-oauth2, totp, client_credentials, …). Empty
	// for events that are not a credential exchange (e.g. admin CRUD).
	AuthMethod string
	// RequestID correlates this event with the same request's structured
	// logs and traces. Empty for events with no request context.
	RequestID string
	// Metadata is an event-specific detail payload (HTTP method/route,
	// failure reason, changed fields, …). Secret-looking keys are redacted
	// and the serialized form is size-capped before it is written, so it is
	// always safe to pass request-derived data here.
	Metadata map[string]any

	// createdAt is stamped by Log() at enqueue time so the persisted
	// created_at reflects when the event happened, not when the async
	// batch flushed (up to flushInterval later).
	createdAt time.Time
}

// ---------------------------------------------------------------------------
// Query result types
// ---------------------------------------------------------------------------

// LogEntry is a single audit log row returned by the query endpoints.
type LogEntry struct {
	ID              string          `json:"id"`
	TenantID        *string         `json:"tenant_id"`
	TenantSlug      *string         `json:"tenant_slug"`
	UserID          *string         `json:"user_id"`
	AgentID         *string         `json:"agent_id,omitempty"`
	ApplicationID   *string         `json:"application_id,omitempty"`
	ApplicationName *string         `json:"application_name,omitempty"`
	ActorEmail      string          `json:"actor_email"`
	Action          string          `json:"action"`
	AuthMethod      string          `json:"auth_method,omitempty"`
	ResourceType    string          `json:"resource_type"`
	ResourceID      string          `json:"resource_id"`
	IPAddress       string          `json:"ip_address"`
	UserAgent       string          `json:"user_agent,omitempty"`
	Status          string          `json:"status"`
	HTTPStatus      *int            `json:"http_status,omitempty"`
	RequestID       string          `json:"request_id,omitempty"`
	Metadata        json.RawMessage `json:"metadata,omitempty" swaggertype:"object"`
	CreatedAt       time.Time       `json:"created_at"`
}

// LogsPage wraps a paginated audit log result.
type LogsPage struct {
	Logs       []LogEntry `json:"logs"`
	Total      int        `json:"total"`
	Page       int        `json:"page"`
	TotalPages int        `json:"total_pages"`
}

// QueryParams are the filter options for both query endpoints.
type QueryParams struct {
	// TenantID restricts results to one tenant (used for tenant-scoped endpoint).
	// Nil means no restriction (system-wide endpoint).
	TenantID *int64
	Action   string
	UserID   string
	AgentID  string // optional UUID string; filters to events by a specific agent (08-03)
	// ApplicationID filters to events under one application. Combined with
	// TenantID it can only narrow the tenant scope, never widen it — an ID
	// from another tenant simply matches zero rows.
	ApplicationID string
	// OnlyApplicationIDs restricts results to events under these applications.
	// Unlike ApplicationID this is not a user-supplied filter — it is the
	// caller's own reach (issue #97), so a co-owner monitoring the tenant sees
	// only the applications they administer.
	//
	// nil means unrestricted. An EMPTY non-nil slice means nothing matches,
	// which is the fail-closed reading and the right one for an administrator
	// with no grants. The two must not be collapsed.
	//
	// Rows with a NULL application_id — tenant-level events belonging to no
	// application — are excluded when this is set. They are the tenant's own
	// business, not any one application's.
	OnlyApplicationIDs []int64
	// Status filters by outcome — "success" or "failure". Empty = all.
	Status string
	// AuthMethod filters by credential/mechanism (one of the AuthMethod*
	// constants). Empty = all.
	AuthMethod string
	From       *time.Time
	To         *time.Time
	Page       int
	Limit      int
}

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

// Logger accepts audit events on the request path and persists them
// asynchronously — see writer.go for the batching pipeline. Log() never
// blocks and never returns an error: under sustained overload the pipeline
// degrades by dropping events (counted in Prometheus), never by slowing
// or failing an auth operation.
type Logger struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger

	// Async pipeline state (writer.go).
	queue         chan Event
	quit          chan struct{} // closed by Close() to stop the worker
	done          chan struct{} // closed by the worker after the final flush
	closed        atomic.Bool
	batchSize     int
	flushInterval time.Duration

	// geo is an optional IP→location resolver (nil = geo enrichment disabled).
	geo GeoResolver
	// risk is an optional security-signal assessor for login-type events
	// (nil = risk enrichment disabled).
	risk RiskAssessor

	// Tamper-evidence hash chain (writer.go). lastHash is the row_hash of the
	// most recently written row; chainSeeded records whether it has been
	// initialised from the DB tail. The worker goroutine is the only writer on
	// the flush path, but the maintenance path (PurgeOlderThan) resets
	// chainSeeded from another goroutine, so all access is guarded by chainMu.
	chainMu     sync.Mutex
	lastHash    string
	chainSeeded bool

	// sinks are optional external streams (SIEM, notification emails) fed each
	// persisted batch. Empty = streaming disabled. Written only by WithSink
	// during construction, read only by the writer goroutine, so no lock.
	sinks []Sink
}

// Option customises the async pipeline. Production code uses the defaults;
// options exist mainly so tests can force small buffers and long intervals.
type Option func(*Logger)

// WithQueueSize sets the in-memory event buffer capacity.
func WithQueueSize(n int) Option {
	return func(l *Logger) {
		if n > 0 {
			l.queue = make(chan Event, n)
		}
	}
}

// WithBatchSize sets how many events trigger an immediate flush.
func WithBatchSize(n int) Option {
	return func(l *Logger) {
		if n > 0 {
			l.batchSize = n
		}
	}
}

// WithFlushInterval sets the maximum time an event waits before being flushed.
func WithFlushInterval(d time.Duration) Option {
	return func(l *Logger) {
		if d > 0 {
			l.flushInterval = d
		}
	}
}

// WithGeoIP enables IP→location enrichment. Pass nil (or omit) to leave geo
// enrichment off — the common case when no GeoIP database is configured.
func WithGeoIP(r GeoResolver) Option {
	return func(l *Logger) {
		l.geo = r
	}
}

// WithRiskAssessor enables security-signal enrichment for login-type events.
// Pass nil (or omit) to leave risk assessment off.
func WithRiskAssessor(r RiskAssessor) Option {
	return func(l *Logger) {
		l.risk = r
	}
}

// WithSink streams each persisted batch to an external destination (SIEM,
// notification emails, …). Repeatable: each call adds a sink, and every one
// receives every batch.
//
// A nil interface is ignored rather than stored, so the length check in flush
// stays meaningful. Note this cannot catch a TYPED nil — NewWebhookSink returns
// (*WebhookSink)(nil) when no URL is configured, which is non-nil as an
// interface — so callers still guard at the concrete type, as main.go does. The
// sinks themselves are nil-receiver-safe as a second line of defence.
func WithSink(s Sink) Option {
	return func(l *Logger) {
		if s == nil {
			return
		}
		l.sinks = append(l.sinks, s)
	}
}

// New creates an audit Logger and starts its background writer.
// Call Close() during shutdown to flush buffered events.
func New(pool *pgxpool.Pool, logger zerolog.Logger, opts ...Option) *Logger {
	l := &Logger{
		pool:          pool,
		logger:        logger,
		queue:         make(chan Event, defaultQueueSize),
		quit:          make(chan struct{}),
		done:          make(chan struct{}),
		batchSize:     defaultBatchSize,
		flushInterval: defaultFlushInterval,
	}
	for _, opt := range opts {
		opt(l)
	}
	go l.run()
	return l
}

// Log enqueues an audit event for asynchronous persistence and returns
// immediately. The ctx parameter is retained for API compatibility; the
// actual write runs on the background worker with its own context, so
// request cancellation never cancels an audit write.
//
// Degradation contract: if the buffer is full (DB overwhelmed or down) or
// the logger is closed, the event is dropped and counted — never blocking
// the caller.
func (l *Logger) Log(_ context.Context, e Event) {
	if l.closed.Load() {
		metrics.AuditEventsDropped.WithLabelValues("shutdown").Inc()
		return
	}
	e.createdAt = time.Now().UTC()
	select {
	case l.queue <- e:
		metrics.AuditQueueDepth.Set(float64(len(l.queue)))
	default:
		metrics.AuditEventsDropped.WithLabelValues("queue_full").Inc()
		l.logger.Warn().Str("action", e.Action).Msg("audit: buffer full — event dropped")
	}
}

// ---------------------------------------------------------------------------
// Query — tenant-scoped (admin:access) and system-wide (tenant:manage)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Stats — aggregated counts for the monitoring dashboard
// ---------------------------------------------------------------------------

// StatsResult holds aggregated counts for the monitoring dashboard.
//
// Every counter is a ROLLING window, not a calendar period: "today" means the
// last 24 hours and "week" the last 7 days. The field names say today/week
// because they are published API, and the dashboard labels them "(24h)" and
// "(7d)" to match the behaviour rather than the names.
type StatsResult struct {
	LoginsToday       int `json:"logins_today"`
	FailedLoginsToday int `json:"failed_logins_today"`
	LogoutsToday      int `json:"logouts_today"`
	// ActiveUsersWeek counts distinct users who SIGNED IN over the last 7 days.
	//
	// Deliberately not "users who produced any audit event": that counted a
	// failed login, a password-reset request, or an admin acting ON the user as
	// activity, so a tenant with nobody able to get in still reported active
	// users. The number a tile labelled "Active Users" has to mean is people who
	// actually reached the product.
	ActiveUsersWeek  int `json:"active_users_week"`
	TotalAuditEvents int `json:"total_audit_events"`

	// RecentEvents is OPT-IN via ?include=recent, and empty otherwise.
	//
	// It used to be returned unconditionally: ten fully-hydrated audit rows,
	// carrying IP addresses, full user agents, request ids and response bodies,
	// on an endpoint a dashboard polls. No client reads it — the audit page has
	// its own paginated endpoint with its own guard — so the default was several
	// kilobytes of the most sensitive rows in the system, sent repeatedly to
	// satisfy nobody.
	//
	// Kept rather than deleted because the field is published API and something
	// outside this repository may parse it. omitempty so a caller that does not
	// ask sees no key at all, which is the honest shape for "not requested".
	//
	// Deprecated: query /audit-logs instead. This exists for compatibility and
	// will be removed once no caller passes include=recent.
	RecentEvents []LogEntry `json:"recent_events,omitempty"`
}

// Stats returns aggregated counts for the monitoring dashboard.
// When tenantID is nil, returns system-wide counts.
//
// Counters only. Use StatsScopedWithRecent when the caller explicitly asked for
// the recent-events list.
func (l *Logger) Stats(ctx context.Context, tenantID *int64) (*StatsResult, error) {
	return l.StatsScoped(ctx, tenantID, nil)
}

// StatsScoped is Stats restricted to a set of applications — the caller's own
// administrative reach (issue #97), not a user-chosen filter.
//
// nil onlyAppIDs means unrestricted, which is what an owner and a platform admin
// get. An empty non-nil slice means nothing, so the counts an administrator with
// no grants sees are zeros rather than the tenant's totals.
func (l *Logger) StatsScoped(ctx context.Context, tenantID *int64, onlyAppIDs []int64) (*StatsResult, error) {
	return l.StatsScopedWithRecent(ctx, tenantID, onlyAppIDs, false)
}

// StatsScopedWithRecent is StatsScoped with the deprecated recent-events list
// controlled explicitly.
//
// includeRecent is threaded from ?include=recent rather than defaulting to true,
// because the list is expensive in exactly the way a polled dashboard endpoint
// should not be: a second query, ten fully-hydrated rows, and the most sensitive
// columns in the schema. See StatsResult.RecentEvents.
func (l *Logger) StatsScopedWithRecent(ctx context.Context, tenantID *int64, onlyAppIDs []int64, includeRecent bool) (*StatsResult, error) {
	where := "WHERE 1=1"
	args := []any{}
	if tenantID != nil {
		args = append(args, *tenantID)
		where += fmt.Sprintf(" AND tenant_id = $%d", len(args))
	}
	if onlyAppIDs != nil {
		args = append(args, onlyAppIDs)
		where += fmt.Sprintf(" AND application_id = ANY($%d)", len(args))
	}

	var s StatsResult
	err := l.pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT
			COUNT(*) FILTER (WHERE action = 'auth.login'        AND created_at >= NOW() - INTERVAL '24 hours'),
			COUNT(*) FILTER (WHERE action = 'auth.login_failed' AND created_at >= NOW() - INTERVAL '24 hours'),
			COUNT(*) FILTER (WHERE action = 'auth.logout'       AND created_at >= NOW() - INTERVAL '24 hours'),
			-- Distinct users who actually SIGNED IN, not users who appear anywhere
			-- in the log. The previous predicate counted any event, so a failed
			-- login, a password-reset request, or an administrator acting ON a
			-- user all made that user "active" — a tenant nobody could get into
			-- still reported active users.
			--
			-- The action list matches the one platform_admins.go uses for
			-- last-sign-in, so "active" means the same thing in both places.
			-- auth.register is included for the same reason it is there: creating
			-- an account is a session-establishing act, and excluding it would
			-- show a brand-new tenant as having nobody.
			COUNT(DISTINCT user_id) FILTER (
				WHERE created_at >= NOW() - INTERVAL '7 days'
				  AND user_id IS NOT NULL
				  AND action IN (
				      'auth.login', 'auth.google_login', 'auth.github_login',
				      'auth.magic_link_requested', 'auth.register')
			),
			COUNT(*)
		FROM audit_logs %s
	`, where), args...).Scan(
		&s.LoginsToday, &s.FailedLoginsToday, &s.LogoutsToday,
		&s.ActiveUsersWeek, &s.TotalAuditEvents,
	)
	if err != nil {
		return nil, fmt.Errorf("audit stats: %w", err)
	}

	// Skipped unless asked for: one fewer query, and several kilobytes of the
	// most sensitive rows in the schema not sent to a caller that never reads
	// them. See StatsResult.RecentEvents.
	if !includeRecent {
		return &s, nil
	}

	// The recent-events list carries the same restriction as the counts.
	// Without it a scoped administrator would read zeroed totals above and then
	// the whole tenant's most recent events underneath them.
	page, err := l.Query(ctx, QueryParams{
		TenantID:           tenantID,
		OnlyApplicationIDs: onlyAppIDs,
		Page:               1,
		Limit:              10,
	})
	if err != nil {
		return nil, fmt.Errorf("audit stats recent: %w", err)
	}
	s.RecentEvents = page.Logs
	return &s, nil
}

// ---------------------------------------------------------------------------

// rowScanner is satisfied by both pgx.Rows and pgx.Row, so scanLogEntry can
// serve the list Query (many rows) and GetByID (single row) from one place.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanLogEntry reads one row in the exact column order of the shared SELECT
// (see Query / GetByID). Keeping the projection and the scan in lockstep here
// avoids the positional drift that bit the CopyFrom path.
func scanLogEntry(row rowScanner) (*LogEntry, error) {
	var e LogEntry
	var tenantID, userID, applicationID *int64
	var agentID *uuid.UUID
	var tenantSlug, appName *string
	var httpStatus *int16
	var logID int64
	var metadata []byte
	if err := row.Scan(
		&logID, &tenantID, &tenantSlug, &userID, &agentID, &applicationID,
		&appName, &e.ActorEmail, &e.Action, &e.AuthMethod, &e.ResourceType,
		&e.ResourceID, &e.IPAddress, &e.UserAgent,
		&e.Status, &httpStatus, &e.RequestID, &metadata, &e.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("audit scan: %w", err)
	}
	// Pass metadata through as raw JSON; omit the empty object so the client
	// can treat "no detail" uniformly.
	if len(metadata) > 0 && string(metadata) != "{}" {
		e.Metadata = json.RawMessage(metadata)
	}
	e.ID = strconv.FormatInt(logID, 10)
	if tenantID != nil {
		s := strconv.FormatInt(*tenantID, 10)
		e.TenantID = &s
	}
	if userID != nil {
		s := strconv.FormatInt(*userID, 10)
		e.UserID = &s
	}
	if agentID != nil {
		s := agentID.String()
		e.AgentID = &s
	}
	if applicationID != nil {
		s := strconv.FormatInt(*applicationID, 10)
		e.ApplicationID = &s
	}
	if httpStatus != nil {
		s := int(*httpStatus)
		e.HTTPStatus = &s
	}
	e.TenantSlug = tenantSlug
	e.ApplicationName = appName
	return &e, nil
}

// Query returns a paginated, filtered list of audit log entries.
// When p.TenantID is set, results are scoped to that tenant only.
// When p.TenantID is nil, results span all tenants (system-wide view).
func (l *Logger) Query(ctx context.Context, p QueryParams) (*LogsPage, error) {
	if p.Page < 1 {
		p.Page = 1
	}
	if p.Limit < 1 {
		p.Limit = 50
	}
	if p.Limit > 200 {
		p.Limit = 200
	}
	offset := (p.Page - 1) * p.Limit

	args := []any{}
	where := "WHERE 1=1"

	if p.TenantID != nil {
		args = append(args, *p.TenantID)
		where += fmt.Sprintf(" AND al.tenant_id = $%d", len(args))
	}
	if p.Action != "" {
		args = append(args, p.Action)
		where += fmt.Sprintf(" AND al.action = $%d", len(args))
	}
	if p.UserID != "" {
		uid, err := strconv.ParseInt(p.UserID, 10, 64)
		if err == nil {
			args = append(args, uid)
			where += fmt.Sprintf(" AND al.user_id = $%d", len(args))
		}
	}
	if p.AgentID != "" {
		aid, err := uuid.Parse(p.AgentID)
		if err == nil {
			args = append(args, aid)
			where += fmt.Sprintf(" AND al.agent_id = $%d", len(args))
		}
	}
	if p.ApplicationID != "" {
		appID, err := strconv.ParseInt(p.ApplicationID, 10, 64)
		if err == nil {
			args = append(args, appID)
			where += fmt.Sprintf(" AND al.application_id = $%d", len(args))
		}
	}
	// The caller's own reach, applied after any requested filter so it can only
	// narrow. A co-owner asking for an application they were not granted gets
	// nothing rather than someone else's events.
	if p.OnlyApplicationIDs != nil {
		args = append(args, p.OnlyApplicationIDs)
		where += fmt.Sprintf(" AND al.application_id = ANY($%d)", len(args))
	}
	if p.Status != "" {
		args = append(args, p.Status)
		where += fmt.Sprintf(" AND al.status = $%d", len(args))
	}
	if p.AuthMethod != "" {
		args = append(args, p.AuthMethod)
		where += fmt.Sprintf(" AND al.auth_method = $%d", len(args))
	}
	if p.From != nil {
		args = append(args, *p.From)
		where += fmt.Sprintf(" AND al.created_at >= $%d", len(args))
	}
	if p.To != nil {
		args = append(args, *p.To)
		where += fmt.Sprintf(" AND al.created_at <= $%d", len(args))
	}

	var total int
	countSQL := fmt.Sprintf(`SELECT COUNT(*) FROM audit_logs al %s`, where)
	if err := l.pool.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("audit count: %w", err)
	}

	args = append(args, p.Limit, offset)
	limitArg := len(args) - 1
	offsetArg := len(args)

	querySQL := fmt.Sprintf(`
		SELECT al.id, al.tenant_id, t.slug, al.user_id, al.agent_id, al.application_id,
		       oc.name, al.actor_email, al.action, al.auth_method, al.resource_type,
		       al.resource_id, COALESCE(host(al.ip_address), ''), al.user_agent,
		       al.status, al.http_status, al.request_id, al.metadata, al.created_at
		FROM audit_logs al
		LEFT JOIN tenants t ON t.id = al.tenant_id
		LEFT JOIN oauth_clients oc ON oc.id = al.application_id
		%s
		ORDER BY al.created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, limitArg, offsetArg)

	rows, err := l.pool.Query(ctx, querySQL, args...)
	if err != nil {
		return nil, fmt.Errorf("audit query: %w", err)
	}
	defer rows.Close()

	var logs []LogEntry
	for rows.Next() {
		e, err := scanLogEntry(rows)
		if err != nil {
			return nil, err
		}
		logs = append(logs, *e)
	}
	if logs == nil {
		logs = []LogEntry{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	totalPages := (total + p.Limit - 1) / p.Limit
	if totalPages == 0 {
		totalPages = 1
	}
	return &LogsPage{
		Logs:       logs,
		Total:      total,
		Page:       p.Page,
		TotalPages: totalPages,
	}, nil
}

// ErrLogNotFound is returned by GetByID when no row matches (or the row is
// outside the caller's tenant scope — the two are indistinguishable on purpose,
// so a tenant admin can't probe for the existence of another tenant's rows).
var ErrLogNotFound = fmt.Errorf("audit log not found")

// GetByID returns the full detail of a single audit row for the drill-down
// view. When tenantScope is non-nil the row must belong to that tenant, so a
// tenant admin cannot read another tenant's events; pass nil for the
// system-wide (super-admin) view.
func (l *Logger) GetByID(ctx context.Context, id int64, tenantScope *int64) (*LogEntry, error) {
	args := []any{id}
	scope := ""
	if tenantScope != nil {
		args = append(args, *tenantScope)
		scope = " AND al.tenant_id = $2"
	}
	row := l.pool.QueryRow(ctx, `
		SELECT al.id, al.tenant_id, t.slug, al.user_id, al.agent_id, al.application_id,
		       oc.name, al.actor_email, al.action, al.auth_method, al.resource_type,
		       al.resource_id, COALESCE(host(al.ip_address), ''), al.user_agent,
		       al.status, al.http_status, al.request_id, al.metadata, al.created_at
		FROM audit_logs al
		LEFT JOIN tenants t ON t.id = al.tenant_id
		LEFT JOIN oauth_clients oc ON oc.id = al.application_id
		WHERE al.id = $1`+scope, args...)

	e, err := scanLogEntry(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrLogNotFound
		}
		return nil, err
	}
	return e, nil
}
