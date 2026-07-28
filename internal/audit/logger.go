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
	ActionAdminUserInvited        = "admin.user_invited"
	ActionAuthInvitationAccepted  = "auth.invitation_accepted"
	ActionAuthEmailChangeReq      = "auth.email_change_requested"
	ActionAuthEmailChanged        = "auth.email_changed"
	ActionAuthAccountBlocked      = "auth.account_blocked"
	ActionAuthAccountUnblocked    = "auth.account_unblocked"
	ActionAuthPasswordBreachFound = "auth.password_breach_detected"

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

	// Admin — user identity management
	ActionAdminUserIdentityUnlinked = "admin.user_identity_unlinked"

	// Admin — audit maintenance (compliance)
	ActionAdminUserAuditErased = "admin.user_audit_erased"
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

	// sink is an optional external stream (SIEM) fed each persisted batch
	// (nil = streaming disabled).
	sink Sink
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

// WithSink streams each persisted batch to an external destination (SIEM).
// Pass nil (or omit) to leave streaming off.
func WithSink(s Sink) Option {
	return func(l *Logger) {
		l.sink = s
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
type StatsResult struct {
	LoginsToday       int        `json:"logins_today"`
	FailedLoginsToday int        `json:"failed_logins_today"`
	LogoutsToday      int        `json:"logouts_today"`
	ActiveUsersWeek   int        `json:"active_users_week"`
	TotalAuditEvents  int        `json:"total_audit_events"`
	RecentEvents      []LogEntry `json:"recent_events"`
}

// Stats returns aggregated counts for the monitoring dashboard.
// When tenantID is nil, returns system-wide counts.
func (l *Logger) Stats(ctx context.Context, tenantID *int64) (*StatsResult, error) {
	where := "WHERE 1=1"
	args := []any{}
	if tenantID != nil {
		args = append(args, *tenantID)
		where += fmt.Sprintf(" AND tenant_id = $%d", len(args))
	}

	var s StatsResult
	err := l.pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT
			COUNT(*) FILTER (WHERE action = 'auth.login'        AND created_at >= NOW() - INTERVAL '24 hours'),
			COUNT(*) FILTER (WHERE action = 'auth.login_failed' AND created_at >= NOW() - INTERVAL '24 hours'),
			COUNT(*) FILTER (WHERE action = 'auth.logout'       AND created_at >= NOW() - INTERVAL '24 hours'),
			COUNT(DISTINCT user_id) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days' AND user_id IS NOT NULL),
			COUNT(*)
		FROM audit_logs %s
	`, where), args...).Scan(
		&s.LoginsToday, &s.FailedLoginsToday, &s.LogoutsToday,
		&s.ActiveUsersWeek, &s.TotalAuditEvents,
	)
	if err != nil {
		return nil, fmt.Errorf("audit stats: %w", err)
	}

	page, err := l.Query(ctx, QueryParams{TenantID: tenantID, Page: 1, Limit: 10})
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
