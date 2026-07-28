// Package metrics defines the Prometheus metric descriptors for emc-auth-server.
// All metrics use the "emc_auth" namespace for easy dashboard filtering.
//
// Metric inventory:
//   - emc_auth_http_request_duration_seconds — per-route latency histogram
//   - emc_auth_http_requests_in_flight       — active request gauge
//   - emc_auth_operations_total              — named auth operation counter
//   - emc_auth_rate_limit_hits_total         — rate-limiter rejection counter
//   - emc_auth_audit_queue_depth             — async audit writer buffer gauge
//   - emc_auth_audit_events_dropped_total    — audit events lost (by reason)
//   - emc_auth_audit_events_written_total    — audit events durably inserted
//   - emc_auth_audit_flush_duration_seconds  — audit batch insert latency
//   - emc_auth_mfa_challenges_total          — MFA attempts (factor, outcome)
//   - emc_auth_mfa_lockouts_total            — MFA attempt-budget lockouts
//   - emc_auth_tokens_issued_total           — tokens issued (grant_type)
//   - emc_auth_tokens_revoked_total          — tokens/sessions revoked (reason)
//   - emc_auth_apikey_auth_total             — API-key auth attempts (outcome)
//   - emc_auth_social_login_total            — social login (provider, outcome)
//   - emc_auth_risk_signals_total            — risk signals raised (signal)
//   - emc_auth_audit_enrichment_errors_total — enrichment failures (stage)
//   - emc_auth_email_delivery_total          — email delivery (outcome)
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTPRequestDuration tracks end-to-end HTTP request latency.
	// Labels: method (GET/POST/…), path (Echo route template), status (200/401/…).
	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "emc_auth",
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request latency bucketed by method, route, and status code.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"method", "path", "status"},
	)

	// HTTPRequestsInFlight is the count of requests currently being handled.
	HTTPRequestsInFlight = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "emc_auth",
			Name:      "http_requests_in_flight",
			Help:      "Number of HTTP requests currently in flight.",
		},
	)

	// AuthOperations counts discrete auth events with an outcome label.
	// operation values: login, login_otp, register, token_refresh, logout,
	//                   password_reset_request, password_reset_complete,
	//                   totp_enroll, totp_activate, totp_disable, totp_verify,
	//                   api_key_create, api_key_revoke, api_key_auth
	// outcome values: success, failure
	AuthOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "operations_total",
			Help:      "Total number of auth operations by type and outcome.",
		},
		[]string{"operation", "outcome"},
	)

	// RateLimitHits counts requests blocked by rate limiting.
	// Labels: limiter (ip, tenant, app).
	RateLimitHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "rate_limit_hits_total",
			Help:      "Total number of requests rejected by rate limiters.",
		},
		[]string{"limiter"},
	)

	// ---------------------------------------------------------------------
	// Audit pipeline — health of the async audit writer (internal/audit).
	// The pipeline is designed to degrade by dropping events, never by
	// blocking auth requests; these metrics make that degradation visible.
	// Alert on audit_events_dropped_total > 0.
	// ---------------------------------------------------------------------

	// AuditQueueDepth is the number of audit events buffered in memory
	// waiting to be flushed to Postgres. Sustained growth means the DB
	// cannot keep up with the audit event rate.
	AuditQueueDepth = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "emc_auth",
			Name:      "audit_queue_depth",
			Help:      "Audit events buffered in memory awaiting batch insert.",
		},
	)

	// AuditEventsDropped counts audit events lost instead of blocking a
	// request. reason values: queue_full (buffer at capacity), db_error
	// (batch insert failed after retry), shutdown (arrived after Close).
	AuditEventsDropped = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "audit_events_dropped_total",
			Help:      "Audit events dropped by the async writer, by reason.",
		},
		[]string{"reason"},
	)

	// AuditEventsWritten counts audit events durably inserted into audit_logs.
	AuditEventsWritten = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "audit_events_written_total",
			Help:      "Audit events successfully written to the audit_logs table.",
		},
	)

	// AuditFlushDuration tracks how long each batch insert takes.
	AuditFlushDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "emc_auth",
			Name:      "audit_flush_duration_seconds",
			Help:      "Latency of audit batch inserts (CopyFrom) to Postgres.",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// ---------------------------------------------------------------------
	// IdP observability — login/MFA/token/risk activity. Dimensions match
	// the audit trail so dashboards and the audit log tell the same story.
	// ---------------------------------------------------------------------

	// MFAChallenges counts MFA verification attempts by factor and outcome.
	// factor: totp | email_otp | backup_code | mfa. outcome: success | failure.
	MFAChallenges = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "mfa_challenges_total",
			Help:      "MFA verification attempts by factor and outcome.",
		},
		[]string{"factor", "outcome"},
	)

	// MFALockouts counts MFA sessions invalidated by the attempt-budget cap
	// (ErrTooManyOTPAttempts) — the brute-force backstop tripping.
	MFALockouts = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "mfa_lockouts_total",
			Help:      "MFA sessions locked out after exhausting the attempt budget.",
		},
	)

	// AccountLockouts counts per-account password brute-force lockouts as they
	// trip (issue #72), once per tier crossing rather than once per attempt.
	// tier: soft (in-window refusal, no database write) | hard (users.locked_until set).
	AccountLockouts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "account_lockouts_total",
			Help:      "Per-account login lockouts triggered, by tier (soft|hard).",
		},
		[]string{"tier"},
	)

	// LoginsBlockedByLockout counts login attempts refused because a lockout was
	// already in force. Rising while account_lockouts_total is flat means an
	// attack is still hammering an already-locked account — the signal worth
	// alerting on, since the refusal itself is invisible to the client (the
	// response is byte-identical to a wrong password, by design).
	LoginsBlockedByLockout = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "logins_blocked_by_lockout_total",
			Help:      "Login attempts refused because the account was already locked, by tier (soft|hard).",
		},
		[]string{"tier"},
	)

	// TokensIssued counts access tokens issued by grant type.
	// grant_type: password | refresh_token | client_credentials | magic_link |
	//             google-oauth2 | management.
	TokensIssued = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "tokens_issued_total",
			Help:      "Access tokens issued by grant type.",
		},
		[]string{"grant_type"},
	)

	// TokensRevoked counts token/session revocations by reason.
	// reason: logout | replay_detected | refresh_rotation.
	TokensRevoked = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "tokens_revoked_total",
			Help:      "Tokens/sessions revoked by reason.",
		},
		[]string{"reason"},
	)

	// APIKeyAuth counts API-key → management-token exchanges by outcome.
	APIKeyAuth = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "apikey_auth_total",
			Help:      "API-key authentication (management-token) attempts by outcome.",
		},
		[]string{"outcome"},
	)

	// SocialLogin counts social-login attempts by provider and outcome.
	SocialLogin = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "social_login_total",
			Help:      "Social-login attempts by provider and outcome.",
		},
		[]string{"provider", "outcome"},
	)

	// RiskSignals counts security signals raised during audit risk assessment.
	// signal: new_device | impossible_travel | untrusted_ip.
	RiskSignals = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "risk_signals_total",
			Help:      "Security risk signals raised on login-type events, by signal.",
		},
		[]string{"signal"},
	)

	// AuditEnrichmentErrors counts failures inside the async enrichment step.
	// stage: geo | ua | risk.
	AuditEnrichmentErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "audit_enrichment_errors_total",
			Help:      "Errors during async audit enrichment, by stage.",
		},
		[]string{"stage"},
	)

	// EmailDelivery counts transactional emails sent by outcome (mailer).
	EmailDelivery = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "email_delivery_total",
			Help:      "Transactional email delivery attempts by outcome.",
		},
		[]string{"outcome"},
	)
)

// RecordOp is a convenience wrapper around AuthOperations.WithLabelValues.
func RecordOp(operation, outcome string) {
	AuthOperations.WithLabelValues(operation, outcome).Inc()
}
