// Package metrics defines the Prometheus metric descriptors for emc-auth-server.
// All metrics use the "emc_auth" namespace for easy dashboard filtering.
//
// Metric inventory:
//   - emc_auth_http_request_duration_seconds — per-route latency histogram
//   - emc_auth_http_requests_in_flight       — active request gauge
//   - emc_auth_operations_total              — named auth operation counter
//   - emc_auth_app_scope_rejections_total    — tokens refused: wrong application
//   - emc_auth_rate_limit_hits_total         — rate-limiter rejection counter
//   - emc_auth_audit_queue_depth             — async audit writer buffer gauge
//   - emc_auth_audit_events_dropped_total    — audit events lost (by reason)
//   - emc_auth_audit_events_written_total    — audit events durably inserted
//   - emc_auth_audit_flush_duration_seconds  — audit batch insert latency
//   - emc_auth_mfa_challenges_total          — MFA attempts (factor, outcome)
//   - emc_auth_mfa_lockouts_total            — MFA attempt-budget lockouts
//   - emc_auth_tokens_issued_total           — tokens issued (grant_type)
//   - emc_auth_tokens_revoked_total          — tokens/sessions revoked (reason)
//   - emc_auth_token_audience_rejections_total — tokens refused on a route by aud
//   - emc_auth_legacy_hs256_verifications_total — symmetric-path verifications (Phase 4 gate)
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

	// AppScopeRejections counts tokens refused because they were not issued for
	// the application that presented them (issue #96).
	//
	// A well-behaved consumer never triggers this: it sends its own tokens with
	// its own credentials. Any sustained rate therefore means a misconfigured
	// integration or a caller replaying another application's token — which is
	// exactly the condition that was previously invisible, because enforcement
	// lived in each consumer's own middleware and we never saw the outcome.
	//
	// Labels:
	//   client_id — the AUTHENTICATED calling application, or the literal
	//               "unauthenticated" when the client could not be identified.
	//               Never an unverified caller-supplied value: Prometheus label
	//               values are unbounded, so accepting arbitrary input here would
	//               let anyone inflate the series count at will — a denial of
	//               service against our own monitoring. Bounded this way,
	//               cardinality is (applications + 1).
	//   reason    — app_mismatch | empty_app_id | tenant_mismatch |
	//               not_a_user_token | client_auth_failed |
	//               client_credentials_missing | missing_claims |
	//               appsvc_unconfigured
	AppScopeRejections = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "app_scope_rejections_total",
			Help:      "Tokens refused because they were not issued for the calling application.",
		},
		[]string{"client_id", "reason"},
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

	// LegacyHS256Verifications counts tokens verified through the legacy
	// symmetric HS256 path rather than by asymmetric key id (issue #95).
	//
	// This metric exists to GATE the Phase 4 cutover. Phase 4 rejects HS256
	// outright, which is only safe once no live token is still signed that way.
	// The issue's original plan was "restart at least one AgentTokenTTL (1 h)
	// after Phase 2" — an unverifiable instruction that trusts a clock. Watching
	// this counter flatten to zero turns that guess into an observation.
	//
	// It is also the alarm for the reverse case: a non-zero rate long after
	// Phase 2 means something is still minting or replaying symmetric tokens,
	// i.e. a holder of a tenant's jwt_secret is still active and must be
	// identified before the secret can be decommissioned.
	//
	// Labels: reason —
	//   no_kid          a pre-#95 token, the normal case during migration
	//   unexpected_kid  a symmetric token carrying a kid; no current code path
	//                   mints one, so it is an old token or a forged header
	//   rejected        refused because JWT_ALLOW_LEGACY_HS256=false (Phase 4 is
	//                   done). A climbing "rejected" count means a consumer is
	//                   still sending symmetric tokens and needs migrating.
	LegacyHS256Verifications = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "legacy_hs256_verifications_total",
			Help:      "Tokens verified via the legacy symmetric HS256 path. Must reach zero before the Phase 4 RS256-only cutover.",
		},
		[]string{"reason"},
	)

	// LegacyIssuerVerifications counts tokens accepted because their "iss"
	// matched the old global JWT_ISSUER rather than the token's own per-tenant
	// issuer (issue #7).
	//
	// Same role as LegacyHS256Verifications, for the same kind of migration:
	// issue #7 moves iss from one server-wide value to {base}/tenants/{slug} so
	// that OIDC discovery can name a jwks_uri whose keys actually verify the
	// token. Tokens minted before that change carry the old value and must keep
	// working until they expire, so the legacy value stays acceptable behind
	// JWT_ALLOW_LEGACY_ISSUER.
	//
	// Watch this flatten to zero before setting JWT_ALLOW_LEGACY_ISSUER=false.
	// The longest-lived affected token is the 1 h agent token, but a clock is not
	// evidence — a flat counter is.
	//
	// Labels: reason —
	//   accepted  a pre-#7 token verified against the global issuer; the normal
	//             case during the migration window
	//   rejected  refused because JWT_ALLOW_LEGACY_ISSUER=false. A climbing count
	//             means something is still minting or replaying tokens with the
	//             old issuer and must be found before this stays off.
	LegacyIssuerVerifications = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "legacy_issuer_verifications_total",
			Help:      "Tokens accepted via the legacy global issuer rather than a per-tenant issuer. Must reach zero before JWT_ALLOW_LEGACY_ISSUER=false.",
		},
		[]string{"reason"},
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

	// TokenAudienceRejections counts requests refused because the token was
	// minted for a different audience (token type) than the route accepts —
	// e.g. an M2M service token presented on a user self-service route.
	//
	// A correctly-behaving client never triggers this: it means a token is being
	// used outside its intended flow, which is the signature of a leaked or
	// replayed token. Alert on any sustained non-zero rate.
	//
	// Labels: audience (the presented aud, normalized to a known value or
	// "other"), route (Echo route template).
	TokenAudienceRejections = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "token_audience_rejections_total",
			Help:      "Requests rejected because the token's audience is not accepted on that route.",
		},
		[]string{"audience", "route"},
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

	// OAuthGrants counts token-endpoint exchanges by grant type and outcome
	// (issue #6).
	//
	// The outcome label is the operationally important half. "replayed" and
	// "pkce_failed" are attack signals, not noise: a replayed authorization
	// code means a code was seen by someone who should not have had it, and a
	// PKCE mismatch means a code was presented by a party that did not
	// originate the request. Both are invisible without this counter, because
	// the client is deliberately told the same generic invalid_grant either way.
	//
	// grant: authorization_code | refresh_token | client_credentials
	// outcome: success | invalid | replayed | pkce_failed | user_unavailable |
	//          invalid_client | error
	OAuthGrants = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "oauth_grants_total",
			Help:      "OAuth 2.0 token endpoint exchanges by grant type and outcome.",
		},
		[]string{"grant", "outcome"},
	)

	// OAuthAuthorizeRequests counts /oauth/authorize outcomes (issue #6).
	//
	// outcome: code_issued | login_shown | invalid_client | invalid_redirect |
	//          consent_required | invalid_request | error
	OAuthAuthorizeRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "oauth_authorize_requests_total",
			Help:      "OAuth 2.0 authorization endpoint requests by outcome.",
		},
		[]string{"outcome"},
	)
)

// RecordOp is a convenience wrapper around AuthOperations.WithLabelValues.
func RecordOp(operation, outcome string) {
	AuthOperations.WithLabelValues(operation, outcome).Inc()
}
