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
	//
	// Buckets are tuned to this server's measured latency profile rather than
	// prometheus.DefBuckets, whose lowest bucket (5ms) sits above almost every
	// endpoint here. Measured p50s: /health 0.55ms, /auth/me 1.6ms, JWKS 1.7ms,
	// list endpoints 2.5-5.7ms — i.e. DefBuckets lands the entire API in its
	// first one or two buckets, where no useful quantile can be computed.
	//
	// The dense 1ms-10ms range gives real resolution over that band. The
	// .75/1.5/2/3 steps bracket the bcrypt-bound login path (measured ~1.0s),
	// which under DefBuckets straddles the 1s boundary — the worst place for it,
	// since p99 estimates then swing on which side of that single edge samples
	// land. Keep 10s as the final bucket so timeouts remain visible.
	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "emc_auth",
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request latency bucketed by method, route, and status code.",
			Buckets: []float64{
				0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5,
				0.75, 1, 1.5, 2, 3, 5, 10,
			},
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
	//
	// The limiter label names the specific bucket that rejected the request, so
	// per-surface abuse is distinguishable: login_ip, login_account, token_ip,
	// token_client, otp_ip, otp_session, oauth_ip, oauth_client, authorize,
	// oauth_token, revoke, jwks_ip, userinfo, audit_maint,
	// signing_key_rotation, app, app_client.
	//
	// Every limiter must increment this on rejection. A limiter that blocks
	// silently is indistinguishable from one that never fires, which makes it
	// impossible to tell "the threshold is protecting us" from "the threshold
	// is set so high it never engages" — and hides both credential-stuffing
	// campaigns and legitimate customers being throttled.
	RateLimitHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "rate_limit_hits_total",
			Help:      "Total number of requests rejected by rate limiters.",
		},
		[]string{"limiter"},
	)

	// RateLimitFailOpen counts requests that bypassed a rate limiter because the
	// limiter itself could not make a decision.
	//
	// The per-application limiter fails OPEN by design: a Redis outage must not
	// take down all authenticated traffic. The cost of that choice is that
	// during an incident every tenant-configured quota silently stops being
	// enforced. Without this counter that state is invisible — it appears only
	// as warn-level log lines, and "all customer quotas are currently
	// unenforced" is something to alert on within seconds.
	//
	// It also compounds: on a Redis outage every request falls through to the
	// database for its limit lookup, so quotas stopping and DB load spiking
	// happen together. Alert on any sustained non-zero rate.
	//
	// Labels: limiter (which limiter bypassed), reason (redis_error,
	// malformed_app_id, malformed_tenant_id).
	RateLimitFailOpen = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "rate_limit_fail_open_total",
			Help:      "Requests allowed through because a rate limiter could not evaluate them.",
		},
		[]string{"limiter", "reason"},
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

	// LegacyAudienceVerifications counts tokens verified through the legacy
	// token-type "aud" fallback because they carry no "gty" claim (issue #130).
	//
	// This is a migration burn-down, not an alert. Every token minted from #130
	// onward carries "gty", so this counter drains as the last pre-#130 tokens
	// expire and should reach a sustained zero within one refresh-token lifetime
	// (30 days). That sustained zero is the gate for issue #132, which removes
	// the fallback: while it is non-zero, dropping the fallback would refuse live
	// tokens.
	//
	// It reads zero for two very different reasons — no legacy tokens left, or
	// nothing ever incrementing it — so the increment is asserted in the test
	// suite. CLAUDE.md deferred #12 is the same metric shape without that
	// assertion, dead since it was written.
	//
	// Labels: client_id (the app_id claim, or "none" for first-party tokens,
	// which carry no application).
	LegacyAudienceVerifications = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "legacy_audience_verifications_total",
			Help:      "Tokens verified via the legacy aud token-type fallback because they carry no gty claim.",
		},
		[]string{"client_id"},
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

	// SessionRevocations counts refresh-token rows revoked, by cause.
	//
	// reason: rotated | logout | user_revoked | admin_revoked |
	//         admin_revoked_all | replay_detected | cap_evicted |
	//         credential_change | idle_expired
	//
	// Counts ROWS, not sessions: one session revoke touches every live token in
	// the family, which is normally one. The ratio is not meaningful; the rate per
	// reason is. Watch replay_detected especially — a sustained non-zero rate is
	// either stolen tokens or a client that retries refreshes incorrectly, and the
	// two need opposite responses.
	SessionRevocations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "session_revocations_total",
			Help:      "Refresh tokens revoked, by cause.",
		},
		[]string{"reason"},
	)

	// SessionDenylistErrors counts Redis failures on the revoked-session
	// denylist. op: read | write.
	//
	// Worth alerting on rather than merely graphing: the denylist fails OPEN, so
	// errors here mean revoked sessions keep working until their access tokens
	// expire. Nothing else surfaces that — the revocation itself reports success.
	SessionDenylistErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "session_denylist_errors_total",
			Help:      "Redis errors on the revoked-session denylist, by operation.",
		},
		[]string{"op"},
	)

	// SessionsReaped counts refresh-token rows deleted by the retention reaper.
	SessionsReaped = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "sessions_reaped_total",
			Help:      "Expired refresh-token rows deleted by the retention reaper.",
		},
	)

	// SessionReaperRuns counts reaper executions by outcome.
	// outcome: success | failure | skipped_locked
	//
	// skipped_locked is normal and expected, not a fault: every replica runs the
	// reaper on its own timer and the advisory lock lets exactly one win.
	SessionReaperRuns = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "session_reaper_runs_total",
			Help:      "Session retention reaper executions by outcome.",
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
	// Incremented exactly once on every terminal path through Authorize,
	// LoginSubmit and MFASubmit — see countAuthorize and the authzOutcome*
	// constants in internal/api/handlers/oauth_authorize.go, which are the
	// authority on these values. Keep the two lists in step.
	//
	// outcome: code_issued | login_shown | invalid_client | invalid_redirect |
	//          consent_required | invalid_request | invalid_scope |
	//          unauthorized_client | mfa_enrollment_required | login_failed |
	//          request_expired | error
	//
	// login_failed is the operationally interesting one: the hosted login is a
	// password form on the public internet, and a rate of failures far above
	// code_issued is what credential stuffing looks like from here.
	OAuthAuthorizeRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "oauth_authorize_requests_total",
			Help:      "OAuth 2.0 authorization endpoint requests by outcome.",
		},
		[]string{"outcome"},
	)

	// OIDCDiscoveryRequests counts fetches of a tenant's OpenID Connect
	// discovery document (issue #7b).
	//
	// Incremented on every terminal path through OIDCHandler.Discovery — see
	// the discoveryOutcome* constants in
	// internal/api/handlers/oidc_discovery.go, which are the authority on these
	// values. Keep the two lists in step.
	//
	// outcome: served | not_modified | unknown_tenant | error
	//
	// Two things make this worth a counter rather than log-grepping. First,
	// served vs not_modified IS the cache-hit ratio: every OIDC client fetches
	// discovery on process start, so a fleet restart with a broken ETag shows
	// up here as a sudden all-served spike before it shows up as load on the
	// tenants table. Second, unknown_tenant at volume is someone enumerating
	// slugs, which is otherwise indistinguishable from a misconfigured client.
	OIDCDiscoveryRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "oidc_discovery_requests_total",
			Help:      "OpenID Connect discovery document fetches by outcome.",
		},
		[]string{"outcome"},
	)
)

// RecordOp is a convenience wrapper around AuthOperations.WithLabelValues.
func RecordOp(operation, outcome string) {
	AuthOperations.WithLabelValues(operation, outcome).Inc()
}

// PasswordRehashTotal counts credentials upgraded to the current password
// hashing parameters on login, labelled by the algorithm they came from.
//
// This is how the bcrypt-to-Argon2id migration is tracked. A one-way hash cannot
// be converted in a batch job — the plaintext exists only during a sign-in — so
// the corpus drains as users return, and the only way to know how far along it
// is, or whether it has stalled, is to count the upgrades as they happen.
//
// Read alongside PasswordHashByAlgorithm: this is the rate, that is the level.
var PasswordRehashTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "emc_auth",
		Name:      "password_rehash_total",
		Help:      "Credentials rehashed to current password parameters on login, by previous algorithm.",
	},
	[]string{"from"},
)

// PasswordHashDuration measures how long a password derivation takes, split by
// algorithm and operation.
//
// Argon2id is deliberately expensive, so this is the metric that says whether
// the configured parameters still suit the hardware. Buckets span 10ms to ~2.5s:
// the low end catches a misconfiguration that has made hashing too cheap to be
// protective, the high end catches an instance too slow for the parameters, which
// presents to users as login latency and to the fleet as saturation.
var PasswordHashDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace: "emc_auth",
		Name:      "password_hash_duration_seconds",
		Help:      "Password hashing and verification latency.",
		Buckets:   []float64{0.01, 0.025, 0.05, 0.075, 0.1, 0.15, 0.25, 0.5, 1, 2.5},
	},
	[]string{"algorithm", "operation"},
)

// PasswordHashInFlight is the number of Argon2id derivations running now.
//
// Each one holds its full memory allocation for its whole duration, so this
// gauge multiplied by the configured memory is live usage. It saturates at the
// concurrency cap; sitting at the cap means logins are queueing for a slot, which
// is the signal to raise the cap (if memory allows) or add instances.
var PasswordHashInFlight = promauto.NewGauge(
	prometheus.GaugeOpts{
		Namespace: "emc_auth",
		Name:      "password_hash_in_flight",
		Help:      "Argon2id derivations currently running.",
	},
)

// PasswordHashQueueWait measures time spent waiting for a derivation slot.
//
// Distinct from PasswordHashDuration on purpose: derivation time is a property
// of the parameters and is expected to be steady, while queue wait is a property
// of load. Conflating them would make a capacity problem look like a slow
// algorithm, and the remedies differ — add instances versus retune parameters.
var PasswordHashQueueWait = promauto.NewHistogram(
	prometheus.HistogramOpts{
		Namespace: "emc_auth",
		Name:      "password_hash_queue_wait_seconds",
		Help:      "Time a password derivation waited for a concurrency slot.",
		Buckets:   []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
	},
)
