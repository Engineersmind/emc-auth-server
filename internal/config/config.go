package config

import (
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	Port        string
	DatabaseURL string
	RedisURL    string
	LogLevel    string
	Env         string
	JWTIssuer   string

	// MetricsToken optionally gates GET /metrics behind a bearer token, set via
	// METRICS_TOKEN. Empty (the default) leaves the endpoint open, preserving
	// the original contract: bind it to localhost and restrict it at the
	// reverse proxy.
	//
	// This exists because that network-level control is the ONLY thing standing
	// between the Prometheus registry and the public internet, and it is easy to
	// omit — a catch-all `location /` in nginx publishes /metrics along with the
	// API. The exported series carry tenant identifiers, login and token
	// volumes, MFA lockout counts, risk-signal counts, and the internal route
	// table, which is reconnaissance material for an auth server. Setting this
	// gives defence in depth so a proxy misconfiguration is not immediately a
	// data leak.
	MetricsToken string

	// EmailProvider selects the GLOBAL email transport: "sendgrid" or "smtp".
	// Empty is inferred: "sendgrid" when SENDGRID_API_KEY is set, else "smtp"
	// when SMTP_HOST is set, else a console log-only dev mailer. Set via EMAIL_PROVIDER.
	EmailProvider string
	// SendGridAPIKey is the global SendGrid API key (provider="sendgrid").
	// Set via SENDGRID_API_KEY.
	SendGridAPIKey string
	// EmailFromName is the optional display name on the global From header.
	// Set via EMAIL_FROM_NAME.
	EmailFromName string

	// SMTP configuration for the global SMTP provider (password reset, MFA,
	// verification, magic link). In development with no provider configured,
	// emails are logged to console instead.
	SMTPHost string
	SMTPPort int
	// SMTPFrom is the global From address for both providers. Set via SMTP_FROM.
	SMTPFrom     string
	SMTPUsername string
	SMTPPassword string
	// SMTPTLS overrides TLS mode for the global sender: "ssl" (implicit TLS,
	// port 465), "starttls" (mandatory, port 587), "opportunistic", or "none"
	// (local relays only). Empty derives from the port. Set via SMTP_TLS.
	SMTPTLS string

	// AppBaseURL is prepended to the reset token link in emails.
	// Example: "https://auth.emc.local"
	AppBaseURL string

	// DashboardBaseURL is the origin of the admin console SPA. It is prepended
	// to emailed links whose destination is a PAGE rather than an API endpoint.
	//
	// The distinction matters: verify-email, confirm-email-change and
	// unblock-account are GET endpoints that act on the token directly, so their
	// links point at AppBaseURL. An invitation cannot — the recipient has to
	// choose a password first, so accept-invitation is POST-only and a link to
	// it produces "authorization required" in a browser. That link must land on
	// the console page that collects the password and then calls the API.
	//
	// Set via DASHBOARD_BASE_URL. The default is the Vite dev server; any
	// deployment where the console is not on localhost must set it explicitly.
	DashboardBaseURL string

	// PlatformNotifyEmails receive the admin-activity notifications raised when a
	// tenant OWNER takes a privileged action — the platform tier's oversight
	// mail. Comma-separated; set via PLATFORM_NOTIFY_EMAIL.
	//
	// When empty the notifier falls back to every active super_admin user, so
	// the feature works unconfigured. Naming an address is preferable in a real
	// deployment: it survives super_admin churn and routes to a shared mailbox
	// or a ticket queue rather than fanning out to individuals.
	PlatformNotifyEmails []string

	// TOTPEncryptionKey is a 32-byte hex-encoded key used to AES-256-GCM encrypt
	// TOTP secrets at rest. Generate with: openssl rand -hex 32
	// Required when TOTP is used. Must be exactly 64 hex characters.
	TOTPEncryptionKey string

	// OAuthClientSecretEncryptionKey is a 32-byte hex-encoded key used to
	// AES-256-GCM encrypt social-login provider client secrets at rest
	// (identity_provider_configs.client_secret_enc). Generate with:
	// openssl rand -hex 32. Unlike TOTP's key there is NO zero-key fallback
	// in production — the server refuses to start (issue #64).
	OAuthClientSecretEncryptionKey string

	// OAuthClientSecretEncryptionKeyPrevious enables zero-downtime key
	// rotation: set the NEW key as OAUTH_CLIENT_SECRET_ENCRYPTION_KEY and the
	// old one here. Decryption falls back to this key; rows re-encrypt under
	// the new key on their next admin write. Remove once rotation completes.
	OAuthClientSecretEncryptionKeyPrevious string

	// JWTSigningKeyEncryptionKey is a 32-byte hex-encoded key used to
	// AES-256-GCM encrypt JWT signing private keys at rest
	// (signing_keys.private_key_enc). Generate with: openssl rand -hex 32.
	// Follows the OAuthClientSecretEncryptionKey precedent — NO zero-key
	// fallback in production/staging, the server refuses to start (issue #95).
	//
	// This key protects token-signing authority: whoever can decrypt these rows
	// can mint a token for any user in the affected tenant. Treat its loss as
	// more severe than a database leak of hashed passwords.
	JWTSigningKeyEncryptionKey string

	// JWTSigningKeyEncryptionKeyPrevious enables zero-downtime rotation of the
	// key above: set the NEW key as JWT_SIGNING_KEY_ENCRYPTION_KEY and the old
	// one here. Decryption falls back to it transparently. Note this rotates the
	// ENCRYPTION key, not the signing keys themselves — signing-key rotation is
	// a separate operation (see the admin rotate endpoint).
	JWTSigningKeyEncryptionKeyPrevious string

	// JWTAllowLegacyHS256 keeps symmetric HS256 tokens verifiable during the
	// migration to RS256. Set JWT_ALLOW_LEGACY_HS256=false to perform the Phase 4
	// cutover (issue #95).
	//
	// Defaults to true so upgrading to RS256 signing does not invalidate tokens
	// minted seconds earlier. Setting it false is what actually removes the forging
	// risk: while HS256 verifies, any holder of a tenant's jwt_secret can still mint
	// a token for any user in that tenant.
	//
	// Flip it only once emc_auth_legacy_hs256_verifications_total has been flat at
	// zero — that counter, not a stopwatch, is the evidence. The longest-lived
	// symmetric token is the 1 h agent token.
	JWTAllowLegacyHS256 bool

	// OIDCIssuerBaseURL is the public origin used to build each tenant's OIDC
	// issuer, as {base}/tenants/{slug} (issue #7).
	//
	// A field of its own rather than reusing AppBaseURL, which is documented as
	// the base for links inside emails and may legitimately point at a front end
	// on a different host. The issuer must be the origin a relying party can
	// actually fetch this server's discovery document and JWKS from — get it wrong
	// and every external verifier breaks, with the failure surfacing at the
	// relying party rather than here. It defaults to AppBaseURL because in the
	// single-binary deployment they are the same host.
	//
	// Must be the exact scheme+host+port an external verifier will use, with no
	// trailing slash — OIDC issuer comparison is an exact string match, so
	// https://auth.example.com and https://auth.example.com/ are different issuers.
	OIDCIssuerBaseURL string

	// JWTAllowLegacyIssuer keeps tokens carrying the old global JWT_ISSUER
	// verifiable during the migration to per-tenant issuers (issue #7).
	//
	// Same shape and same discipline as JWTAllowLegacyHS256: defaults to true so
	// the switch does not invalidate tokens minted seconds earlier, and is flipped
	// to false only once emc_auth_legacy_issuer_verifications_total has been flat
	// at zero. The longest-lived affected token is the 1 h agent token.
	JWTAllowLegacyIssuer bool

	// CookieDomain sets the Domain attribute on auth cookies.
	// Leave empty for localhost development (browser scopes to current host).
	// In production set to the shared parent domain, e.g. ".engineersmind.com",
	// so both app.engineersmind.com and auth.engineersmind.com can read the cookies.
	CookieDomain string

	// GlobalCORSOrigins are the allowed browser origins for slug-less endpoints
	// (e.g. /auth/login) whose tenant isn't known until after authentication, so
	// per-tenant CORS lookups don't apply. Comma-separated via GLOBAL_CORS_ORIGINS.
	GlobalCORSOrigins []string

	// WebAuthnRPID is the WebAuthn Relying Party ID: the registrable domain that
	// passkeys are bound to, with no scheme and no port ("localhost",
	// "insurance.acme.com"). Empty (the default) disables passkeys entirely —
	// the endpoints are not registered at all.
	//
	// It is NOT derived from APP_BASE_URL, deliberately. A credential is
	// permanently bound to this value: change it and every passkey ever issued
	// stops working, with no migration path. That is not something to have happen
	// as a side effect of editing an unrelated URL. Set via WEBAUTHN_RP_ID.
	WebAuthnRPID string

	// WebAuthnRPDisplayName is the human-readable name the authenticator shows
	// when asking the user whether to create a passkey, and the label the
	// credential keeps in their password manager afterwards. Set via
	// WEBAUTHN_RP_DISPLAY_NAME.
	WebAuthnRPDisplayName string

	// WebAuthnOrigins is the exact-match allow-list of page origins permitted to
	// run a ceremony, INCLUDING scheme and port
	// ("http://localhost:5173,https://app.acme.com").
	//
	// Separate from GlobalCORSOrigins even though the values often coincide: CORS
	// governs which pages may read our responses, this governs which pages may
	// mint credentials against our relying party. Conflating them would mean
	// widening CORS for an unrelated reason silently widened the set of origins
	// that can create passkeys. Set via WEBAUTHN_ORIGINS.
	WebAuthnOrigins []string

	// WebAuthnRequireUserVerification demands a biometric or PIN gesture during
	// the ceremony. Defaults TRUE: in a passwordless sign-in there is no password,
	// so the gesture is the only evidence the right human is present, and without
	// it a passkey on an unlocked stolen laptop signs in with one click.
	// Set WEBAUTHN_REQUIRE_UV=false only to support older security keys that
	// cannot do UV, and only where a password is still the first factor.
	WebAuthnRequireUserVerification bool

	// GeoIPDatabasePath points to a MaxMind GeoLite2/GeoIP2-City .mmdb file used
	// to enrich audit rows with a coarse location. Empty (the default) disables
	// geo enrichment — the .mmdb is licensed and not shipped with the server.
	// Set via GEOIP_DATABASE_PATH.
	GeoIPDatabasePath string

	// UntrustedIPCIDRs is an optional denylist of CIDR ranges flagged as
	// untrusted in the audit risk assessment (Auth0's UntrustedIP signal).
	// Comma-separated via UNTRUSTED_IP_CIDRS; empty disables the check.
	UntrustedIPCIDRs []string

	// BreachDetectionEnabled turns on breached-password warnings, which check
	// each accepted password against the Have I Been Pwned corpus via the
	// k-anonymous range API (only a 5-character hash prefix leaves the server —
	// see internal/security/breach). Off by default because it makes an outbound
	// call to a third party; set BREACH_DETECTION_ENABLED=true to enable.
	BreachDetectionEnabled bool

	// AuditCaptureResponseBody controls whether the (redacted) HTTP response
	// body is stored on audit rows. Values: "off" | "failures" | "all".
	// Default "failures" — failure bodies are just error envelopes (no PII),
	// while success bodies (which can carry PII) are not stored unless "all".
	// Set via AUDIT_CAPTURE_RESPONSE_BODY.
	AuditCaptureResponseBody string

	// AuditRetentionDays is the retention window for audit_logs, enforced by a
	// background purge worker. 0 (default) disables automatic purging — logs
	// are kept indefinitely. Set via AUDIT_RETENTION_DAYS.
	AuditRetentionDays int

	// PasswordHashMaxConcurrent caps simultaneous Argon2id derivations.
	//
	// Argon2id holds ~46MiB for the whole of each derivation, so this value times
	// that memory is the process's worst-case hashing footprint. Unbounded, a
	// login spike is an OOM kill rather than a slowdown — and an attacker who
	// notices can trigger it with unauthenticated requests.
	//
	// 0 (default) means NumCPU, floored at 2: derivation is CPU-saturating as
	// well as memory-hungry, so exceeding core count buys no throughput while
	// every queued derivation still holds its full allocation. Raise it only with
	// the container memory limit raised to match. Set via
	// PASSWORD_HASH_MAX_CONCURRENT.
	PasswordHashMaxConcurrent int

	// AuditSIEMWebhookURL, when set, streams every persisted audit event as a
	// JSON POST to this URL (Datadog/Splunk/S3-proxy/generic webhook). Empty
	// disables streaming. Must be https and resolve to a public IP — private,
	// loopback, and link-local targets are rejected at startup (SSRF guard).
	// Set via AUDIT_SIEM_WEBHOOK_URL.
	AuditSIEMWebhookURL string

	// AudienceScheme prefixes every per-application audience identifier
	// (issue #131), as <scheme><tenant-slug>/<app-slug>. Default "api://".
	//
	// It exists so the scheme is not hardcoded in five places, NOT because a
	// deployment should change it. Changing it after any application has been
	// created splits the namespace in two: existing identifiers keep the old
	// scheme (audiences are immutable by design, and every resource server
	// validating one would break if they were not), while new applications get
	// the new one. Treat it as set-once, before the first application exists.
	//
	// A malformed value is ignored with a warning rather than applied — see
	// AudienceService.WithScheme. Must be a lowercase scheme followed by "://".
	AudienceScheme string

	// AuditSIEMWebhookSecret, when set, signs every outbound SIEM payload with
	// HMAC-SHA256 in the X-EMC-Audit-Signature header so the receiver can
	// authenticate the stream. Empty leaves payloads unsigned. Set via
	// AUDIT_SIEM_WEBHOOK_SECRET.
	AuditSIEMWebhookSecret string
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	smtpPort, _ := strconv.Atoi(getEnv("SMTP_PORT", "587"))
	return &Config{
		Port:                                   getEnv("PORT", "9090"),
		DatabaseURL:                            getEnv("DATABASE_URL", "postgres://emc_auth:password@localhost:5433/emc_auth?sslmode=disable"),
		RedisURL:                               getEnv("REDIS_URL", "redis://localhost:6379/0"),
		LogLevel:                               getEnv("LOG_LEVEL", "info"),
		Env:                                    getEnv("ENV", "development"),
		MetricsToken:                           getEnv("METRICS_TOKEN", ""),
		JWTIssuer:                              getEnv("JWT_ISSUER", "https://auth.emc.local"),
		EmailProvider:                          getEnv("EMAIL_PROVIDER", ""),
		SendGridAPIKey:                         getEnv("SENDGRID_API_KEY", ""),
		EmailFromName:                          getEnv("EMAIL_FROM_NAME", ""),
		SMTPHost:                               getEnv("SMTP_HOST", ""),
		SMTPPort:                               smtpPort,
		SMTPFrom:                               getEnv("SMTP_FROM", "no-reply@emc.local"),
		SMTPUsername:                           getEnv("SMTP_USERNAME", ""),
		SMTPPassword:                           getEnv("SMTP_PASSWORD", ""),
		SMTPTLS:                                getEnv("SMTP_TLS", ""),
		AppBaseURL:                             getEnv("APP_BASE_URL", "http://localhost:9090"),
		DashboardBaseURL:                       getEnv("DASHBOARD_BASE_URL", "http://localhost:5173"),
		PlatformNotifyEmails:                   getEnvList("PLATFORM_NOTIFY_EMAIL", ""),
		TOTPEncryptionKey:                      getEnv("TOTP_ENCRYPTION_KEY", ""),
		OAuthClientSecretEncryptionKey:         getEnv("OAUTH_CLIENT_SECRET_ENCRYPTION_KEY", ""),
		OAuthClientSecretEncryptionKeyPrevious: getEnv("OAUTH_CLIENT_SECRET_ENCRYPTION_KEY_PREVIOUS", ""),
		JWTSigningKeyEncryptionKey:             getEnv("JWT_SIGNING_KEY_ENCRYPTION_KEY", ""),
		JWTSigningKeyEncryptionKeyPrevious:     getEnv("JWT_SIGNING_KEY_ENCRYPTION_KEY_PREVIOUS", ""),
		// Fails closed towards COMPATIBILITY, not towards strictness: only the
		// exact string "false" disables legacy verification, so a typo cannot
		// accidentally reject every live token.
		JWTAllowLegacyHS256: getEnv("JWT_ALLOW_LEGACY_HS256", "true") != "false",
		// Same fail-towards-compatibility rule as JWT_ALLOW_LEGACY_HS256 above.
		JWTAllowLegacyIssuer: getEnv("JWT_ALLOW_LEGACY_ISSUER", "true") != "false",
		// Defaults to APP_BASE_URL: in the single-binary deployment the auth server
		// and the origin used for email links are the same host, so requiring both
		// to be set would be a config trap with one obviously correct answer.
		OIDCIssuerBaseURL:     getEnv("OIDC_ISSUER_BASE_URL", getEnv("APP_BASE_URL", "http://localhost:9090")),
		CookieDomain:          getEnv("COOKIE_DOMAIN", ""),
		GlobalCORSOrigins:     getEnvList("GLOBAL_CORS_ORIGINS", ""),
		WebAuthnRPID:          getEnv("WEBAUTHN_RP_ID", ""),
		WebAuthnRPDisplayName: getEnv("WEBAUTHN_RP_DISPLAY_NAME", "EMC Auth"),
		WebAuthnOrigins:       getEnvList("WEBAUTHN_ORIGINS", ""),
		// Default true — see the field comment. Only an explicit "false" opts out.
		WebAuthnRequireUserVerification: getEnv("WEBAUTHN_REQUIRE_UV", "true") != "false",
		GeoIPDatabasePath:               getEnv("GEOIP_DATABASE_PATH", ""),
		UntrustedIPCIDRs:                getEnvList("UNTRUSTED_IP_CIDRS", ""),
		BreachDetectionEnabled:          getEnv("BREACH_DETECTION_ENABLED", "false") == "true",
		AuditCaptureResponseBody:        getEnv("AUDIT_CAPTURE_RESPONSE_BODY", "failures"),
		AuditRetentionDays:              mustAtoi(getEnv("AUDIT_RETENTION_DAYS", "0")),
		PasswordHashMaxConcurrent:       mustAtoi(getEnv("PASSWORD_HASH_MAX_CONCURRENT", "0")),
		AuditSIEMWebhookURL:             getEnv("AUDIT_SIEM_WEBHOOK_URL", ""),
		AuditSIEMWebhookSecret:          getEnv("AUDIT_SIEM_WEBHOOK_SECRET", ""),
		AudienceScheme:                  getEnv("AUDIENCE_SCHEME", "api://"),
	}
}

// Validate refuses a deployed configuration that would leave cookie sessions
// broken at runtime rather than at boot.
//
// Both checks became boot-critical with the portal's move to cookie sessions:
// the CSRF middleware fails closed, so a misconfiguration here is not a degraded
// mode, it is a total outage of every cookie-authenticated write on the API —
// surfacing as scattered 403s rather than as a failed deploy. Development is
// exempt: it runs on SameSite=Lax with no cookie domain, and the CSRF check is
// skipped entirely there.
func (c *Config) Validate() error {
	if c.Env != "production" && c.Env != "staging" {
		return nil
	}
	if c.CookieDomain == "" {
		return errors.New("COOKIE_DOMAIN must be set when ENV=production or staging: cookie sessions and the CSRF trusted-origin check both derive from it, and the CSRF check fails closed without it")
	}
	if slices.Contains(c.GlobalCORSOrigins, "*") {
		return errors.New("GLOBAL_CORS_ORIGINS must name the portal origin explicitly when ENV=production or staging: a wildcard suppresses Access-Control-Allow-Credentials, so the browser will never send the session cookies")
	}
	return nil
}

// mustAtoi parses an integer env value, returning 0 on any parse error so a
// malformed value disables the feature rather than crashing startup.
func mustAtoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getEnvList parses a comma-separated env var into a trimmed, non-empty slice.
// Trailing slashes are stripped since browser Origin headers never include a path.
func getEnvList(key, fallback string) []string {
	raw := getEnv(key, fallback)
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(p), "/"))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
