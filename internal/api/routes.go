package api

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/getsentry/sentry-go"
	echoSwagger "github.com/swaggo/echo-swagger"
	"go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/api/handlers"
	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
	samlsvc "github.com/engineersmind/emc-auth-server/internal/saml"
	"github.com/engineersmind/emc-auth-server/internal/security/breach"
	"github.com/engineersmind/emc-auth-server/internal/security/risk"
)

// Deps holds shared dependencies injected into route handlers.
type Deps struct {
	Logger zerolog.Logger
	Pool   *pgxpool.Pool
	Redis  *redis.Client
	// Audit is the async audit logger. main.go owns its lifecycle (Close on
	// shutdown drains buffered events). When nil, RegisterRoutes creates one
	// internally — convenient for tests, but its buffer is not drained on exit.
	Audit  *audit.Logger
	Config RoutesConfig
}

// RoutesConfig holds configuration values needed at route-wiring time.
type RoutesConfig struct {
	// JWTIssuer is placed in the "iss" claim (e.g. "https://auth.emc.local").
	JWTIssuer string
	// Env is "development" or "production" — controls HTTPS enforcement behaviour.
	Env string
	// AppBaseURL is prepended to the reset token link in emails.
	AppBaseURL string
	// DashboardBaseURL is the admin console origin, used for emailed links whose
	// destination is a page rather than an API endpoint (the invitation link).
	DashboardBaseURL string
	// TOTPEncryptionKey is the 64-char hex key for AES-256-GCM TOTP secret encryption.
	TOTPEncryptionKey string
	// OAuthClientSecretEncryptionKey is the 64-char hex key for AES-256-GCM
	// encryption of social-login provider client secrets (issue #64).
	// Required in production/staging — the server refuses to start without it.
	OAuthClientSecretEncryptionKey string
	// JWTSigningKeyEncryptionKey is the 64-char hex key for AES-256-GCM
	// encryption of asymmetric JWT signing private keys at rest
	// (signing_keys.private_key_enc). Required in production/staging (issue #95).
	JWTSigningKeyEncryptionKey string
	// JWTSigningKeyEncryptionKeyPrevious is the old key accepted for decryption
	// during rotation of the key above.
	JWTSigningKeyEncryptionKeyPrevious string
	// JWTAllowLegacyHS256 keeps symmetric HS256 tokens verifiable. False performs
	// the issue #95 Phase 4 cutover (RS256 only).
	JWTAllowLegacyHS256 bool
	// OIDCIssuerBaseURL is the public origin used to build each tenant's OIDC
	// issuer as {base}/tenants/{slug} (issue #7).
	OIDCIssuerBaseURL string
	// JWTAllowLegacyIssuer keeps tokens carrying the old global JWT_ISSUER
	// verifiable. False performs the issue #7 issuer cutover.
	JWTAllowLegacyIssuer bool
	// OAuthClientSecretEncryptionKeyPrevious is the old key accepted for
	// decryption during rotation (empty when no rotation is in progress).
	OAuthClientSecretEncryptionKeyPrevious string
	// EmailProvider selects the global transport ("sendgrid"|"smtp"; empty = inferred).
	EmailProvider string
	// SendGridAPIKey is the global SendGrid API key (provider="sendgrid").
	SendGridAPIKey string
	// EmailFromName is the optional display name on the global From header.
	EmailFromName string
	// SMTP fields for the global SMTP provider (dev logs to console when nothing set).
	SMTPHost     string
	SMTPPort     int
	SMTPFrom     string
	SMTPUsername string
	SMTPPassword string
	SMTPTLS      string
	// CookieDomain is the Domain attribute for auth cookies (e.g. ".engineersmind.com").
	// Leave empty for localhost development.
	CookieDomain string
	// GlobalCORSOrigins are the allowed browser origins for slug-less endpoints
	// (e.g. /auth/login), which have no tenant to look up a per-tenant list by.
	GlobalCORSOrigins []string
	// AuditCaptureResponseBody gates response-body capture: "off" | "failures" | "all".
	AuditCaptureResponseBody string
	// BreachDetectionEnabled turns on breached-password warnings (HIBP range API).
	BreachDetectionEnabled bool
	// UntrustedIPCIDRs feeds the risk assessor behind suspicious-sign-in alerts.
	UntrustedIPCIDRs []string
}

// securityHeaders returns an Echo middleware that injects security-related
// HTTP response headers on every response (NFR-06).
//
// Headers applied:
//   - Strict-Transport-Security: max-age=31536000; includeSubDomains (HSTS — 1 year)
//   - X-Content-Type-Options: nosniff
//   - X-Frame-Options: DENY
//   - Referrer-Policy: strict-origin-when-cross-origin
//   - Content-Security-Policy: restricts sources for scripts, styles, images, etc.
//
// In development (Env != "production"), HSTS is still set so that the header
// is visible during local testing. Adjust if local HTTPS is not configured.
func securityHeaders() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			h := c.Response().Header()
			// NFR-06: HSTS — tells browsers to always use HTTPS for 1 year.
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			// Prevent MIME sniffing attacks.
			h.Set("X-Content-Type-Options", "nosniff")
			// Prevent clickjacking via iframes.
			// frame-ancestors 'none' in CSP makes this redundant but keep both
			// for older browser compatibility.
			h.Set("X-Frame-Options", "DENY")
			// Control referrer information leakage.
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			// Content Security Policy — primary browser XSS mitigation (HIGH-03).
			// Swagger UI (/swagger/*) uses inline <script> blocks for SwaggerUIBundle
			// initialization, so it requires 'unsafe-inline' in script-src.
			// All other routes use the stricter policy.
			scriptSrc := "'self'"
			if strings.HasPrefix(c.Request().URL.Path, "/swagger/") {
				scriptSrc = "'self' 'unsafe-inline'"
			}
			// style-src includes 'unsafe-inline' because Tailwind CSS injects
			// inline styles at runtime. All other sources are restricted to 'self'.
			h.Set("Content-Security-Policy",
				"default-src 'self'; "+
					"script-src "+scriptSrc+"; "+
					"style-src 'self' 'unsafe-inline'; "+
					"img-src 'self' data:; "+
					"connect-src 'self'; "+
					"font-src 'self'; "+
					"frame-ancestors 'none'")
			return next(c)
		}
	}
}

// httpsRedirect returns middleware that issues a 301 redirect to HTTPS when the
// request arrives over plain HTTP. Only active when Env == "production".
// In development, requests pass through unchanged so localhost HTTP works.
func httpsRedirect(env string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if env == "production" && c.Request().TLS == nil {
				// Check X-Forwarded-Proto in case a TLS-terminating proxy is in front.
				proto := c.Request().Header.Get("X-Forwarded-Proto")
				if proto != "https" {
					target := "https://" + c.Request().Host + c.Request().RequestURI
					return c.Redirect(http.StatusMovedPermanently, target)
				}
			}
			return next(c)
		}
	}
}

// sentryMiddleware captures panics and reports them to Sentry, then re-panics so
// Echo's Recover middleware can still return HTTP 500. Uses echo/v4 MiddlewareFunc
// directly to avoid the sentry-go/echo sub-package which requires echo/v5.
func sentryMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			hub := sentry.CurrentHub().Clone()
			hub.Scope().SetRequest(c.Request())
			c.Set("sentry_hub", hub)
			defer func() {
				if r := recover(); r != nil {
					hub.RecoverWithContext(c.Request().Context(), r)
					panic(r)
				}
			}()
			return next(c)
		}
	}
}

// warnIssuerHostMismatch flags a JWT_ISSUER whose host differs from APP_BASE_URL
// (issue #95).
//
// The two are independent settings that ship with different defaults
// ("https://auth.emc.local" vs "http://localhost:9090"). That was harmless while
// we published nothing, but a JWKS endpoint changes it: OIDC convention says a
// relying party derives the key-set URL from the token's "iss", so a verifier
// following convention would look for our keys on a host that does not serve them.
//
// APP_BASE_URL is authoritative for discovery here — it is where the endpoint
// actually is — and "iss" is left alone deliberately, because changing it would
// invalidate every consumer that has pinned the current value. So this warns
// rather than rewrites: reconciling them is an operator decision with external
// consequences, not something to do silently at startup.
//
// Production is escalated to an error-level log because a mismatch there is a
// live integration hazard for real relying parties.
//
// Issue #7 update: the value compared here is now OIDC_ISSUER_BASE_URL, not
// JWT_ISSUER. Per-tenant issuers made JWT_ISSUER a legacy value that new tokens
// no longer carry, so comparing it would warn about a host that appears in no
// token while staying silent on the one that does — the check would look healthy
// and cover nothing. What still matters is unchanged and is exactly what #7 makes
// structural: the origin a token's "iss" is built from must be the origin that
// serves the matching JWKS.
func warnIssuerHostMismatch(issuer, appBaseURL, env string, logger zerolog.Logger) {
	if issuer == "" || appBaseURL == "" {
		return
	}
	iss, errIss := url.Parse(issuer)
	base, errBase := url.Parse(appBaseURL)
	if errIss != nil || errBase != nil || iss.Host == "" || base.Host == "" {
		return
	}
	if strings.EqualFold(iss.Host, base.Host) {
		return
	}

	evt := logger.Warn()
	if env == "production" {
		evt = logger.Error()
	}
	evt.
		Str("jwt_issuer", issuer).
		Str("app_base_url", appBaseURL).
		Str("jwks_url", strings.TrimRight(appBaseURL, "/")+"/tenants/{slug}/.well-known/jwks.json").
		Msg("JWT_ISSUER host differs from APP_BASE_URL — verifiers deriving the JWKS URL from the iss claim (standard OIDC discovery) will look on the wrong host. JWKS is served from APP_BASE_URL; give consumers that URL explicitly, or set the two to the same host.")
}

// RegisterRoutes configures all route groups and middleware on the Echo instance.
func RegisterRoutes(e *echo.Echo, deps Deps) {
	// Middleware stack — order matters:
	// 1. RequestID  — generates unique ID for each request (used by logger)
	// 2. SecurityHeaders — HSTS + X-Content-Type-Options etc. on every response
	// 3. HTTPSRedirect — production-only redirect from HTTP to HTTPS
	// 4. RequestLogger — structured zerolog request logging
	// 5. Recover — catches panics from all subsequent handlers
	e.Use(echoMiddleware.RequestID())
	e.Use(otelecho.Middleware("emc-auth-server")) // traces every HTTP request
	// Sentry: before Recover so panics reach Sentry first; re-panics so Recover returns 500.
	e.Use(sentryMiddleware())
	e.Use(securityHeaders())
	e.Use(httpsRedirect(deps.Config.Env))
	e.Use(mw.RequestLogger(deps.Logger))
	e.Use(mw.PrometheusMetrics())
	e.Use(echoMiddleware.Recover())

	// Health check — no auth required
	e.GET("/health", handlers.HealthHandler)

	// Prometheus metrics — internal observability endpoint (07-05).
	// Bind to 127.0.0.1 in production via reverse proxy; no auth by design
	// (Prometheus scrapes this; protect via network policy).
	e.GET("/metrics", echo.WrapHandler(promhttp.Handler()))

	// Swagger UI — available at /swagger/index.html
	// Override CSP for Swagger: its bundled JS uses inline scripts that require
	// 'unsafe-inline'; acceptable here since Swagger is a dev/docs-only endpoint.
	e.GET("/swagger/*", echoSwagger.WrapHandler, func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Response().Header().Set("Content-Security-Policy",
				"default-src 'self'; "+
					"script-src 'self' 'unsafe-inline'; "+
					"style-src 'self' 'unsafe-inline'; "+
					"img-src 'self' data:; "+
					"connect-src 'self'; "+
					"font-src 'self'; "+
					"frame-ancestors 'none'")
			return next(c)
		}
	})

	// Build shared services
	jwtSvc, jwtErr := auth.NewJWTService(deps.Pool, deps.Config.JWTIssuer)
	if jwtErr != nil {
		deps.Logger.Fatal().Err(jwtErr).Msg("JWT service init failed — check JWT_ISSUER")
	}

	// Per-tenant OIDC issuers (issue #7): iss becomes {base}/tenants/{slug} so a
	// relying party following discovery reaches a jwks_uri whose keys actually
	// verify the token. Wired here, immediately after construction, so no mint
	// path can run before it — the failure mode of wiring it later is tokens
	// issued during startup carrying the wrong issuer.
	//
	// Verification keeps accepting the legacy global issuer until the cutover, so
	// no live session breaks at this point.
	issuerResolver, issErr := auth.NewTenantIssuerResolver(deps.Pool, deps.Config.OIDCIssuerBaseURL)
	if issErr != nil {
		deps.Logger.Fatal().Err(issErr).Msg("tenant issuer resolver init failed — check OIDC_ISSUER_BASE_URL / APP_BASE_URL")
	}
	jwtSvc.WithTenantIssuers(issuerResolver).WithLegacyIssuer(deps.Config.JWTAllowLegacyIssuer)
	if !deps.Config.JWTAllowLegacyIssuer {
		deps.Logger.Warn().Msg("JWT_ALLOW_LEGACY_ISSUER=false — tokens carrying the old global JWT_ISSUER are REJECTED (issue #7 cutover). Any token minted before per-tenant issuers went live will fail.")
	}
	deps.Logger.Info().
		Str("issuer_base_url", issuerResolver.BaseURL()).
		Bool("legacy_issuer_accepted", deps.Config.JWTAllowLegacyIssuer).
		Msg("per-tenant OIDC issuers enabled (issue #7)")
	authSvc := auth.NewAuthService(deps.Pool, jwtSvc, deps.Logger)

	// TOTP service — requires encryption key; logs warning in dev if missing.
	totpSvc, totpErr := auth.NewTOTPService(deps.Pool, deps.Config.TOTPEncryptionKey, deps.Logger)
	if totpErr != nil {
		deps.Logger.Fatal().Err(totpErr).Msg("TOTP service init failed — check TOTP_ENCRYPTION_KEY")
	}
	authSvc.WithTOTP(totpSvc, deps.Redis)

	// API key service
	apiKeySvc := auth.NewAPIKeyService(deps.Pool, deps.Logger)

	// Application service — manages OAuth2 clients (client_id + client_secret)
	appSvc := auth.NewApplicationService(deps.Pool, deps.Logger)
	authSvc.WithApplications(appSvc)

	// Agent service (08-01) — machine-to-machine authentication
	agentSvc := auth.NewAgentService(deps.Pool, deps.Logger)
	agentHandler := handlers.NewAgentHandler(agentSvc, jwtSvc, deps.Logger)

	// Mailer: global provider is SendGrid (Web API) when SENDGRID_API_KEY is set,
	// else SMTP when SMTP_HOST is set, else a console log-only dev mailer.
	m := mailer.NewMailer(mailer.MailerConfig{
		Env:            deps.Config.Env,
		Provider:       deps.Config.EmailProvider,
		SMTPHost:       deps.Config.SMTPHost,
		SMTPPort:       deps.Config.SMTPPort,
		SMTPUsername:   deps.Config.SMTPUsername,
		SMTPPassword:   deps.Config.SMTPPassword,
		SMTPTLS:        deps.Config.SMTPTLS,
		SendGridAPIKey: deps.Config.SendGridAPIKey,
		EmailFrom:      deps.Config.SMTPFrom,
		FromName:       deps.Config.EmailFromName,
		Logger:         deps.Logger,
	})
	resetSvc := auth.NewResetService(deps.Pool, m, deps.Config.AppBaseURL, deps.Logger)

	// White-label email senders (issue #63 follow-on) — transactional emails
	// resolve their sender application → tenant → global. Providers: SMTP or SendGrid.
	senderSvc := auth.NewEmailSenderService(deps.Pool, totpSvc.EncryptionKey(), deps.Logger)

	// Per-scope email templates (Auth0-style) — application → tenant → built-in.
	tmplSvc := auth.NewEmailTemplateService(deps.Pool, deps.Logger)

	resetSvc.WithSenders(senderSvc).WithTemplates(tmplSvc) // reset uses tenant sender + template

	// Email verification (register → verify link → welcome). Reuses the sender +
	// template resolvers so verification/welcome mail is branded per scope too.
	verifSvc := auth.NewVerificationService(deps.Pool, m, deps.Config.AppBaseURL, deps.Logger).
		WithSenders(senderSvc).
		WithTemplates(tmplSvc)
	authSvc.WithVerification(verifSvc)

	// Email MFA service (issue #63) — email one-time codes as a second factor,
	// per-application opt-in via application_mfa_settings.allowed_methods.
	emailMFASvc := auth.NewEmailMFAService(deps.Pool, deps.Redis, m, deps.Logger).
		WithSenders(senderSvc).
		WithTemplates(tmplSvc)
	authSvc.WithEmailMFA(emailMFASvc)

	// Invitations, self-service email change, account lockout, and breached-
	// password warnings — the remaining transactional email flows. Each reuses
	// the same sender + template resolvers, so their mail is branded per scope
	// and can be customized or disabled per application like every other type.
	invSvc := auth.NewInvitationService(deps.Pool, m, deps.Config.DashboardBaseURL, deps.Logger).
		WithSenders(senderSvc).
		WithTemplates(tmplSvc)
	emailChangeSvc := auth.NewEmailChangeService(deps.Pool, m, deps.Config.AppBaseURL, deps.Logger).
		WithSenders(senderSvc).
		WithTemplates(tmplSvc)
	blockSvc := auth.NewAccountBlockService(deps.Pool, m, deps.Config.AppBaseURL, deps.Logger).
		WithSenders(senderSvc).
		WithTemplates(tmplSvc).
		WithRiskAssessor(risk.New(deps.Pool, deps.Config.UntrustedIPCIDRs, deps.Logger))
	// A disabled checker yields a service whose Notify is a no-op.
	breachSvc := auth.NewBreachService(deps.Pool,
		breach.New(deps.Config.BreachDetectionEnabled, deps.Logger),
		m, deps.Config.AppBaseURL, deps.Logger).
		WithSenders(senderSvc).
		WithTemplates(tmplSvc)
	authSvc.WithAccountBlocking(blockSvc).WithBreachDetection(breachSvc)

	// Audit logger — shared by both auth and admin handlers. Prefer the
	// caller-owned instance (main.go closes it on shutdown to drain the
	// async buffer); fall back to a local one for tests.
	auditLog := deps.Audit
	if auditLog == nil {
		auditLog = audit.New(deps.Pool, deps.Logger)
	}

	// Wire the audit logger into the send services so a template-disabled
	// suppression is recorded (auth.email_suppressed), giving operators a trail
	// when an email is intentionally not sent.
	resetSvc.WithAudit(auditLog)
	verifSvc.WithAudit(auditLog)
	emailMFASvc.WithAudit(auditLog)
	invSvc.WithAudit(auditLog)
	emailChangeSvc.WithAudit(auditLog)
	blockSvc.WithAudit(auditLog)
	breachSvc.WithAudit(auditLog)

	// Capture the real response status + (redacted) body and attach them to each
	// request's audit events. Registered here (after auditLog exists) so it wraps
	// the response writer before any handler runs. Body capture is gated by
	// config (default "failures") and always redacts secrets + PII.
	e.Use(mw.AuditCapture(auditLog, deps.Config.AuditCaptureResponseBody))

	cookieCfg := mw.BuildCookieConfig(deps.Config.Env, deps.Config.CookieDomain)

	authHandler := handlers.NewAuthHandler(authSvc, resetSvc, auditLog, deps.Logger).
		WithTOTP(totpSvc).
		WithEmailMFA(emailMFASvc).
		WithVerification(verifSvc).
		WithAPIKeys(apiKeySvc).
		WithApplications(appSvc).
		WithCookieConfig(cookieCfg).
		WithJWT(jwtSvc).
		WithRedis(deps.Redis).
		WithInvitations(invSvc).
		WithEmailChange(emailChangeSvc).
		WithAccountBlocking(blockSvc)

	// Admin service (Phase 5)
	adminSvc := admin.New(deps.Pool, resetSvc, deps.Logger).
		WithInvitations(invSvc).
		WithAccountBlocking(blockSvc)

	// Per-app rate limit service (08-02) — DB-backed, Redis-cached, 60s TTL.
	appLimitSvc := auth.NewAppRateLimitService(deps.Pool, deps.Redis, deps.Logger)

	// Per-tenant CORS service — DB-backed, Redis-cached, 60s TTL. Slug-less
	// requests (e.g. /auth/login) fall back to the global allow-list instead.
	corsSvc := mw.NewTenantCORSService(deps.Pool, deps.Redis, deps.Logger).
		WithGlobalOrigins(deps.Config.GlobalCORSOrigins)

	adminHandler := handlers.NewAdminHandler(adminSvc, auditLog, deps.Logger).
		WithAppRateLimits(appLimitSvc).
		WithApplications(appSvc).
		WithTOTP(totpSvc).
		WithEmailSenders(senderSvc).
		WithEmailTemplates(tmplSvc).
		WithMailer(m).
		WithCORS(corsSvc)

	// SAML service (Phase 4) — lightweight SP, no external dependencies.
	samlService := samlsvc.New(deps.Pool, deps.Config.AppBaseURL, deps.Logger)
	samlHandler := handlers.NewSAMLHandler(samlService, jwtSvc, deps.Logger)

	// Social login (issue #64 Google, issue #66 GitHub) — OAuth for app-scoped end users.
	// The secret box fails hard in production/staging when the key is unset;
	// in development it falls back to an insecure zero key with a warning.
	secretBox, sbErr := auth.NewSecretBox(deps.Config.OAuthClientSecretEncryptionKey, deps.Config.Env, "OAUTH_CLIENT_SECRET_ENCRYPTION_KEY", deps.Logger)
	if sbErr != nil {
		deps.Logger.Fatal().Err(sbErr).Msg("social login init failed — check OAUTH_CLIENT_SECRET_ENCRYPTION_KEY")
	}
	if err := secretBox.WithPreviousKey(deps.Config.OAuthClientSecretEncryptionKeyPrevious, "OAUTH_CLIENT_SECRET_ENCRYPTION_KEY_PREVIOUS"); err != nil {
		deps.Logger.Fatal().Err(err).Msg("social login init failed — check OAUTH_CLIENT_SECRET_ENCRYPTION_KEY_PREVIOUS")
	}
	// Asymmetric JWT signing keys (issue #95). Separate SecretBox from the OAuth
	// one: these protect token-SIGNING authority, so a compromise of the social
	// login secrets must not also hand over the ability to mint tokens, and the two
	// keys must be rotatable independently. Same fail-closed contract — no
	// zero-key fallback in production/staging.
	signingKeyBox, skbErr := auth.NewSecretBox(deps.Config.JWTSigningKeyEncryptionKey, deps.Config.Env, "JWT_SIGNING_KEY_ENCRYPTION_KEY", deps.Logger)
	if skbErr != nil {
		deps.Logger.Fatal().Err(skbErr).Msg("JWT signing key init failed — check JWT_SIGNING_KEY_ENCRYPTION_KEY")
	}
	if err := signingKeyBox.WithPreviousKey(deps.Config.JWTSigningKeyEncryptionKeyPrevious, "JWT_SIGNING_KEY_ENCRYPTION_KEY_PREVIOUS"); err != nil {
		deps.Logger.Fatal().Err(err).Msg("JWT signing key init failed — check JWT_SIGNING_KEY_ENCRYPTION_KEY_PREVIOUS")
	}
	signingKeySvc, skErr := auth.NewSigningKeyService(deps.Pool, signingKeyBox, deps.Logger)
	if skErr != nil {
		deps.Logger.Fatal().Err(skErr).Msg("JWT signing key service init failed")
	}
	// Switch signing to RS256. Verification continues to accept legacy HS256
	// tokens (no kid) until the Phase 4 cutover, so no live session breaks here.
	jwtSvc.WithSigningKeys(signingKeySvc).WithLegacyHS256(deps.Config.JWTAllowLegacyHS256)
	if !deps.Config.JWTAllowLegacyHS256 {
		deps.Logger.Warn().Msg("JWT_ALLOW_LEGACY_HS256=false — HS256 tokens are REJECTED (issue #95 Phase 4 cutover). Any token minted before RS256 signing went live will fail; tenants.jwt_secret is now unused and can be dropped.")
	}

	// Backfill keys for tenants that predate this feature so their JWKS endpoint is
	// live immediately rather than on their next login. Non-fatal: EnsureTenantKey
	// generates lazily, so a backfill failure costs latency, not availability.
	startupCtx, cancelStartup := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelStartup()
	if created, err := signingKeySvc.BackfillAllTenants(startupCtx); err != nil {
		deps.Logger.Error().Err(err).Msg("signing key backfill failed — keys will be generated lazily")
	} else if created > 0 {
		deps.Logger.Info().Int("tenants", created).Msg("backfilled JWT signing keys")
	}

	// Drop retired keys whose grace window has elapsed. Without this every rotation
	// leaves a row behind forever and the published JWKS grows without bound.
	if _, err := signingKeySvc.CollectGarbageAllTenants(startupCtx); err != nil {
		deps.Logger.Error().Err(err).Msg("retired signing key GC failed")
	}

	// JWT_ISSUER and APP_BASE_URL are independent settings that default to
	// different hosts, and OIDC convention derives a JWKS URL from the issuer. Now
	// that we publish keys, a mismatch means a verifier that follows convention
	// looks for our keys at the wrong host. APP_BASE_URL is authoritative for
	// discovery (it is where the endpoint actually is); warn loudly when the issuer
	// disagrees so an operator reconciles them deliberately.
	// Compares the per-tenant issuer origin (issue #7), not the legacy JWT_ISSUER
	// — see warnIssuerHostMismatch for why the operand changed.
	warnIssuerHostMismatch(deps.Config.OIDCIssuerBaseURL, deps.Config.AppBaseURL, deps.Config.Env, deps.Logger)

	// JWKS publication + signing-key rotation handlers (issue #95).
	jwksHandler := handlers.NewJWKSHandler(deps.Pool, signingKeySvc, deps.Logger)
	oidcHandler := handlers.NewOIDCHandler(deps.Pool, deps.Logger)
	signingKeyHandler := handlers.NewSigningKeyHandler(deps.Pool, signingKeySvc, deps.Config.AppBaseURL, auditLog, deps.Logger)

	// Give newly created tenants their key pair up front rather than lazily on
	// first login.
	adminSvc.WithSigningKeys(signingKeySvc)

	idpSvc := auth.NewIdentityProviderService(deps.Pool, secretBox, deps.Config.AppBaseURL, deps.Logger)
	oauthSvc := auth.NewOAuthLoginService(deps.Pool, deps.Redis, idpSvc, authSvc, deps.Config.AppBaseURL, deps.Logger)
	oauthHandler := handlers.NewOAuthHandler(oauthSvc, idpSvc, auditLog, deps.Logger)

	// OAuth 2.0 authorization server (issue #6) — EMC issuing its own
	// authorization codes, as opposed to oauthSvc above which consumes
	// Google's and GitHub's.
	authzSvc := auth.NewAuthorizationServer(deps.Pool, deps.Logger)
	authzSessions := auth.NewAuthzSessionStore(deps.Redis)
	authorizeHandler := handlers.NewOAuthAuthorizeHandler(
		authzSvc, authzSessions, authSvc, auditLog, deps.Logger, cookieCfg.Secure)
	oauthTokenHandler := handlers.NewOAuthTokenHandler(
		authzSvc, authSvc, jwtSvc, appSvc, auditLog, deps.Logger)

	// AppRateLimiter middleware — enforces per-app token-bucket limits keyed on
	// the JWT app_id (oauth_clients.id) + tenant_id claims. It MUST run after a
	// JWT middleware has populated claims, so it is applied per authenticated
	// group below (adminGroup + the JWT-renew protected auth routes), NOT globally.
	appRateLimit := mw.AppRateLimiter(appLimitSvc, deps.Redis, deps.Logger)

	// appClientRateLimit enforces the same per-app limit on the Basic-auth
	// application endpoints (token + /apps/*), keyed on the client_id.
	appClientRateLimit := mw.AppClientRateLimiter(appLimitSvc, deps.Redis, deps.Logger)

	// TenantCORS middleware — applies per-tenant CORS headers (reads X-Tenant-Slug header).
	e.Use(mw.TenantCORS(corsSvc))

	// Rate limiter config (AUTH-07: 5/min/IP, 10/min/tenant).
	rlCfg := mw.DefaultRateLimitConfig()

	// /api/v1 route group.
	//
	// CookieCSRF guards the whole surface against cross-site writes made with the
	// browser session cookies, which SameSite=None (staging/production) would
	// otherwise let any page attach. It is inert for Bearer clients, for safe
	// methods, and for requests carrying no auth cookie — see its doc comment.
	apiV1 := e.Group("/api/v1", mw.CookieCSRF(cookieCfg))

	// Auth routes — public (no JWT required)
	authGroup := apiV1.Group("/auth")
	authGroup.POST("/register", authHandler.Register)
	// Login is rate-limited at route level (not global) to avoid impacting other endpoints.
	authGroup.POST("/login", authHandler.Login, mw.LoginRateLimiter(rlCfg))
	// TOTP challenge completion + forced-enrollment endpoints (03-02, issue #63).
	// OTPRateLimiter bounds endpoint volume per IP and per session token; the
	// hard per-session cap of auth.MaxOTPAttempts incorrect codes lives in the
	// service layer (Redis INCR), so a 6-digit code cannot be brute-forced
	// within the challenge TTL.
	authGroup.POST("/login/otp", authHandler.LoginOTP, mw.OTPRateLimiter(rlCfg))                    // complete MFA-gated login (TOTP, backup, or emailed code)
	authGroup.POST("/login/otp/resend", authHandler.LoginOTPResend, mw.OTPRateLimiter(rlCfg))       // re-send the emailed login code (max 3/challenge)
	authGroup.POST("/login/mfa/enroll", authHandler.MFAEnrollPending, mw.OTPRateLimiter(rlCfg))     // forced enrollment, TOTP path: get QR + backup codes
	authGroup.POST("/login/mfa/email", authHandler.MFAEmailPending, mw.OTPRateLimiter(rlCfg))       // forced enrollment, email path: send code to inbox
	authGroup.POST("/login/mfa/activate", authHandler.MFAActivatePending, mw.OTPRateLimiter(rlCfg)) // forced enrollment: first code → tokens
	authGroup.POST("/refresh", authHandler.Refresh)
	authGroup.POST("/logout", authHandler.Logout)
	authGroup.POST("/forgot-password", authHandler.ForgotPassword, mw.TokenRateLimiter(rlCfg), appClientRateLimit)
	authGroup.POST("/reset-password", authHandler.ResetPassword)

	// Email verification — link is clicked (GET) from the email; resend is
	// rate-limited and enumeration-safe (tenant via X-Tenant-Slug).
	authGroup.GET("/verify-email", authHandler.VerifyEmail)
	authGroup.POST("/resend-verification", authHandler.ResendVerification, mw.TokenRateLimiter(rlCfg))

	// Landing points for the invitation, email-change, and unblock emails. All
	// three are token-authenticated (the token IS the credential), so they are
	// public but rate-limited: a bearer-token guard would be impossible to
	// satisfy from a link in an email.
	authGroup.POST("/accept-invitation", authHandler.AcceptInvitation, mw.TokenRateLimiter(rlCfg))
	// Read-only companion so the landing page can tell an onboarding link (set a
	// password) from a confirmation link (an existing account accepting an
	// administrative grant). Does not consume the token.
	authGroup.GET("/invitation", authHandler.PreviewInvitation, mw.TokenRateLimiter(rlCfg))
	authGroup.GET("/confirm-email-change", authHandler.ConfirmEmailChange, mw.TokenRateLimiter(rlCfg))
	authGroup.GET("/unblock-account", authHandler.UnblockAccount, mw.TokenRateLimiter(rlCfg))

	// Management token — exchange an API key for a short-lived admin JWT.
	// Equivalent to Auth0 client_credentials grant for the Management API.
	// Usage: POST /api/v1/auth/management-token with X-API-Key: emck_<key>
	authGroup.POST("/management-token", authHandler.ManagementToken)

	// Cookie-based session endpoints for browser/SPA clients (sets HttpOnly cookies).
	// SessionCSRF guards against cross-site form-POST attacks when SameSite=None is
	// active (staging/production); it is a no-op in development (SameSite=Lax).
	sessionCSRF := mw.SessionCSRF(cookieCfg)
	authGroup.POST("/session", authHandler.SessionLogin, sessionCSRF)
	authGroup.POST("/session/refresh", authHandler.SessionRefresh, sessionCSRF)
	authGroup.POST("/session/logout", authHandler.SessionLogout, sessionCSRF)

	// Client credentials token endpoint — machine-to-machine auth (no user).
	// TokenRateLimiter keys per client_id (not email) so each M2M client gets
	// an isolated bucket instead of all sharing one email-less fallback bucket;
	// appClientRateLimit layers the tenant-configured per-app limit on top,
	// keyed on the same client_id → application.
	authGroup.POST("/token", authHandler.Token, mw.TokenRateLimiter(rlCfg), appClientRateLimit)

	// Application-authenticated end-user register/login (Auth0-style
	// integration): the calling application authenticates itself via
	// Authorization: Basic, and gets its own isolated end-user base, distinct
	// from /register and /login above (which are tenant-level, first-party
	// only). Rate-limited per client_id — same reasoning as /token.
	authGroup.POST("/apps/register", authHandler.AppRegister, mw.TokenRateLimiter(rlCfg), appClientRateLimit)
	authGroup.POST("/apps/login", authHandler.AppLogin, mw.TokenRateLimiter(rlCfg), appClientRateLimit)

	// Passwordless magic-link sign-in (issue #63 follow-on) — per-application
	// opt-in. The link replaces only the password step: verification runs the
	// same MFA gate as /apps/login, so a 'required' app still challenges.
	authGroup.POST("/apps/login/magic", authHandler.AppMagicLink, mw.TokenRateLimiter(rlCfg), appClientRateLimit)
	authGroup.POST("/apps/login/magic/verify", authHandler.AppMagicLinkVerify, mw.TokenRateLimiter(rlCfg), appClientRateLimit)

	// jwtRenew is used on all cookie-aware protected routes.
	// It validates the access token and, when expired, transparently rotates
	// the refresh token (distributed lock + fresh user DB load) and writes new
	// cookies onto the response before the handler body is flushed.
	jwtRenew := mw.JWTRenew(jwtSvc, authSvc, deps.Redis, cookieCfg, auditLog, deps.Logger)

	// Auth routes — protected with transparent renewal (AUTH-09)
	authGroup.GET("/me", authHandler.Me, jwtRenew, appRateLimit)

	// App-scoped identity (issue #96). Additive — /auth/me above is untouched, so
	// admin and browser sessions cannot regress.
	//
	// Mounted behind the SAME jwtRenew middleware as /auth/me, so it inherits
	// signature, issuer, expiry, tenant, and audience verification rather than
	// re-implementing them; the handler adds only the application-boundary check.
	//
	// Middleware order matters here, and Echo runs them left-to-right:
	//
	//	TokenRateLimiter → appClientRateLimit → Normalize… → jwtRenew → AppMe
	//
	// Both limiters sit AHEAD of jwtRenew. Behind it, they would only ever run
	// for callers who already hold a valid token, so anyone with an expired or
	// forged one could drive the app lookups underneath at full speed — the
	// unauthenticated traffic a limiter exists for would be the traffic it never
	// saw. TokenRateLimiter is first because it is purely in-memory and per IP:
	// it fences the DB read appClientRateLimit performs to resolve a client_id.
	// This is the same pairing every other /apps/* route uses.
	//
	// appClientRateLimit rather than appRateLimit: this endpoint bears client
	// credentials, so it is keyed on client_id like every other /apps/* route.
	// It finds them in X-Client-Authorization (mw.ClientAuthHeader) — this route
	// cannot put them in Authorization, which carries the user's Bearer token.
	//
	// NormalizeAppScopeUnauthorized wraps jwtRenew so its 401s (e.g.
	// token_expired) come back as the same generic token_invalid AppMe uses —
	// see that middleware's doc comment. It sits inside the limiters because a
	// 429 is not a rejection this endpoint's no-oracle contract covers: it
	// reveals nothing about the token, and disguising it as 401 would strip the
	// Retry-After signal a well-behaved client needs.
	authGroup.GET("/apps/me", authHandler.AppMe,
		mw.TokenRateLimiter(rlCfg), appClientRateLimit, mw.NormalizeAppScopeUnauthorized, jwtRenew)
	authGroup.GET("/my-activity", authHandler.MyActivity, jwtRenew, appRateLimit)

	// Self-service email change — authenticated: the user must prove who they are
	// to start it, and prove control of the new inbox to finish it (the GET
	// confirm route above). Rate-limited so the confirmation mail cannot be used
	// to spam an arbitrary address.
	authGroup.POST("/change-email", authHandler.ChangeEmail, jwtRenew, appRateLimit, mw.TokenRateLimiter(rlCfg))

	// TOTP management — protected (03-01)
	otpGroup := authGroup.Group("/otp", jwtRenew, appRateLimit)
	otpGroup.POST("/enroll", authHandler.TOTPEnroll)
	otpGroup.POST("/activate", authHandler.TOTPActivate)
	otpGroup.GET("/status", authHandler.TOTPStatus)                 // all-method MFA state + backup codes remaining
	otpGroup.POST("/backup-codes", authHandler.TOTPRegenerateCodes) // fresh set of 8, secret unchanged
	otpGroup.DELETE("", authHandler.TOTPDisable)

	// Email MFA self-service (issue #63) — one-time codes to the account inbox.
	otpGroup.POST("/email/enroll", authHandler.EmailMFAEnroll)     // policy-checked; sends verification code
	otpGroup.POST("/email/activate", authHandler.EmailMFAActivate) // confirm code → method active
	otpGroup.POST("/email/send", authHandler.EmailMFASendCode)     // fresh code as proof for self-service actions
	otpGroup.DELETE("/email", authHandler.EmailMFADisable)         // code-verified; last-factor guard under 'required'

	// Admin routes — require a valid JWT, supplied either as a Bearer token or as
	// the emc_access_token cookie (scoped to /api/v1, so browser sessions reach
	// these routes). JWTRequired (not JWTRenew) is used here because the refresh
	// cookie stays scoped to /api/v1/auth; browsers will not send it to non-auth
	// paths, so transparent renewal is impossible. Browser clients must call
	// /auth/session/refresh when they receive 401 token_expired, then retry the
	// admin request.
	// appRateLimit is a pass-through for first-party admin/tenant tokens: those
	// JWTs are minted with an empty app_id claim (only application-scoped end-user
	// tokens carry a numeric app_id), and AppRateLimiter skips any request whose
	// app_id is empty. So mounting it here cannot rate-limit an operator out of
	// the rate-limit CRUD routes below — the limiter only ever engages for
	// application-scoped traffic, never for the admin console's own calls.
	//
	// Accepted token types (issue #84): admin/management routes have three
	// legitimate kinds of caller, so all three audiences are allowed here and
	// authorization stays with the RequirePermission guards below —
	//   - AudienceAPI:        a human operator in the admin SPA
	//   - AudienceManagement: an API-key integration (POST /auth/management-token)
	//   - AudienceM2M:        a client_credentials machine client, whose grants
	//                         come from oauth_clients.scopes
	// Agent tokens are deliberately absent — nothing verifies them yet.
	adminGroup := apiV1.Group("", mw.JWTRequired(
		jwtSvc,
		auth.AudienceAPI,
		auth.AudienceManagement,
		auth.AudienceM2M,
	), appRateLimit)

	// Ping (smoke test — requires admin:access)
	adminGroup.GET("/ping", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "admin ping ok"})
	}, mw.RequirePermission("admin:access"))

	// GET /tenants and /tenants/stats: any authenticated user, not just
	// tenant:manage — the handlers branch internally on the caller's permissions
	// (platform admins get every tenant; everyone else gets only the tenants
	// tied to their own email). Registered before tenantMgmt so /stats isn't
	// shadowed by tenantMgmt's /tenants/:id.
	adminGroup.GET("/tenants", adminHandler.ListTenants)
	adminGroup.GET("/tenants/stats", adminHandler.GetTenantDashboardStats)

	// Tenant management — remaining routes require tenant:manage (super_admin only).
	tenantMgmt := adminGroup.Group("", mw.RequirePermission("tenant:manage"))
	tenantMgmt.POST("/tenants", adminHandler.CreateTenant)
	// Static sub-paths registered before /:id so Echo does not treat them as ID params.
	// Cross-tenant administrator directory. Platform oversight, so it lives on
	// tenantMgmt (tenant:manage) rather than the tenant-scoped family, and is
	// registered before /tenants/:id so the static path is not read as an id.
	tenantMgmt.GET("/administrators", adminHandler.ListPlatformAdministrators)
	tenantMgmt.GET("/administrators/stats", adminHandler.PlatformAdminSummary)

	tenantMgmt.GET("/tenants/check-slug", adminHandler.CheckSlug)
	tenantMgmt.GET("/tenants/:id", adminHandler.GetTenant)
	tenantMgmt.PUT("/tenants/:id", adminHandler.UpdateTenant)
	tenantMgmt.PUT("/tenants/:id/activate", adminHandler.ActivateTenant)
	tenantMgmt.DELETE("/tenants/:id", adminHandler.DeactivateTenant)
	tenantMgmt.PUT("/tenants/:id/cors-origins", adminHandler.UpdateTenantCORSOrigins)

	// Canonical tenant-scoped resource routes — /tenants/:tid/... is ONE URL
	// family serving both personas: super_admin (tenant:manage, any :tid) and
	// the tenant's own admins (:tid must match the JWT tenant + the granular
	// resource permission). Clients never branch on role to pick a URL.
	tidPermsRead := mw.RequireTenantSelfOrAny("permissions:read")
	tidPermsWrite := mw.RequireTenantSelfOrAny("permissions:write")
	tidRolesRead := mw.RequireTenantSelfOrAny("roles:read")
	tidRolesWrite := mw.RequireTenantSelfOrAny("roles:write")
	tidUsersRead := mw.RequireTenantSelfOrAny("users:read")
	tidUsersWrite := mw.RequireTenantSelfOrAny("users:write")
	tidAppsRead := mw.RequireTenantSelfOrAny("apps:read")
	tidAppsList := mw.RequireTenantSelfScoped("apps:read")
	tidAppsWrite := mw.RequireTenantSelfOrAny("apps:write")
	// Monitoring is scoped, not withheld: a co-owner reaches these and the
	// handlers narrow the result to the applications they administer
	// (monitoringScope). An owner sees the whole tenant; super_admin sees
	// everything.
	tidStatsRead := mw.RequireTenantSelfScoped("stats:read")

	// Per-application variants (issue #97). Same tenant + permission check as
	// above, plus "does this administrator's scope actually cover THIS
	// application?" — the question RequireTenantSelfOrAny cannot ask, and which
	// a co-owner granted one application would otherwise pass for every
	// application in the tenant.
	//
	// The "id" suffixed pair guard /applications/:id, where the application's
	// own row id is bound to :id rather than :appID.
	appPermsRead := mw.RequireAppScope("appID", "permissions:read")
	appPermsWrite := mw.RequireAppScope("appID", "permissions:write")
	appRolesRead := mw.RequireAppScope("appID", "roles:read")
	appRolesWrite := mw.RequireAppScope("appID", "roles:write")
	appUsersRead := mw.RequireAppScope("appID", "users:read")
	appUsersWrite := mw.RequireAppScope("appID", "users:write")
	appAppsRead := mw.RequireAppScope("appID", "apps:read")
	appAppsWrite := mw.RequireAppScope("appID", "apps:write")
	appIDAppsRead := mw.RequireAppScope("id", "apps:read")
	appIDAppsWrite := mw.RequireAppScope("id", "apps:write")

	adminGroup.GET("/tenants/:tid/permissions", adminHandler.ListPermissions, tidPermsRead)
	adminGroup.POST("/tenants/:tid/permissions", adminHandler.CreatePermission, tidPermsWrite)
	adminGroup.PUT("/tenants/:tid/permissions/:pid", adminHandler.UpdatePermission, tidPermsWrite)
	adminGroup.DELETE("/tenants/:tid/permissions/:pid", adminHandler.DeletePermission, tidPermsWrite)
	adminGroup.GET("/tenants/:tid/roles", adminHandler.TenantListRoles, tidRolesRead)
	adminGroup.POST("/tenants/:tid/roles", adminHandler.TenantCreateRole, tidRolesWrite)
	adminGroup.PUT("/tenants/:tid/roles/:rid/permissions", adminHandler.TenantUpdateRolePermissions, tidRolesWrite)
	adminGroup.DELETE("/tenants/:tid/roles/:rid", adminHandler.TenantDeleteRole, tidRolesWrite)
	adminGroup.GET("/tenants/:tid/users", adminHandler.ListUsers, tidUsersRead)
	adminGroup.POST("/tenants/:tid/users", adminHandler.CreateAdminUser, tidUsersWrite)
	adminGroup.GET("/tenants/:tid/users/:uid", adminHandler.GetAdminUser, tidUsersRead)
	adminGroup.PUT("/tenants/:tid/users/:uid", adminHandler.UpdateAdminUser, tidUsersWrite)
	adminGroup.PUT("/tenants/:tid/users/:uid/role", adminHandler.AssignUserRole, tidUsersWrite)
	adminGroup.POST("/tenants/:tid/users/:uid/force-password-reset", adminHandler.ForcePasswordReset, tidUsersWrite)
	adminGroup.POST("/tenants/:tid/users/:uid/invite", adminHandler.ResendInvitation, tidUsersWrite)
	adminGroup.DELETE("/tenants/:tid/users/:uid", adminHandler.DeleteAdminUser, tidUsersWrite)
	adminGroup.GET("/tenants/:tid/users/:uid/detail", adminHandler.GetAdminUserDetail, tidUsersRead)
	adminGroup.PUT("/tenants/:tid/users/:uid/status", adminHandler.SetUserStatus, tidUsersWrite)
	adminGroup.GET("/tenants/:tid/users/:uid/sessions", adminHandler.ListUserSessions, tidUsersRead)
	adminGroup.DELETE("/tenants/:tid/users/:uid/sessions", adminHandler.RevokeAllUserSessions, tidUsersWrite)
	adminGroup.DELETE("/tenants/:tid/users/:uid/sessions/:familyID", adminHandler.RevokeUserSession, tidUsersWrite)
	adminGroup.GET("/tenants/:tid/users/:uid/mfa", adminHandler.GetUserMFAStatus, tidUsersRead)

	// Application management under the canonical family — same handlers as
	// the flat /applications aliases; the :tid path param overrides the JWT
	// tenant (super_admin) or must equal it (tenant admins).
	// The list is the one tenant-level route a co-owner must reach: it is how
	// they find the applications they administer. ListApplications narrows the
	// response to their grants — see RequireTenantSelfScoped.
	adminGroup.GET("/tenants/:tid/applications", adminHandler.ListApplications, tidAppsList)
	adminGroup.POST("/tenants/:tid/applications", adminHandler.CreateApplication, tidAppsWrite)
	adminGroup.GET("/tenants/:tid/applications/:id", adminHandler.GetApplication, appIDAppsRead)
	adminGroup.PUT("/tenants/:tid/applications/:id", adminHandler.UpdateApplication, appIDAppsWrite)
	adminGroup.DELETE("/tenants/:tid/applications/:id", adminHandler.DeactivateApplication, appIDAppsWrite)
	adminGroup.POST("/tenants/:tid/applications/:id/rotate-secret", adminHandler.RotateApplicationSecret, appIDAppsWrite)

	// End-user application roles under the canonical family (mirrors the flat
	// /applications/:appID/roles aliases registered below).
	adminGroup.POST("/tenants/:tid/applications/:appID/roles", adminHandler.CreateApplicationRole, appRolesWrite)
	adminGroup.GET("/tenants/:tid/applications/:appID/roles", adminHandler.ListApplicationRoles, appRolesRead)
	adminGroup.PUT("/tenants/:tid/applications/:appID/roles/:id", adminHandler.UpdateApplicationRole, appRolesWrite)
	adminGroup.PUT("/tenants/:tid/applications/:appID/roles/:id/permissions", adminHandler.UpdateRolePermissions, appRolesWrite)
	adminGroup.PUT("/tenants/:tid/applications/:appID/roles/:id/default", adminHandler.SetDefaultApplicationRole, appRolesWrite)
	adminGroup.DELETE("/tenants/:tid/applications/:appID/roles/:id", adminHandler.DeleteRole, appRolesWrite)

	// End-user application permissions under the canonical family.
	adminGroup.POST("/tenants/:tid/applications/:appID/permissions", adminHandler.CreatePermission, appPermsWrite)
	adminGroup.GET("/tenants/:tid/applications/:appID/permissions", adminHandler.ListPermissions, appPermsRead)
	adminGroup.PUT("/tenants/:tid/applications/:appID/permissions/:pid", adminHandler.UpdatePermission, appPermsWrite)
	adminGroup.DELETE("/tenants/:tid/applications/:appID/permissions/:pid", adminHandler.DeletePermission, appPermsWrite)

	// Per-application MFA policy under the canonical family (issue #63) —
	// owner (apps:read/apps:write, own tenant) and super_admin (tenant:manage,
	// any tenant) manage each application's MFA mode; MFA policy is
	// application configuration, so it rides the apps:* permissions.
	adminGroup.GET("/tenants/:tid/applications/:appID/mfa", adminHandler.GetApplicationMFA, appAppsRead)
	adminGroup.PUT("/tenants/:tid/applications/:appID/mfa", adminHandler.UpdateApplicationMFA, appAppsWrite)
	adminGroup.DELETE("/tenants/:tid/applications/:appID/users/:uid/mfa", adminHandler.ResetUserMFA, appUsersWrite)

	// White-label email senders under the canonical family (issue #63
	// follow-on) — tenant-level sender plus optional per-application override;
	// MFA code emails resolve application → tenant → global.
	adminGroup.GET("/tenants/:tid/email-settings", adminHandler.GetEmailSender, tidAppsRead)
	adminGroup.PUT("/tenants/:tid/email-settings", adminHandler.UpsertEmailSender, tidAppsWrite)
	adminGroup.DELETE("/tenants/:tid/email-settings", adminHandler.DeleteEmailSender, tidAppsWrite)
	adminGroup.POST("/tenants/:tid/email-settings/test", adminHandler.SendTestEmail, tidAppsWrite, mw.TokenRateLimiter(rlCfg))
	adminGroup.GET("/tenants/:tid/applications/:appID/email-settings", adminHandler.GetEmailSender, appAppsRead)
	adminGroup.PUT("/tenants/:tid/applications/:appID/email-settings", adminHandler.UpsertEmailSender, appAppsWrite)
	adminGroup.DELETE("/tenants/:tid/applications/:appID/email-settings", adminHandler.DeleteEmailSender, appAppsWrite)
	adminGroup.POST("/tenants/:tid/applications/:appID/email-settings/test", adminHandler.SendTestEmail, appAppsWrite, mw.TokenRateLimiter(rlCfg))

	// Per-scope email templates (Auth0-style) — same guards as senders.
	adminGroup.GET("/tenants/:tid/email-templates", adminHandler.ListEmailTemplates, tidAppsRead)
	adminGroup.GET("/tenants/:tid/email-templates/:type", adminHandler.GetEmailTemplate, tidAppsRead)
	adminGroup.PUT("/tenants/:tid/email-templates/:type", adminHandler.UpsertEmailTemplate, tidAppsWrite)
	adminGroup.DELETE("/tenants/:tid/email-templates/:type", adminHandler.DeleteEmailTemplate, tidAppsWrite)
	adminGroup.GET("/tenants/:tid/applications/:appID/email-templates", adminHandler.ListEmailTemplates, appAppsRead)
	adminGroup.GET("/tenants/:tid/applications/:appID/email-templates/:type", adminHandler.GetEmailTemplate, appAppsRead)
	adminGroup.PUT("/tenants/:tid/applications/:appID/email-templates/:type", adminHandler.UpsertEmailTemplate, appAppsWrite)
	adminGroup.DELETE("/tenants/:tid/applications/:appID/email-templates/:type", adminHandler.DeleteEmailTemplate, appAppsWrite)

	// End-user application users under the canonical family — each
	// application manages its own isolated user base.
	adminGroup.GET("/tenants/:tid/applications/:appID/users", adminHandler.ListUsers, appUsersRead)
	adminGroup.POST("/tenants/:tid/applications/:appID/users", adminHandler.CreateAdminUser, appUsersWrite)
	adminGroup.GET("/tenants/:tid/applications/:appID/users/:uid", adminHandler.GetAdminUser, appUsersRead)
	adminGroup.PUT("/tenants/:tid/applications/:appID/users/:uid", adminHandler.UpdateAdminUser, appUsersWrite)
	adminGroup.PUT("/tenants/:tid/applications/:appID/users/:uid/role", adminHandler.AssignUserRole, appUsersWrite)
	adminGroup.POST("/tenants/:tid/applications/:appID/users/:uid/force-password-reset", adminHandler.ForcePasswordReset, appUsersWrite)
	adminGroup.POST("/tenants/:tid/applications/:appID/users/:uid/invite", adminHandler.ResendInvitation, appUsersWrite)
	adminGroup.DELETE("/tenants/:tid/applications/:appID/users/:uid", adminHandler.DeleteAdminUser, appUsersWrite)
	adminGroup.GET("/tenants/:tid/applications/:appID/users/:uid/detail", adminHandler.GetAdminUserDetail, appUsersRead)
	adminGroup.PUT("/tenants/:tid/applications/:appID/users/:uid/status", adminHandler.SetUserStatus, appUsersWrite)
	adminGroup.GET("/tenants/:tid/applications/:appID/users/:uid/sessions", adminHandler.ListUserSessions, appUsersRead)
	adminGroup.DELETE("/tenants/:tid/applications/:appID/users/:uid/sessions", adminHandler.RevokeAllUserSessions, appUsersWrite)
	adminGroup.DELETE("/tenants/:tid/applications/:appID/users/:uid/sessions/:familyID", adminHandler.RevokeUserSession, appUsersWrite)
	adminGroup.GET("/tenants/:tid/applications/:appID/users/:uid/mfa", adminHandler.GetUserMFAStatus, appUsersRead)

	// Tenant administration — owners and co-owners (issue #97). Tenant-level
	// routes, so RequireTenantSelfOrAny already refuses a co-owner: an
	// administrator scoped to particular applications has no say in who else
	// administers the tenant. Guarded by users:* because administrators are
	// users; there is no separate admins:* permission to add to every role.
	adminGroup.GET("/tenants/:tid/admins", adminHandler.ListTenantAdmins, tidUsersRead)
	// TokenRateLimiter, as on every other route that dispatches mail: inviting
	// (and re-inviting) an administrator sends to an arbitrary external address,
	// so without it a tenant owner is an open relay bounded only by request rate.
	adminGroup.POST("/tenants/:tid/admins", adminHandler.InviteTenantAdmin, tidUsersWrite, mw.TokenRateLimiter(rlCfg))
	adminGroup.PUT("/tenants/:tid/admins/:adminID/applications", adminHandler.SetTenantAdminGrants, tidUsersWrite)
	adminGroup.DELETE("/tenants/:tid/admins/:adminID", adminHandler.RemoveTenantAdmin, tidUsersWrite)

	// Tenant stats + activity feed (EMC-004 tenant overview page).
	adminGroup.GET("/tenants/:tid/stats", adminHandler.TenantGetStats, tidStatsRead)
	adminGroup.GET("/tenants/:tid/activity", adminHandler.TenantGetActivity, tidStatsRead)

	// Tenant-admin routes are guarded by granular per-resource permissions
	// (seeded onto every tenant's "owner" role at creation), with "admin:access"
	// accepted everywhere as the coarse fallback held by super_admin.
	permsRead := mw.RequireAnyPermission("permissions:read", "admin:access")
	permsWrite := mw.RequireAnyPermission("permissions:write", "admin:access")
	rolesRead := mw.RequireAnyPermission("roles:read", "admin:access")
	rolesWrite := mw.RequireAnyPermission("roles:write", "admin:access")
	usersRead := mw.RequireAnyPermission("users:read", "admin:access")
	usersWrite := mw.RequireAnyPermission("users:write", "admin:access")
	appsRead := mw.RequireAnyPermission("apps:read", "admin:access")
	appsWrite := mw.RequireAnyPermission("apps:write", "admin:access")
	// Monitoring is the one flat family a co-owner may call: the handlers narrow
	// audit events and stats to the applications they administer
	// (monitoringScope). Everything else on the flat routes acts on the tenant
	// as a whole and is tenant-wide only.
	auditRead := mw.RequireAnyPermissionScoped("audit:read", "admin:access")
	statsRead := mw.RequireAnyPermissionScoped("stats:read", "admin:access")
	samlManage := mw.RequireAnyPermission("saml:manage", "admin:access")

	// Permission management — permissions:read / permissions:write
	adminGroup.POST("/permissions", adminHandler.CreatePermission, permsWrite)
	adminGroup.GET("/permissions", adminHandler.ListPermissions, permsRead)
	adminGroup.PUT("/permissions/:id", adminHandler.UpdatePermission, permsWrite)
	adminGroup.DELETE("/permissions/:id", adminHandler.DeletePermission, permsWrite)

	// Role management — roles:read / roles:write
	adminGroup.POST("/roles", adminHandler.CreateRole, rolesWrite)
	adminGroup.GET("/roles", adminHandler.ListRoles, rolesRead)
	adminGroup.PUT("/roles/:id/permissions", adminHandler.UpdateRolePermissions, rolesWrite)
	adminGroup.DELETE("/roles/:id", adminHandler.DeleteRole, rolesWrite)

	// User pool management — users:read / users:write
	adminGroup.GET("/users", adminHandler.ListUsers, usersRead)
	adminGroup.POST("/users", adminHandler.CreateAdminUser, usersWrite)
	adminGroup.GET("/users/:id", adminHandler.GetAdminUser, usersRead)
	adminGroup.PUT("/users/:id", adminHandler.UpdateAdminUser, usersWrite)
	adminGroup.PUT("/users/:id/role", adminHandler.AssignUserRole, usersWrite)
	adminGroup.DELETE("/users/:id", adminHandler.DeleteAdminUser, usersWrite)
	adminGroup.POST("/users/:id/force-password-reset", adminHandler.ForcePasswordReset, usersWrite)
	adminGroup.GET("/users/:id/detail", adminHandler.GetAdminUserDetail, usersRead)
	adminGroup.PUT("/users/:id/status", adminHandler.SetUserStatus, usersWrite)
	adminGroup.GET("/users/:id/sessions", adminHandler.ListUserSessions, usersRead)
	adminGroup.DELETE("/users/:id/sessions", adminHandler.RevokeAllUserSessions, usersWrite)
	adminGroup.DELETE("/users/:id/sessions/:familyID", adminHandler.RevokeUserSession, usersWrite)
	adminGroup.GET("/users/:id/mfa", adminHandler.GetUserMFAStatus, usersRead)

	// API key management — apps:read / apps:write (keys are machine credentials) (03-03)
	adminGroup.POST("/api-keys", authHandler.CreateAPIKey, appsWrite)
	adminGroup.GET("/api-keys", authHandler.ListAPIKeys, appsRead)
	adminGroup.DELETE("/api-keys/:id", authHandler.RevokeAPIKey, appsWrite)

	// Monitoring stats — tenant-scoped (stats:read) and system-wide (tenant:manage)
	adminGroup.GET("/stats", adminHandler.GetStats, statsRead)
	tenantMgmt.GET("/stats/system", adminHandler.GetSystemStats)

	// Audit logs — tenant-scoped (audit:read) and system-wide (tenant:manage).
	// List (summary) + detail-by-id, mirroring the list → drill-down UX.
	adminGroup.GET("/audit-logs", adminHandler.GetTenantAuditLogs, auditRead)
	// Expensive compliance endpoints carry a per-tenant rate limit on top of JWT:
	// export streams up to maxExportRows and verify recomputes the whole chain.
	auditMaintLimit := mw.AuditMaintenanceRateLimiter(0)
	adminGroup.GET("/audit-logs/export", adminHandler.ExportAuditLogs, auditRead, auditMaintLimit)
	adminGroup.GET("/audit-logs/:id", adminHandler.GetTenantAuditLogByID, auditRead)
	tenantMgmt.GET("/audit-logs/system", adminHandler.GetSystemAuditLogs)
	tenantMgmt.GET("/audit-logs/system/:id", adminHandler.GetSystemAuditLogByID)
	// Compliance surfaces — super_admin only (tenant:manage), rate-limited per tenant.
	tenantMgmt.GET("/audit-logs/verify", adminHandler.VerifyAuditChain, auditMaintLimit)
	tenantMgmt.POST("/audit-logs/erase-user", adminHandler.EraseUserAudit, auditMaintLimit)

	// Application management — apps:read / apps:write (tenant from JWT claims)
	adminGroup.POST("/applications", adminHandler.CreateApplication, appsWrite)
	adminGroup.GET("/applications", adminHandler.ListApplications, appsRead)
	adminGroup.GET("/applications/:id", adminHandler.GetApplication, appsRead)
	adminGroup.PUT("/applications/:id", adminHandler.UpdateApplication, appsWrite)
	adminGroup.DELETE("/applications/:id", adminHandler.DeactivateApplication, appsWrite)
	adminGroup.POST("/applications/:id/rotate-secret", adminHandler.RotateApplicationSecret, appsWrite)

	// End-user application roles — roles:read / roles:write, scoped to one of
	// the caller's own applications. :id (role) reuses UpdateRolePermissions /
	// DeleteRole unchanged, since those already scope by tenant + role id.
	adminGroup.POST("/applications/:appID/roles", adminHandler.CreateApplicationRole, rolesWrite)
	adminGroup.GET("/applications/:appID/roles", adminHandler.ListApplicationRoles, rolesRead)
	adminGroup.PUT("/applications/:appID/roles/:id", adminHandler.UpdateApplicationRole, rolesWrite)
	adminGroup.PUT("/applications/:appID/roles/:id/permissions", adminHandler.UpdateRolePermissions, rolesWrite)
	adminGroup.PUT("/applications/:appID/roles/:id/default", adminHandler.SetDefaultApplicationRole, rolesWrite)
	adminGroup.DELETE("/applications/:appID/roles/:id", adminHandler.DeleteRole, rolesWrite)

	// End-user application permissions — each application owns an isolated
	// permission catalog; roles inside the application may only hold
	// permissions from this catalog.
	adminGroup.POST("/applications/:appID/permissions", adminHandler.CreatePermission, permsWrite)
	adminGroup.GET("/applications/:appID/permissions", adminHandler.ListPermissions, permsRead)
	adminGroup.PUT("/applications/:appID/permissions/:pid", adminHandler.UpdatePermission, permsWrite)
	adminGroup.DELETE("/applications/:appID/permissions/:pid", adminHandler.DeletePermission, permsWrite)

	// Per-application MFA policy — flat aliases of the canonical
	// /tenants/:tid/applications/:appID/mfa family (issue #63).
	adminGroup.GET("/applications/:appID/mfa", adminHandler.GetApplicationMFA, appsRead)
	adminGroup.PUT("/applications/:appID/mfa", adminHandler.UpdateApplicationMFA, appsWrite)
	adminGroup.DELETE("/applications/:appID/users/:uid/mfa", adminHandler.ResetUserMFA, usersWrite)

	// White-label email senders — flat aliases (tenant from JWT).
	adminGroup.GET("/email-settings", adminHandler.GetEmailSender, appsRead)
	adminGroup.PUT("/email-settings", adminHandler.UpsertEmailSender, appsWrite)
	adminGroup.DELETE("/email-settings", adminHandler.DeleteEmailSender, appsWrite)
	adminGroup.POST("/email-settings/test", adminHandler.SendTestEmail, appsWrite, mw.TokenRateLimiter(rlCfg))
	adminGroup.GET("/applications/:appID/email-settings", adminHandler.GetEmailSender, appsRead)
	adminGroup.PUT("/applications/:appID/email-settings", adminHandler.UpsertEmailSender, appsWrite)
	adminGroup.DELETE("/applications/:appID/email-settings", adminHandler.DeleteEmailSender, appsWrite)
	adminGroup.POST("/applications/:appID/email-settings/test", adminHandler.SendTestEmail, appsWrite, mw.TokenRateLimiter(rlCfg))

	// Flat email-template aliases (tenant from JWT).
	adminGroup.GET("/email-templates", adminHandler.ListEmailTemplates, appsRead)
	adminGroup.GET("/email-templates/:type", adminHandler.GetEmailTemplate, appsRead)
	adminGroup.PUT("/email-templates/:type", adminHandler.UpsertEmailTemplate, appsWrite)
	adminGroup.DELETE("/email-templates/:type", adminHandler.DeleteEmailTemplate, appsWrite)
	adminGroup.GET("/applications/:appID/email-templates", adminHandler.ListEmailTemplates, appsRead)
	adminGroup.GET("/applications/:appID/email-templates/:type", adminHandler.GetEmailTemplate, appsRead)
	adminGroup.PUT("/applications/:appID/email-templates/:type", adminHandler.UpsertEmailTemplate, appsWrite)
	adminGroup.DELETE("/applications/:appID/email-templates/:type", adminHandler.DeleteEmailTemplate, appsWrite)

	// End-user application users — each application manages its own isolated
	// user base (flat aliases of the canonical /tenants/:tid variants).
	adminGroup.GET("/applications/:appID/users", adminHandler.ListUsers, usersRead)
	adminGroup.POST("/applications/:appID/users", adminHandler.CreateAdminUser, usersWrite)
	adminGroup.GET("/applications/:appID/users/:uid", adminHandler.GetAdminUser, usersRead)
	adminGroup.PUT("/applications/:appID/users/:uid", adminHandler.UpdateAdminUser, usersWrite)
	adminGroup.PUT("/applications/:appID/users/:uid/role", adminHandler.AssignUserRole, usersWrite)
	adminGroup.POST("/applications/:appID/users/:uid/force-password-reset", adminHandler.ForcePasswordReset, usersWrite)
	adminGroup.DELETE("/applications/:appID/users/:uid", adminHandler.DeleteAdminUser, usersWrite)
	adminGroup.GET("/applications/:appID/users/:uid/detail", adminHandler.GetAdminUserDetail, usersRead)
	adminGroup.PUT("/applications/:appID/users/:uid/status", adminHandler.SetUserStatus, usersWrite)
	adminGroup.GET("/applications/:appID/users/:uid/sessions", adminHandler.ListUserSessions, usersRead)
	adminGroup.DELETE("/applications/:appID/users/:uid/sessions", adminHandler.RevokeAllUserSessions, usersWrite)
	adminGroup.DELETE("/applications/:appID/users/:uid/sessions/:familyID", adminHandler.RevokeUserSession, usersWrite)
	adminGroup.GET("/applications/:appID/users/:uid/mfa", adminHandler.GetUserMFAStatus, usersRead)

	// Per-app rate limit management — apps:read / apps:write (08-02).
	// Keyed on the numeric application id (oauth_clients.id), consistent with
	// the /applications/:appID family and the JWT app_id claim. PUT upserts the
	// single limit for the app; GET/DELETE read/clear it. ListAppLimits returns
	// every configured limit for the caller's tenant.
	adminGroup.GET("/app-limits", adminHandler.ListAppLimits, appsRead)
	adminGroup.GET("/applications/:appID/rate-limit", adminHandler.GetAppLimit, appsRead)
	adminGroup.PUT("/applications/:appID/rate-limit", adminHandler.SetAppLimit, appsWrite)
	adminGroup.DELETE("/applications/:appID/rate-limit", adminHandler.DeleteAppLimit, appsWrite)
	// Cross-tenant / tenant-scoped mirror for super_admin (:tid overrides the JWT tenant).
	adminGroup.GET("/tenants/:tid/app-limits", adminHandler.ListAppLimits, tidAppsRead)
	adminGroup.GET("/tenants/:tid/applications/:appID/rate-limit", adminHandler.GetAppLimit, tidAppsRead)
	adminGroup.PUT("/tenants/:tid/applications/:appID/rate-limit", adminHandler.SetAppLimit, tidAppsWrite)
	adminGroup.DELETE("/tenants/:tid/applications/:appID/rate-limit", adminHandler.DeleteAppLimit, tidAppsWrite)

	// JWT signing-key management (issue #95) — tenant:manage, because rotating a
	// signing key is a tenant-wide security operation, not an application-level one.
	//
	// Two-step rotation by design: prepare publishes the incoming key so verifier
	// caches pick it up, complete then activates it. A single-shot rotate endpoint
	// would reintroduce the window where a token is signed by a key no verifier has
	// seen yet.
	//
	// Both mutating steps are rate limited per tenant. Authorisation alone is not
	// enough here: completing a rotation retires the outgoing key, so a caller
	// that already holds tenant:manage can cycle prepare→complete to push keys
	// past RetiredKeyGrace faster than issued tokens expire, invalidating them.
	// The limiter turns that from seconds into hours. Listing is read-only and
	// stays unthrottled.
	rotationLimit := mw.SigningKeyRotationRateLimiter()
	tenantMgmt.GET("/signing-keys", signingKeyHandler.ListSigningKeys)
	tenantMgmt.POST("/signing-keys/prepare", signingKeyHandler.PrepareSigningKeyRotation, rotationLimit)
	tenantMgmt.POST("/signing-keys/complete", signingKeyHandler.CompleteSigningKeyRotation, rotationLimit)

	// SAML admin config — saml:manage (04-01)
	adminGroup.GET("/saml-config", samlHandler.GetSAMLConfig, samlManage)
	adminGroup.PUT("/saml-config", samlHandler.UpsertSAMLConfig, samlManage)

	// Published JWKS — public, unauthenticated, top-level (issue #95, Phase 3).
	//
	// Mounted with e.GET like /saml/metadata below: there is no SPA catch-all or
	// RouteNotFound handler in this server (the only wildcard is the scoped
	// /api/* 404 at the end of this function), so a top-level path is unshadowed.
	//
	// Per-tenant by path because the slug cannot travel in X-Tenant-Slug here — a
	// JWKS library or browser fetching a URL sends no custom headers.
	//
	// The rate limiter is deliberately generous (JWKSPerIPRate) and refunds 304s:
	// a public route inherits no throttling at all, but throttling this one too
	// hard breaks every offline verifier we are asking to depend on it.
	// TenantCORS skips this path entirely — see isPublicCORSExempt.
	e.GET("/tenants/:slug/.well-known/jwks.json", jwksHandler.GetTenantJWKS, mw.JWKSRateLimiter())

	// OIDC UserInfo (issue #7) — top-level, beside JWKS, because both are standard
	// OIDC surfaces that external client libraries fetch by absolute URL.
	//
	// No /tenants/:slug prefix, unlike JWKS. JWKS is unauthenticated, so the slug
	// is the only thing that can select a tenant; UserInfo carries a verified
	// token, and the tenant claim inside it is authoritative. Taking the tenant
	// from the path here would mean accepting a tenant selector from the caller on
	// an authenticated route — exactly what the tenant-isolation rule forbids.
	//
	// AudienceAPI only, and stated explicitly rather than inherited: machine,
	// management, and agent tokens stand for no user, so there is no user info to
	// return for them (issue #84). JWTRequired enforces it before the handler runs.
	//
	// GET and POST because OIDC Core §5.3 requires both.
	userInfoAuth := mw.JWTRequired(jwtSvc, auth.AudienceAPI)
	e.GET("/oauth/userinfo", oidcHandler.UserInfo, userInfoAuth, mw.UserInfoRateLimiter())
	e.POST("/oauth/userinfo", oidcHandler.UserInfo, userInfoAuth, mw.UserInfoRateLimiter())

	// SAML SP endpoints — public, no JWT required (04-01, 04-02)
	e.GET("/saml/metadata", samlHandler.GetMetadata)
	e.GET("/saml/login", samlHandler.InitiateLogin)
	e.POST("/saml/acs", samlHandler.HandleACS)

	// ---- OAuth 2.0 authorization server (issue #6) -------------------------
	//
	// Top-level, beside JWKS and UserInfo, because these are the standard OAuth
	// surfaces an external client library reaches by absolute URL, and #7b's
	// discovery document will publish exactly these paths as
	// authorization_endpoint, token_endpoint and revocation_endpoint.
	//
	// No Echo conflict with the social-login routes registered below: these are
	// two-segment paths (/oauth/authorize) while those are three
	// (/oauth/:provider/login). This is the same coexistence /oauth/userinfo
	// already relies on.
	//
	// /oauth/authorize and its two login pages are BROWSER routes: they render
	// HTML, accept form posts, and carry the SSO session cookie. They are
	// deliberately outside apiV1 — that group applies CookieCSRF, which is
	// built for the portal's cookie session and would reject a top-level
	// cross-site navigation arriving from a tenant's application, which is
	// exactly how every authorize request begins. CSRF protection here comes
	// instead from the server-side request handle: a forged form cannot supply
	// one, and the handle names the only redirect target a code can be sent to.
	authorizeLimit := mw.AuthorizeRateLimiter()
	e.GET("/oauth/authorize", authorizeHandler.Authorize, authorizeLimit)
	e.POST("/oauth/authorize/login", authorizeHandler.LoginSubmit, authorizeLimit)
	e.POST("/oauth/authorize/mfa", authorizeHandler.MFASubmit, authorizeLimit)

	// Token endpoint — form-encoded (RFC 6749 §4.1.3), unlike the JSON
	// POST /auth/token which keeps working as a documented-deprecated alias.
	e.POST("/oauth/token", oauthTokenHandler.Token, mw.OAuthTokenRateLimiter())

	// Revocation (RFC 7009). Always 200, so the limiter is what stops it being
	// used to probe token validity at volume.
	e.POST("/oauth/revoke", oauthTokenHandler.Revoke, mw.RevokeRateLimiter())

	// Social login browser endpoints — public, top-level like SAML, but with
	// the dedicated rate limiting SAML's routes lack (issue #64).
	e.GET("/oauth/:provider/login", oauthHandler.Login, mw.OAuthRateLimiter(rlCfg))
	e.GET("/oauth/:provider/callback", oauthHandler.Callback, mw.OAuthRateLimiter(rlCfg))

	// Login-code exchange — the tenant app swaps the one-time code for the
	// standard token pair. Per-IP limited; codes are single-use and ≤60s.
	authGroup.POST("/oauth/exchange", oauthHandler.Exchange, mw.OAuthRateLimiter(rlCfg))

	// Identity provider (social login) admin config — apps:read / apps:write.
	adminGroup.GET("/applications/:appID/identity-providers", oauthHandler.ListProviderConfigs, appsRead)
	adminGroup.PUT("/applications/:appID/identity-providers/:provider", oauthHandler.UpsertProviderConfig, appsWrite)
	adminGroup.DELETE("/applications/:appID/identity-providers/:provider", oauthHandler.DeleteProviderConfig, appsWrite)

	// User identity management — list/unlink a user's linked social
	// identities (users:read / users:write).
	adminGroup.GET("/users/:id/identities", oauthHandler.ListUserIdentities, usersRead)
	adminGroup.DELETE("/users/:id/identities/:provider", oauthHandler.UnlinkUserIdentity, usersWrite)

	// Tenant-nested aliases for the identity provider + user identity APIs.
	// The flat routes above resolve the tenant from the caller's JWT, so a
	// super_admin drilling into another tenant would silently manage their
	// OWN tenant's providers. These carry the target tenant in the path,
	// guarded by RequireTenantSelfOrAny exactly like every other
	// /tenants/:tid resource family (email settings, roles, users, ...).
	adminGroup.GET("/tenants/:tid/applications/:appID/identity-providers", oauthHandler.ListProviderConfigs, tidAppsRead)
	// The two mutating routes carry the same token rate limiter as /test: each
	// performs AES-256-GCM work, a DB upsert/delete and an audit write, so
	// leaving the heavier endpoints unguarded while the lighter one is limited
	// would be the wrong asymmetry.
	adminGroup.PUT("/tenants/:tid/applications/:appID/identity-providers/:provider", oauthHandler.UpsertProviderConfig, tidAppsWrite, mw.TokenRateLimiter(rlCfg))
	adminGroup.DELETE("/tenants/:tid/applications/:appID/identity-providers/:provider", oauthHandler.DeleteProviderConfig, tidAppsWrite, mw.TokenRateLimiter(rlCfg))
	adminGroup.POST("/tenants/:tid/applications/:appID/identity-providers/:provider/test", oauthHandler.TestProviderConfig, tidAppsWrite, mw.TokenRateLimiter(rlCfg))
	adminGroup.GET("/tenants/:tid/applications/:appID/users/:uid/identities", oauthHandler.ListUserIdentities, tidUsersRead)
	adminGroup.DELETE("/tenants/:tid/applications/:appID/users/:uid/identities/:provider", oauthHandler.UnlinkUserIdentity, tidUsersWrite)

	// Agent management — apps:read / apps:write (agents are machine clients) (08-01, 08-04)
	adminGroup.POST("/agents", agentHandler.RegisterAgent, appsWrite)
	adminGroup.GET("/agents", agentHandler.ListAgents, appsRead)
	adminGroup.DELETE("/agents/:id", agentHandler.RevokeAgent, appsWrite)
	adminGroup.GET("/agents/analysis", agentHandler.GetAgentAnalysis, appsRead)

	// Agent authentication — public (no JWT required) — issues agent JWT from raw key
	apiV1.POST("/agents/authenticate", agentHandler.AuthenticateAgent)

	// Unmatched /api/ routes return 404 explicitly.
	e.GET("/api/*", func(c echo.Context) error {
		return echo.ErrNotFound
	})
}
