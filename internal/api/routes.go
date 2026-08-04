package api

import (
	"net/http"
	"strings"

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
	// TOTPEncryptionKey is the 64-char hex key for AES-256-GCM TOTP secret encryption.
	TOTPEncryptionKey string
	// OAuthClientSecretEncryptionKey is the 64-char hex key for AES-256-GCM
	// encryption of social-login provider client secrets (issue #64).
	// Required in production/staging — the server refuses to start without it.
	OAuthClientSecretEncryptionKey string
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
	jwtSvc := auth.NewJWTService(deps.Pool, deps.Config.JWTIssuer)
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
	invSvc := auth.NewInvitationService(deps.Pool, m, deps.Config.AppBaseURL, deps.Logger).
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
	idpSvc := auth.NewIdentityProviderService(deps.Pool, secretBox, deps.Config.AppBaseURL, deps.Logger)
	oauthSvc := auth.NewOAuthLoginService(deps.Pool, deps.Redis, idpSvc, authSvc, deps.Config.AppBaseURL, deps.Logger)
	oauthHandler := handlers.NewOAuthHandler(oauthSvc, idpSvc, auditLog, deps.Logger)

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

	// /api/v1 route group
	apiV1 := e.Group("/api/v1")

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

	// Admin routes — require a valid JWT. JWTRequired (not JWTRenew) is used here
	// because the refresh cookie is scoped to /api/v1/auth; browsers will not send
	// it to non-auth paths, so transparent renewal is impossible. Browser
	// clients must call /auth/session/refresh when they receive 401 token_expired,
	// then retry the admin request.
	// appRateLimit is a pass-through for first-party admin/tenant tokens: those
	// JWTs are minted with an empty app_id claim (only application-scoped end-user
	// tokens carry a numeric app_id), and AppRateLimiter skips any request whose
	// app_id is empty. So mounting it here cannot rate-limit an operator out of
	// the rate-limit CRUD routes below — the limiter only ever engages for
	// application-scoped traffic, never for the admin console's own calls.
	adminGroup := apiV1.Group("", mw.JWTRequired(jwtSvc), appRateLimit)

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
	tidAppsWrite := mw.RequireTenantSelfOrAny("apps:write")
	tidStatsRead := mw.RequireTenantSelfOrAny("stats:read")

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
	adminGroup.GET("/tenants/:tid/applications", adminHandler.ListApplications, tidAppsRead)
	adminGroup.POST("/tenants/:tid/applications", adminHandler.CreateApplication, tidAppsWrite)
	adminGroup.GET("/tenants/:tid/applications/:id", adminHandler.GetApplication, tidAppsRead)
	adminGroup.PUT("/tenants/:tid/applications/:id", adminHandler.UpdateApplication, tidAppsWrite)
	adminGroup.DELETE("/tenants/:tid/applications/:id", adminHandler.DeactivateApplication, tidAppsWrite)
	adminGroup.POST("/tenants/:tid/applications/:id/rotate-secret", adminHandler.RotateApplicationSecret, tidAppsWrite)

	// End-user application roles under the canonical family (mirrors the flat
	// /applications/:appID/roles aliases registered below).
	adminGroup.POST("/tenants/:tid/applications/:appID/roles", adminHandler.CreateApplicationRole, tidRolesWrite)
	adminGroup.GET("/tenants/:tid/applications/:appID/roles", adminHandler.ListApplicationRoles, tidRolesRead)
	adminGroup.PUT("/tenants/:tid/applications/:appID/roles/:id", adminHandler.UpdateApplicationRole, tidRolesWrite)
	adminGroup.PUT("/tenants/:tid/applications/:appID/roles/:id/permissions", adminHandler.UpdateRolePermissions, tidRolesWrite)
	adminGroup.PUT("/tenants/:tid/applications/:appID/roles/:id/default", adminHandler.SetDefaultApplicationRole, tidRolesWrite)
	adminGroup.DELETE("/tenants/:tid/applications/:appID/roles/:id", adminHandler.DeleteRole, tidRolesWrite)

	// End-user application permissions under the canonical family.
	adminGroup.POST("/tenants/:tid/applications/:appID/permissions", adminHandler.CreatePermission, tidPermsWrite)
	adminGroup.GET("/tenants/:tid/applications/:appID/permissions", adminHandler.ListPermissions, tidPermsRead)
	adminGroup.PUT("/tenants/:tid/applications/:appID/permissions/:pid", adminHandler.UpdatePermission, tidPermsWrite)
	adminGroup.DELETE("/tenants/:tid/applications/:appID/permissions/:pid", adminHandler.DeletePermission, tidPermsWrite)

	// Per-application MFA policy under the canonical family (issue #63) —
	// owner (apps:read/apps:write, own tenant) and super_admin (tenant:manage,
	// any tenant) manage each application's MFA mode; MFA policy is
	// application configuration, so it rides the apps:* permissions.
	adminGroup.GET("/tenants/:tid/applications/:appID/mfa", adminHandler.GetApplicationMFA, tidAppsRead)
	adminGroup.PUT("/tenants/:tid/applications/:appID/mfa", adminHandler.UpdateApplicationMFA, tidAppsWrite)
	adminGroup.DELETE("/tenants/:tid/applications/:appID/users/:uid/mfa", adminHandler.ResetUserMFA, tidUsersWrite)

	// White-label email senders under the canonical family (issue #63
	// follow-on) — tenant-level sender plus optional per-application override;
	// MFA code emails resolve application → tenant → global.
	adminGroup.GET("/tenants/:tid/email-settings", adminHandler.GetEmailSender, tidAppsRead)
	adminGroup.PUT("/tenants/:tid/email-settings", adminHandler.UpsertEmailSender, tidAppsWrite)
	adminGroup.DELETE("/tenants/:tid/email-settings", adminHandler.DeleteEmailSender, tidAppsWrite)
	adminGroup.POST("/tenants/:tid/email-settings/test", adminHandler.SendTestEmail, tidAppsWrite, mw.TokenRateLimiter(rlCfg))
	adminGroup.GET("/tenants/:tid/applications/:appID/email-settings", adminHandler.GetEmailSender, tidAppsRead)
	adminGroup.PUT("/tenants/:tid/applications/:appID/email-settings", adminHandler.UpsertEmailSender, tidAppsWrite)
	adminGroup.DELETE("/tenants/:tid/applications/:appID/email-settings", adminHandler.DeleteEmailSender, tidAppsWrite)
	adminGroup.POST("/tenants/:tid/applications/:appID/email-settings/test", adminHandler.SendTestEmail, tidAppsWrite, mw.TokenRateLimiter(rlCfg))

	// Per-scope email templates (Auth0-style) — same guards as senders.
	adminGroup.GET("/tenants/:tid/email-templates", adminHandler.ListEmailTemplates, tidAppsRead)
	adminGroup.GET("/tenants/:tid/email-templates/:type", adminHandler.GetEmailTemplate, tidAppsRead)
	adminGroup.PUT("/tenants/:tid/email-templates/:type", adminHandler.UpsertEmailTemplate, tidAppsWrite)
	adminGroup.DELETE("/tenants/:tid/email-templates/:type", adminHandler.DeleteEmailTemplate, tidAppsWrite)
	adminGroup.GET("/tenants/:tid/applications/:appID/email-templates", adminHandler.ListEmailTemplates, tidAppsRead)
	adminGroup.GET("/tenants/:tid/applications/:appID/email-templates/:type", adminHandler.GetEmailTemplate, tidAppsRead)
	adminGroup.PUT("/tenants/:tid/applications/:appID/email-templates/:type", adminHandler.UpsertEmailTemplate, tidAppsWrite)
	adminGroup.DELETE("/tenants/:tid/applications/:appID/email-templates/:type", adminHandler.DeleteEmailTemplate, tidAppsWrite)

	// End-user application users under the canonical family — each
	// application manages its own isolated user base.
	adminGroup.GET("/tenants/:tid/applications/:appID/users", adminHandler.ListUsers, tidUsersRead)
	adminGroup.POST("/tenants/:tid/applications/:appID/users", adminHandler.CreateAdminUser, tidUsersWrite)
	adminGroup.GET("/tenants/:tid/applications/:appID/users/:uid", adminHandler.GetAdminUser, tidUsersRead)
	adminGroup.PUT("/tenants/:tid/applications/:appID/users/:uid", adminHandler.UpdateAdminUser, tidUsersWrite)
	adminGroup.PUT("/tenants/:tid/applications/:appID/users/:uid/role", adminHandler.AssignUserRole, tidUsersWrite)
	adminGroup.POST("/tenants/:tid/applications/:appID/users/:uid/force-password-reset", adminHandler.ForcePasswordReset, tidUsersWrite)
	adminGroup.POST("/tenants/:tid/applications/:appID/users/:uid/invite", adminHandler.ResendInvitation, tidUsersWrite)
	adminGroup.DELETE("/tenants/:tid/applications/:appID/users/:uid", adminHandler.DeleteAdminUser, tidUsersWrite)
	adminGroup.GET("/tenants/:tid/applications/:appID/users/:uid/detail", adminHandler.GetAdminUserDetail, tidUsersRead)
	adminGroup.PUT("/tenants/:tid/applications/:appID/users/:uid/status", adminHandler.SetUserStatus, tidUsersWrite)
	adminGroup.GET("/tenants/:tid/applications/:appID/users/:uid/sessions", adminHandler.ListUserSessions, tidUsersRead)
	adminGroup.DELETE("/tenants/:tid/applications/:appID/users/:uid/sessions", adminHandler.RevokeAllUserSessions, tidUsersWrite)
	adminGroup.DELETE("/tenants/:tid/applications/:appID/users/:uid/sessions/:familyID", adminHandler.RevokeUserSession, tidUsersWrite)
	adminGroup.GET("/tenants/:tid/applications/:appID/users/:uid/mfa", adminHandler.GetUserMFAStatus, tidUsersRead)

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
	auditRead := mw.RequireAnyPermission("audit:read", "admin:access")
	statsRead := mw.RequireAnyPermission("stats:read", "admin:access")
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

	// SAML admin config — saml:manage (04-01)
	adminGroup.GET("/saml-config", samlHandler.GetSAMLConfig, samlManage)
	adminGroup.PUT("/saml-config", samlHandler.UpsertSAMLConfig, samlManage)

	// SAML SP endpoints — public, no JWT required (04-01, 04-02)
	e.GET("/saml/metadata", samlHandler.GetMetadata)
	e.GET("/saml/login", samlHandler.InitiateLogin)
	e.POST("/saml/acs", samlHandler.HandleACS)

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
