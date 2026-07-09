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
)

// Deps holds shared dependencies injected into route handlers.
type Deps struct {
	Logger zerolog.Logger
	Pool   *pgxpool.Pool
	Redis  *redis.Client
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
	// SMTP fields for mailer (used in production; dev logs to console).
	SMTPHost     string
	SMTPPort     int
	SMTPFrom     string
	SMTPUsername string
	SMTPPassword string
	// CookieDomain is the Domain attribute for auth cookies (e.g. ".engineersmind.com").
	// Leave empty for localhost development.
	CookieDomain string
	// GlobalCORSOrigins are the allowed browser origins for slug-less endpoints
	// (e.g. /auth/login), which have no tenant to look up a per-tenant list by.
	GlobalCORSOrigins []string
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

	// Mailer: dev (console log) or SMTP based on Env
	m := mailer.NewMailer(mailer.MailerConfig{
		Env:          deps.Config.Env,
		SMTPHost:     deps.Config.SMTPHost,
		SMTPPort:     deps.Config.SMTPPort,
		SMTPFrom:     deps.Config.SMTPFrom,
		SMTPUsername: deps.Config.SMTPUsername,
		SMTPPassword: deps.Config.SMTPPassword,
		Logger:       deps.Logger,
	})
	resetSvc := auth.NewResetService(deps.Pool, m, deps.Config.AppBaseURL, deps.Logger)

	// Audit logger — shared by both auth and admin handlers
	auditLog := audit.New(deps.Pool, deps.Logger)

	cookieCfg := mw.BuildCookieConfig(deps.Config.Env, deps.Config.CookieDomain)

	authHandler := handlers.NewAuthHandler(authSvc, resetSvc, auditLog, deps.Logger).
		WithTOTP(totpSvc).
		WithAPIKeys(apiKeySvc).
		WithApplications(appSvc).
		WithCookieConfig(cookieCfg).
		WithJWT(jwtSvc)

	// Admin service (Phase 5)
	adminSvc := admin.New(deps.Pool, resetSvc, deps.Logger)

	// Per-app rate limit service (08-02) — DB-backed, Redis-cached, 60s TTL.
	appLimitSvc := auth.NewAppRateLimitService(deps.Pool, deps.Redis, deps.Logger)

	// Per-tenant CORS service — DB-backed, Redis-cached, 60s TTL. Slug-less
	// requests (e.g. /auth/login) fall back to the global allow-list instead.
	corsSvc := mw.NewTenantCORSService(deps.Pool, deps.Redis, deps.Logger).
		WithGlobalOrigins(deps.Config.GlobalCORSOrigins)

	adminHandler := handlers.NewAdminHandler(adminSvc, auditLog, deps.Logger).
		WithAppRateLimits(appLimitSvc).
		WithApplications(appSvc).
		WithCORS(corsSvc)

	// SAML service (Phase 4) — lightweight SP, no external dependencies.
	samlService := samlsvc.New(deps.Pool, deps.Config.AppBaseURL, deps.Logger)
	samlHandler := handlers.NewSAMLHandler(samlService, jwtSvc, deps.Logger)

	// AppRateLimiter middleware — enforces per-app token-bucket limits (reads X-App-ID header).
	e.Use(mw.AppRateLimiter(appLimitSvc, deps.Redis))

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
	authGroup.POST("/login/otp", authHandler.LoginOTP) // complete TOTP-gated login (03-02)
	authGroup.POST("/refresh", authHandler.Refresh)
	authGroup.POST("/logout", authHandler.Logout)
	authGroup.POST("/forgot-password", authHandler.ForgotPassword)
	authGroup.POST("/reset-password", authHandler.ResetPassword)

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
	// an isolated bucket instead of all sharing one email-less fallback bucket.
	authGroup.POST("/token", authHandler.Token, mw.TokenRateLimiter(rlCfg))

	// Application-authenticated end-user register/login (Auth0-style
	// integration): the calling application authenticates itself via
	// Authorization: Basic, and gets its own isolated end-user base, distinct
	// from /register and /login above (which are tenant-level, first-party
	// only). Rate-limited per client_id — same reasoning as /token.
	authGroup.POST("/apps/register", authHandler.AppRegister, mw.TokenRateLimiter(rlCfg))
	authGroup.POST("/apps/login", authHandler.AppLogin, mw.TokenRateLimiter(rlCfg))

	// jwtRenew is used on all cookie-aware protected routes.
	// It validates the access token and, when expired, transparently rotates
	// the refresh token (distributed lock + fresh user DB load) and writes new
	// cookies onto the response before the handler body is flushed.
	jwtRenew := mw.JWTRenew(jwtSvc, authSvc, deps.Redis, cookieCfg, auditLog, deps.Logger)

	// Auth routes — protected with transparent renewal (AUTH-09)
	authGroup.GET("/me", authHandler.Me, jwtRenew)
	authGroup.GET("/my-activity", authHandler.MyActivity, jwtRenew)

	// TOTP management — protected (03-01)
	otpGroup := authGroup.Group("/otp", jwtRenew)
	otpGroup.POST("/enroll", authHandler.TOTPEnroll)
	otpGroup.POST("/activate", authHandler.TOTPActivate)
	otpGroup.DELETE("", authHandler.TOTPDisable)

	// Admin routes — require a valid JWT. JWTRequired (not JWTRenew) is used here
	// because the refresh cookie is scoped to /api/v1/auth; browsers will not send
	// it to non-auth paths, so transparent renewal is impossible. Browser
	// clients must call /auth/session/refresh when they receive 401 token_expired,
	// then retry the admin request.
	adminGroup := apiV1.Group("", mw.JWTRequired(jwtSvc))

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

	// Cross-tenant management — drill into any tenant's permissions / roles / users.
	// :tid = target tenant UUID. Caller must have tenant:manage (super_admin only).
	tenantMgmt.GET("/tenants/:tid/permissions", adminHandler.TenantListPermissions)
	tenantMgmt.POST("/tenants/:tid/permissions", adminHandler.TenantCreatePermission)
	tenantMgmt.DELETE("/tenants/:tid/permissions/:pid", adminHandler.TenantDeletePermission)
	tenantMgmt.GET("/tenants/:tid/roles", adminHandler.TenantListRoles)
	tenantMgmt.POST("/tenants/:tid/roles", adminHandler.TenantCreateRole)
	tenantMgmt.PUT("/tenants/:tid/roles/:rid/permissions", adminHandler.TenantUpdateRolePermissions)
	tenantMgmt.DELETE("/tenants/:tid/roles/:rid", adminHandler.TenantDeleteRole)
	tenantMgmt.GET("/tenants/:tid/users", adminHandler.TenantListUsers)
	tenantMgmt.POST("/tenants/:tid/users", adminHandler.TenantCreateUser)
	tenantMgmt.DELETE("/tenants/:tid/users/:uid", adminHandler.TenantDeleteUser)

	// Cross-tenant application management (EMC-004) — same handlers as the
	// tenant-scoped /applications routes; the :tid path param overrides the
	// JWT tenant. Guarded by tenant:manage via the tenantMgmt group.
	tenantMgmt.GET("/tenants/:tid/applications", adminHandler.ListApplications)
	tenantMgmt.POST("/tenants/:tid/applications", adminHandler.CreateApplication)
	tenantMgmt.GET("/tenants/:tid/applications/:id", adminHandler.GetApplication)
	tenantMgmt.PUT("/tenants/:tid/applications/:id", adminHandler.UpdateApplication)
	tenantMgmt.DELETE("/tenants/:tid/applications/:id", adminHandler.DeactivateApplication)
	tenantMgmt.POST("/tenants/:tid/applications/:id/rotate-secret", adminHandler.RotateApplicationSecret)

	// Cross-tenant stats + activity feed (EMC-004 tenant overview page).
	tenantMgmt.GET("/tenants/:tid/stats", adminHandler.TenantGetStats)
	tenantMgmt.GET("/tenants/:tid/activity", adminHandler.TenantGetActivity)

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

	// API key management — apps:read / apps:write (keys are machine credentials) (03-03)
	adminGroup.POST("/api-keys", authHandler.CreateAPIKey, appsWrite)
	adminGroup.GET("/api-keys", authHandler.ListAPIKeys, appsRead)
	adminGroup.DELETE("/api-keys/:id", authHandler.RevokeAPIKey, appsWrite)

	// Monitoring stats — tenant-scoped (stats:read) and system-wide (tenant:manage)
	adminGroup.GET("/stats", adminHandler.GetStats, statsRead)
	tenantMgmt.GET("/stats/system", adminHandler.GetSystemStats)

	// Audit logs — tenant-scoped (audit:read) and system-wide (tenant:manage)
	adminGroup.GET("/audit-logs", adminHandler.GetTenantAuditLogs, auditRead)
	tenantMgmt.GET("/audit-logs/system", adminHandler.GetSystemAuditLogs)

	// Application management — apps:read / apps:write (tenant from JWT claims)
	adminGroup.POST("/applications", adminHandler.CreateApplication, appsWrite)
	adminGroup.GET("/applications", adminHandler.ListApplications, appsRead)
	adminGroup.GET("/applications/:id", adminHandler.GetApplication, appsRead)
	adminGroup.PUT("/applications/:id", adminHandler.UpdateApplication, appsWrite)
	adminGroup.DELETE("/applications/:id", adminHandler.DeactivateApplication, appsWrite)
	adminGroup.POST("/applications/:id/rotate-secret", adminHandler.RotateApplicationSecret, appsWrite)

	// Per-app rate limit management — apps:read / apps:write (08-02)
	adminGroup.POST("/app-limits", adminHandler.CreateAppLimit, appsWrite)
	adminGroup.GET("/app-limits", adminHandler.ListAppLimits, appsRead)
	adminGroup.PUT("/app-limits/:app_id", adminHandler.UpdateAppLimit, appsWrite)
	adminGroup.DELETE("/app-limits/:app_id", adminHandler.DeleteAppLimit, appsWrite)

	// SAML admin config — saml:manage (04-01)
	adminGroup.GET("/saml-config", samlHandler.GetSAMLConfig, samlManage)
	adminGroup.PUT("/saml-config", samlHandler.UpsertSAMLConfig, samlManage)

	// SAML SP endpoints — public, no JWT required (04-01, 04-02)
	e.GET("/saml/metadata", samlHandler.GetMetadata)
	e.GET("/saml/login", samlHandler.InitiateLogin)
	e.POST("/saml/acs", samlHandler.HandleACS)

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
