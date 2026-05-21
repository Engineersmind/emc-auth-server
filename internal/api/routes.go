package api

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	echoSwagger "github.com/swaggo/echo-swagger"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/api/handlers"
	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
	"github.com/engineersmind/emc-auth-server/internal/ui"
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
}

// securityHeaders returns an Echo middleware that injects security-related
// HTTP response headers on every response (NFR-06).
//
// Headers applied:
//   - Strict-Transport-Security: max-age=31536000; includeSubDomains (HSTS — 1 year)
//   - X-Content-Type-Options: nosniff
//   - X-Frame-Options: DENY
//   - Referrer-Policy: strict-origin-when-cross-origin
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
			h.Set("X-Frame-Options", "DENY")
			// Control referrer information leakage.
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
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

// RegisterRoutes configures all route groups and middleware on the Echo instance.
func RegisterRoutes(e *echo.Echo, deps Deps) {
	// Middleware stack — order matters:
	// 1. RequestID  — generates unique ID for each request (used by logger)
	// 2. SecurityHeaders — HSTS + X-Content-Type-Options etc. on every response
	// 3. HTTPSRedirect — production-only redirect from HTTP to HTTPS
	// 4. RequestLogger — structured zerolog request logging
	// 5. Recover — catches panics from all subsequent handlers
	e.Use(echoMiddleware.RequestID())
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
	e.GET("/swagger/*", echoSwagger.WrapHandler)

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

	authHandler := handlers.NewAuthHandler(authSvc, resetSvc, auditLog, deps.Logger).
		WithTOTP(totpSvc).
		WithAPIKeys(apiKeySvc)

	// Admin service (Phase 5)
	adminSvc := admin.New(deps.Pool, resetSvc, deps.Logger)

	// Per-app rate limit service (08-02) — DB-backed, Redis-cached, 60s TTL.
	appLimitSvc := auth.NewAppRateLimitService(deps.Pool, deps.Redis, deps.Logger)

	// Per-tenant CORS service — DB-backed, Redis-cached, 60s TTL.
	corsSvc := mw.NewTenantCORSService(deps.Pool, deps.Redis, deps.Logger)

	adminHandler := handlers.NewAdminHandler(adminSvc, auditLog, deps.Logger).
		WithAppRateLimits(appLimitSvc).
		WithCORS(corsSvc)

	// AppRateLimiter middleware — enforces per-app token-bucket limits (reads X-App-ID header).
	e.Use(mw.AppRateLimiter(appLimitSvc))

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

	// Cookie-based session endpoints for browser/SPA clients (sets HttpOnly cookies).
	authGroup.POST("/session", authHandler.SessionLogin)
	authGroup.POST("/session/refresh", authHandler.SessionRefresh)
	authGroup.POST("/session/logout", authHandler.SessionLogout)

	// Auth routes — protected by JWTRequired (AUTH-09)
	authGroup.GET("/me", authHandler.Me, mw.JWTRequired(jwtSvc))

	// TOTP management — protected (03-01)
	otpGroup := authGroup.Group("/otp", mw.JWTRequired(jwtSvc))
	otpGroup.POST("/enroll", authHandler.TOTPEnroll)
	otpGroup.POST("/activate", authHandler.TOTPActivate)
	otpGroup.DELETE("", authHandler.TOTPDisable)

	// Admin routes — all require a valid JWT.
	adminGroup := apiV1.Group("/admin", mw.JWTRequired(jwtSvc))

	// Ping (smoke test — requires admin:access)
	adminGroup.GET("/ping", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "admin ping ok"})
	}, mw.RequirePermission("admin:access"))

	// Tenant management — super_admin only (tenant:manage permission)
	tenantMgmt := adminGroup.Group("", mw.RequirePermission("tenant:manage"))
	tenantMgmt.POST("/tenants", adminHandler.CreateTenant)
	tenantMgmt.GET("/tenants", adminHandler.ListTenants)
	tenantMgmt.PUT("/tenants/:id", adminHandler.UpdateTenant)
	tenantMgmt.DELETE("/tenants/:id", adminHandler.DeactivateTenant)
	tenantMgmt.PUT("/tenants/:id/cors-origins", adminHandler.UpdateTenantCORSOrigins)

	// Permission management — tenant admin (admin:access permission)
	rbacGroup := adminGroup.Group("", mw.RequirePermission("admin:access"))
	rbacGroup.POST("/permissions", adminHandler.CreatePermission)
	rbacGroup.GET("/permissions", adminHandler.ListPermissions)
	rbacGroup.DELETE("/permissions/:id", adminHandler.DeletePermission)
	rbacGroup.POST("/roles", adminHandler.CreateRole)
	rbacGroup.GET("/roles", adminHandler.ListRoles)
	rbacGroup.PUT("/roles/:id/permissions", adminHandler.UpdateRolePermissions)
	rbacGroup.DELETE("/roles/:id", adminHandler.DeleteRole)

	// User pool management — tenant admin (admin:access permission)
	rbacGroup.GET("/users", adminHandler.ListUsers)
	rbacGroup.POST("/users", adminHandler.CreateAdminUser)
	rbacGroup.GET("/users/:id", adminHandler.GetAdminUser)
	rbacGroup.PUT("/users/:id", adminHandler.UpdateAdminUser)
	rbacGroup.PUT("/users/:id/role", adminHandler.AssignUserRole)
	rbacGroup.DELETE("/users/:id", adminHandler.DeleteAdminUser)
	rbacGroup.POST("/users/:id/force-password-reset", adminHandler.ForcePasswordReset)

	// API key management — tenant admin (admin:access) (03-03)
	rbacGroup.POST("/api-keys", authHandler.CreateAPIKey)
	rbacGroup.GET("/api-keys", authHandler.ListAPIKeys)
	rbacGroup.DELETE("/api-keys/:id", authHandler.RevokeAPIKey)

	// Audit logs — tenant-scoped (admin:access) and system-wide (tenant:manage)
	rbacGroup.GET("/audit-logs", adminHandler.GetTenantAuditLogs)
	tenantMgmt.GET("/audit-logs/system", adminHandler.GetSystemAuditLogs)

	// Per-app rate limit management — tenant admin (admin:access) (08-02)
	rbacGroup.POST("/app-limits", adminHandler.CreateAppLimit)
	rbacGroup.GET("/app-limits", adminHandler.ListAppLimits)
	rbacGroup.PUT("/app-limits/:app_id", adminHandler.UpdateAppLimit)
	rbacGroup.DELETE("/app-limits/:app_id", adminHandler.DeleteAppLimit)

	// Serve the React Admin SPA for all non-API routes.
	// Must come AFTER all /api/, /metrics, /swagger, /saml, /health routes so it
	// does not shadow them. Static assets (JS/CSS) use the /assets/* prefix
	// produced by Vite; everything else falls back to index.html for client-side
	// routing.
	distFS := ui.DistFS()

	// /assets/* — serve bundled JS, CSS, fonts directly from embed.FS.
	e.StaticFS("/assets", mustSubFS(distFS, "assets"))

	// favicon and vite default icon
	e.GET("/favicon.ico", echo.WrapHandler(http.FileServer(http.FS(distFS))))
	e.GET("/vite.svg", echo.WrapHandler(http.FileServer(http.FS(distFS))))

	// SPA fallback — serve index.html for all unmatched GET routes so that
	// React Router can handle client-side navigation.
	// Guard: /api/ paths return 404 rather than index.html (CRIT-02 review fix).
	e.GET("/*", func(c echo.Context) error {
		if strings.HasPrefix(c.Request().URL.Path, "/api/") {
			return echo.ErrNotFound
		}
		f, err := distFS.Open("index.html")
		if err != nil {
			return echo.ErrNotFound
		}
		defer f.Close()
		return c.Stream(http.StatusOK, "text/html; charset=utf-8", f)
	})
}

// mustSubFS returns a sub-filesystem rooted at dir within fsys.
// Panics on error (programming error — embedded paths must exist at build time).
func mustSubFS(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("ui: failed to open sub-FS " + dir + ": " + err.Error())
	}
	return sub
}
