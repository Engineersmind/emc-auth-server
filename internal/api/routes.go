package api

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/api/handlers"
	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/auth"
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
}

// RegisterRoutes configures all route groups and middleware on the Echo instance.
func RegisterRoutes(e *echo.Echo, deps Deps) {
	// Middleware stack — order matters:
	// 1. RequestID (first, so logger can read it)
	// 2. RequestLogger (uses zerolog, not Echo's built-in)
	// 3. Recover (catches panics from everything after it)
	e.Use(echoMiddleware.RequestID())
	e.Use(mw.RequestLogger(deps.Logger))
	e.Use(echoMiddleware.Recover())

	// Health check — no auth required
	e.GET("/health", handlers.HealthHandler)

	// Build shared services
	jwtSvc := auth.NewJWTService(deps.Pool, deps.Config.JWTIssuer)
	authSvc := auth.NewAuthService(deps.Pool, jwtSvc, deps.Logger)
	authHandler := handlers.NewAuthHandler(authSvc, deps.Logger)

	// /api/v1 route group
	apiV1 := e.Group("/api/v1")

	// Auth routes — public (no JWT required)
	authGroup := apiV1.Group("/auth")
	authGroup.POST("/register", authHandler.Register)
	authGroup.POST("/login", authHandler.Login)
	authGroup.POST("/refresh", authHandler.Refresh)
	authGroup.POST("/logout", authHandler.Logout)

	// Auth routes — protected by JWTRequired (AUTH-09)
	authGroup.GET("/me", authHandler.Me, mw.JWTRequired(jwtSvc))

	// Canary route: demonstrates RequirePermission middleware (AUTH-10 / SC-4).
	// A JWT without "admin:access" in permissions[] gets 403 — verifies SC-4.
	// A JWT with "admin:access" gets 200 {"status":"admin ping ok"}.
	adminGroup := apiV1.Group("/admin")
	adminGroup.GET("/ping", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "admin ping ok"})
	}, mw.JWTRequired(jwtSvc), mw.RequirePermission("admin:access"))

	// Plan 02-04 will add:
	//   authGroup.POST("/forgot-password", authHandler.ForgotPassword)
	//   authGroup.POST("/reset-password", authHandler.ResetPassword)
}
