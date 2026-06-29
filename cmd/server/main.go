// @title           EMC Auth Server
// @version         1.5.0
// @description     Standalone multi-tenant Identity Provider — email/password auth, JWT, refresh tokens, TOTP 2FA, SAML 2.0, RBAC, Admin UI, and AI/Agent security.
//
// @contact.name    EngineersMind
// @contact.url     https://github.com/engineersmind/emc-auth-server
//
// @license.name    MIT
//
// @host            localhost:8082
// @BasePath        /
//
// @securityDefinitions.apikey BearerAuth
// @in              header
// @name            Authorization
// @description     Enter: Bearer <your_access_token>

package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/docs"   // swagger generated docs
	"github.com/engineersmind/emc-auth-server/internal/api"
	"github.com/engineersmind/emc-auth-server/internal/config"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/telemetry"
	"github.com/engineersmind/emc-auth-server/migrations"
)

func main() {
	// Load .env file if present (non-fatal if absent)
	_ = godotenv.Load()

	// Load configuration from environment variables
	cfg := config.Load()

	// Initialize zerolog
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)
	logger := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("service", "emc-auth-server").
		Str("env", cfg.Env).
		Logger()

	ctx := context.Background()

	// Initialise OpenTelemetry (no-op when OTEL_EXPORTER_OTLP_ENDPOINT is unset)
	otelShutdown, err := telemetry.Init(ctx)
	if err != nil {
		logger.Warn().Err(err).Msg("otel init failed — continuing without telemetry")
	} else {
		// Attach hook after Init so the global log provider is already set
		logger = logger.Hook(telemetry.NewOTelHook())
	}

	// Initialise Sentry (no-op when SENTRY_DSN is unset)
	if err := telemetry.InitSentry(cfg.Env); err != nil {
		logger.Warn().Err(err).Msg("sentry init failed — continuing without sentry")
	}

	// Connect to PostgreSQL
	pool, err := store.NewDB(ctx, cfg.DatabaseURL, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer store.CloseDB(pool)

	// Run migrations from embedded SQL files (idempotent)
	if err := store.RunMigrations(ctx, pool, migrations.FS, logger); err != nil {
		logger.Fatal().Err(err).Msg("migrations failed")
	}

	// Seed default tenant and super-admin (idempotent)
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		logger.Fatal().Err(err).Msg("seed failed")
	}

	// Connect to Redis
	rdb, err := store.NewRedis(ctx, cfg.RedisURL, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to redis")
	}
	defer store.CloseRedis(rdb)

	// Set Swagger host dynamically so "Try it out" points to this server's address
	docs.SwaggerInfo.Host = "localhost:" + cfg.Port

	// Echo instance
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	// Register routes and middleware
	api.RegisterRoutes(e, api.Deps{
		Logger: logger,
		Pool:   pool,
		Redis:  rdb,
		Config: api.RoutesConfig{
			JWTIssuer:         cfg.JWTIssuer,
			Env:               cfg.Env,
			AppBaseURL:        cfg.AppBaseURL,
			TOTPEncryptionKey: cfg.TOTPEncryptionKey,
			SMTPHost:          cfg.SMTPHost,
			SMTPPort:          cfg.SMTPPort,
			SMTPFrom:          cfg.SMTPFrom,
			SMTPUsername:      cfg.SMTPUsername,
			SMTPPassword:      cfg.SMTPPassword,
		},
	})

	// Graceful shutdown via signal
	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: e,
	}

	// Start server in goroutine
	go func() {
		logger.Info().Str("port", cfg.Port).Msg("server starting")
		if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal().Err(err).Msg("server error")
		}
	}()

	// Block until shutdown signal
	<-shutdownCtx.Done()
	logger.Info().Msg("shutting down")

	timeoutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Shutdown(timeoutCtx); err != nil {
		logger.Error().Err(err).Msg("shutdown error")
	}
	// Flush OTel exporters and Sentry buffer before exit
	if err := otelShutdown(timeoutCtx); err != nil {
		logger.Warn().Err(err).Msg("otel shutdown error")
	}
	telemetry.FlushSentry()
	logger.Info().Msg("server stopped")
}
