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
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/docs" // swagger generated docs
	"github.com/engineersmind/emc-auth-server/internal/api"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/config"
	"github.com/engineersmind/emc-auth-server/internal/enrich"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
	"github.com/engineersmind/emc-auth-server/internal/notify"
	"github.com/engineersmind/emc-auth-server/internal/security/risk"
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

	// Refuse to boot on a configuration that would break cookie sessions at
	// runtime — a fail-closed CSRF check turns these into a silent portal outage.
	if err := cfg.Validate(); err != nil {
		logger.Fatal().Err(err).Msg("invalid configuration")
	}

	// An invitation is the ONLY route to a password for a newly seeded tenant
	// owner, and its link is built from DashboardBaseURL. Left at the dev default
	// in production, every invitation points at the operator's own machine — the
	// tenant is created, the mail arrives, and nobody can act on it. The failure
	// is silent at the point it happens and only surfaces as a confused owner, so
	// it is worth a loud line at boot.
	if cfg.Env == "production" && strings.Contains(cfg.DashboardBaseURL, "localhost") {
		logger.Error().
			Str("dashboard_base_url", cfg.DashboardBaseURL).
			Msg("DASHBOARD_BASE_URL still points at localhost in production — invitation links will be unusable")
	}

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

	// Detect legacy UUID-schema databases before any migration runs.
	// Fresh databases (tenants table absent) pass through silently.
	if err := store.CheckSchemaCompatibility(ctx, pool); err != nil {
		logger.Fatal().Err(err).Msg("schema incompatibility — cannot proceed")
	}

	// Run migrations from embedded SQL files (idempotent)
	if err := store.RunMigrations(ctx, pool, migrations.FS, logger); err != nil {
		logger.Fatal().Err(err).Msg("migrations failed")
	}

	// Seed default tenant and super-admin (idempotent)
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		logger.Fatal().Err(err).Msg("seed failed")
	}

	// Seed demo tenants + users when SEED_DEMO_DATA=true (local dev / QA only)
	if os.Getenv("SEED_DEMO_DATA") == "true" {
		if err := store.RunDemoSeed(ctx, pool, logger); err != nil {
			logger.Fatal().Err(err).Msg("demo seed failed")
		}
	}

	// Connect to Redis
	rdb, err := store.NewRedis(ctx, cfg.RedisURL, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to redis")
	}
	defer store.CloseRedis(rdb)

	// Set Swagger host dynamically so "Try it out" points to this server's address.
	// In production APP_BASE_URL is e.g. "https://auth.senie.ai" — strip the scheme.
	if cfg.AppBaseURL != "" && cfg.AppBaseURL != "http://localhost:9090" {
		host := cfg.AppBaseURL
		host = strings.TrimPrefix(host, "https://")
		host = strings.TrimPrefix(host, "http://")
		docs.SwaggerInfo.Host = strings.TrimRight(host, "/")
	} else {
		docs.SwaggerInfo.Host = "localhost:" + cfg.Port
	}

	// Optional GeoIP resolver for audit location enrichment. Disabled (nil)
	// when GEOIP_DATABASE_PATH is empty — the .mmdb is licensed and not shipped.
	geoResolver, err := enrich.NewGeoIPResolver(cfg.GeoIPDatabasePath)
	if err != nil {
		logger.Warn().Err(err).Msg("geoip: database unavailable — audit location enrichment disabled")
	}
	if geoResolver != nil {
		defer func() {
			if cerr := geoResolver.Close(); cerr != nil {
				logger.Warn().Err(cerr).Msg("geoip: close failed")
			}
		}()
	}

	// Optional SIEM stream — forwards every persisted audit batch to a webhook.
	// Disabled (nil) when AUDIT_SIEM_WEBHOOK_URL is empty.
	siemSink := enrich.NewWebhookSink(cfg.AuditSIEMWebhookURL, cfg.AuditSIEMWebhookSecret, logger)
	if siemSink != nil {
		defer siemSink.Close()
	}

	// Admin-activity notifications (#97 follow-on) — emails a privileged action
	// to the tier above the actor, and to the actor for sensitive ones.
	//
	// Built here, before the audit logger, because it is registered as one of
	// its sinks. It constructs its own mailer rather than borrowing the one in
	// RegisterRoutes, which does not exist yet; both come from the same config,
	// so they behave identically.
	notifySink := notify.NewEmailSink(
		pool,
		mailer.NewMailer(mailer.MailerConfig{
			Env:            cfg.Env,
			Provider:       cfg.EmailProvider,
			SMTPHost:       cfg.SMTPHost,
			SMTPPort:       cfg.SMTPPort,
			SMTPUsername:   cfg.SMTPUsername,
			SMTPPassword:   cfg.SMTPPassword,
			SMTPTLS:        cfg.SMTPTLS,
			SendGridAPIKey: cfg.SendGridAPIKey,
			EmailFrom:      cfg.SMTPFrom,
			FromName:       cfg.EmailFromName,
			Logger:         logger,
		}),
		auth.NewEmailTemplateService(pool, logger),
		cfg.DashboardBaseURL,
		cfg.PlatformNotifyEmails,
		logger,
	)
	defer notifySink.Close()

	// Async audit logger — owned here so shutdown can drain its buffer
	// after the HTTP server stops and before the DB pool closes.
	auditOpts := []audit.Option{
		audit.WithRiskAssessor(risk.New(pool, cfg.UntrustedIPCIDRs, logger)),
		audit.WithSink(notifySink),
	}
	if geoResolver != nil {
		auditOpts = append(auditOpts, audit.WithGeoIP(geoResolver))
	}
	if siemSink != nil {
		auditOpts = append(auditOpts, audit.WithSink(siemSink))
	}
	auditLog := audit.New(pool, logger, auditOpts...)

	// Close the loop: the sink records its own deliveries, but the logger it
	// records them to only exists now. Safe here — nothing is served yet, so no
	// event can reach the sink before this assignment.
	notifySink.WithAudit(auditLog)

	// Background retention purge (no-op when AUDIT_RETENTION_DAYS <= 0).
	stopRetention := auditLog.StartRetention(cfg.AuditRetentionDays)
	defer stopRetention()

	// Echo instance
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	// Register routes and middleware
	api.RegisterRoutes(e, api.Deps{
		Logger: logger,
		Pool:   pool,
		Redis:  rdb,
		Audit:  auditLog,
		Config: api.RoutesConfig{
			JWTIssuer:                              cfg.JWTIssuer,
			Env:                                    cfg.Env,
			AppBaseURL:                             cfg.AppBaseURL,
			DashboardBaseURL:                       cfg.DashboardBaseURL,
			TOTPEncryptionKey:                      cfg.TOTPEncryptionKey,
			OAuthClientSecretEncryptionKey:         cfg.OAuthClientSecretEncryptionKey,
			OAuthClientSecretEncryptionKeyPrevious: cfg.OAuthClientSecretEncryptionKeyPrevious,
			JWTSigningKeyEncryptionKey:             cfg.JWTSigningKeyEncryptionKey,
			JWTSigningKeyEncryptionKeyPrevious:     cfg.JWTSigningKeyEncryptionKeyPrevious,
			JWTAllowLegacyHS256:                    cfg.JWTAllowLegacyHS256,
			OIDCIssuerBaseURL:                      cfg.OIDCIssuerBaseURL,
			JWTAllowLegacyIssuer:                   cfg.JWTAllowLegacyIssuer,
			EmailProvider:                          cfg.EmailProvider,
			SendGridAPIKey:                         cfg.SendGridAPIKey,
			EmailFromName:                          cfg.EmailFromName,
			SMTPHost:                               cfg.SMTPHost,
			SMTPPort:                               cfg.SMTPPort,
			SMTPFrom:                               cfg.SMTPFrom,
			SMTPUsername:                           cfg.SMTPUsername,
			SMTPPassword:                           cfg.SMTPPassword,
			SMTPTLS:                                cfg.SMTPTLS,
			CookieDomain:                           cfg.CookieDomain,
			GlobalCORSOrigins:                      cfg.GlobalCORSOrigins,
			AuditCaptureResponseBody:               cfg.AuditCaptureResponseBody,
			BreachDetectionEnabled:                 cfg.BreachDetectionEnabled,
			UntrustedIPCIDRs:                       cfg.UntrustedIPCIDRs,
		},
	})

	// Graceful shutdown via signal
	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Session retention reaper. Deletes refresh-token rows that can never be
	// presented again, after a forensic retention margin.
	//
	// Started here rather than inside RegisterRoutes because it owns a goroutine and
	// needs the shutdown context: RegisterRoutes wires request handling and has no
	// lifecycle to hang a background worker off. Bound to shutdownCtx so the reaper
	// stops at a batch boundary when the process is asked to exit — each batch commits
	// independently, so an interrupted pass simply resumes on the next start.
	//
	// Every replica runs this; an advisory lock elects one winner per interval, so the
	// losers skip the run rather than duplicating the deletes.
	go auth.NewSessionReaper(pool, logger).Run(shutdownCtx)

	s := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           e,
		ReadHeaderTimeout: 10 * time.Second,
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
	// Drain buffered audit events now that no new requests can arrive —
	// must complete before the deferred pool.Close() invalidates connections.
	if err := auditLog.Close(timeoutCtx); err != nil {
		logger.Warn().Err(err).Msg("audit drain incomplete at shutdown")
	}
	// Flush OTel exporters and Sentry buffer before exit
	if err := otelShutdown(timeoutCtx); err != nil {
		logger.Warn().Err(err).Msg("otel shutdown error")
	}
	telemetry.FlushSentry()
	logger.Info().Msg("server stopped")
}
