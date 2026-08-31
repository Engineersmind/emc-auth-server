package store

import (
	"context"
	"embed"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/rs/zerolog"
)

// CheckSchemaCompatibility detects databases migrated from the legacy UUID-based
// schema (master branch before the auth-refactor) and returns a descriptive error
// before any migration runs, rather than letting goose produce a cryptic failure
// mid-sequence.
//
// On a fresh database the tenants table does not yet exist, so the query returns
// pgx.ErrNoRows — that is the expected path and the function returns nil.
// On a UUID-schema database tenants.id has data_type = 'uuid'; the function returns
// a non-nil error with upgrade instructions.
func CheckSchemaCompatibility(ctx context.Context, pool *pgxpool.Pool) error {
	var dataType string
	err := pool.QueryRow(ctx, `
		SELECT data_type
		FROM information_schema.columns
		WHERE table_schema = 'public'
		  AND table_name   = 'tenants'
		  AND column_name  = 'id'
	`).Scan(&dataType)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil // fresh database — tenants table does not exist yet
		}
		return fmt.Errorf("schema compatibility check: %w", err)
	}

	if dataType == "uuid" {
		return fmt.Errorf(
			"schema incompatibility: tenants.id is type 'uuid' but this release requires 'bigint identity'. " +
				"This branch rewrites the schema from scratch and cannot upgrade a UUID-schema database in-place. " +
				"Provision a fresh PostgreSQL database (or export, drop, recreate, and re-import all data) " +
				"then restart the server. " +
				"See docs/DEPLOYMENT.md §'Upgrading from UUID Schema' for the full procedure",
		)
	}
	return nil
}

// RunMigrations applies all pending SQL migrations from the embedded filesystem.
// Uses goose.NewProvider (not the legacy global API) for context-aware, type-safe operation.
// The stdlib.OpenDBFromPool bridges pgxpool.Pool to *sql.DB which goose requires.
func RunMigrations(ctx context.Context, pool *pgxpool.Pool, embedFS embed.FS, logger zerolog.Logger) error {
	// goose requires *sql.DB — bridge from pgxpool via stdlib adapter
	db := stdlib.OpenDBFromPool(pool)
	defer func() { _ = db.Close() }()

	provider, err := goose.NewProvider(
		goose.DialectPostgres,
		db,
		embedFS,
		goose.WithAllowOutofOrder(true),
	)
	if err != nil {
		return fmt.Errorf("create goose provider: %w", err)
	}
	defer func() { _ = provider.Close() }()

	results, err := provider.Up(ctx)
	if err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}

	for _, r := range results {
		logger.Info().
			Str("migration", r.Source.Path).
			Dur("duration", r.Duration).
			Msg("migration applied")
	}

	if len(results) == 0 {
		logger.Info().Msg("no pending migrations")
	} else {
		logger.Info().Int("count", len(results)).Msg("migrations complete")
	}

	return nil
}
