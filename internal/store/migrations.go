package store

import (
	"context"
	"embed"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/rs/zerolog"
)

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
