package store

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

const defaultSeedPassword = "ChangeMe123!"

// RunSeed creates the default emc tenant, super_admin role, and super-admin user.
// All inserts use ON CONFLICT DO NOTHING for idempotency — safe to run multiple times.
// BIGINT IDENTITY PKs are auto-generated; we INSERT without explicit id, then SELECT
// to retrieve the generated value for use in subsequent inserts.
// The admin password is read from SEED_ADMIN_PASSWORD env var; falls back to "ChangeMe123!"
// with a prominent warning log.
// CORS origins are seeded from SEED_CORS_ORIGINS (comma-separated, e.g.
// "https://auth.senie.ai,https://app.senie.ai,http://localhost:3000").
func RunSeed(ctx context.Context, pool *pgxpool.Pool, logger zerolog.Logger) error {
	seedPassword := os.Getenv("SEED_ADMIN_PASSWORD")
	if seedPassword == "" {
		seedPassword = defaultSeedPassword
		logger.Warn().Msg("SEED_ADMIN_PASSWORD not set — using default password. Override this in production!")
	}

	var corsOrigins []string
	if raw := os.Getenv("SEED_CORS_ORIGINS"); raw != "" {
		for _, o := range strings.Split(raw, ",") {
			if trimmed := strings.TrimSpace(o); trimmed != "" {
				corsOrigins = append(corsOrigins, trimmed)
			}
		}
	}

	// 1. Seed default tenant (idempotent via slug unique index).
	_, err := pool.Exec(ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ('EMC', 'emc', gen_random_uuid()::text, true)
		ON CONFLICT (slug) WHERE deleted_at IS NULL DO NOTHING
	`)
	if err != nil {
		return fmt.Errorf("seed tenant: %w", err)
	}

	var tenantID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`,
	).Scan(&tenantID); err != nil {
		return fmt.Errorf("seed: fetch tenant id: %w", err)
	}
	logger.Info().Str("tenant", "emc").Int64("id", tenantID).Msg("seed tenant ensured")

	// 1b. Seed CORS origins from SEED_CORS_ORIGINS env var (idempotent — only sets if provided).
	if len(corsOrigins) > 0 {
		_, err = pool.Exec(ctx,
			`UPDATE tenants SET cors_origins = $1 WHERE id = $2`,
			corsOrigins, tenantID,
		)
		if err != nil {
			return fmt.Errorf("seed cors_origins: %w", err)
		}
		logger.Info().Strs("cors_origins", corsOrigins).Msg("seed cors_origins set")
	}

	// 2. Seed super_admin role (idempotent via name+tenant unique index).
	_, err = pool.Exec(ctx, `
		INSERT INTO roles (tenant_id, name, is_system)
		VALUES ($1, 'super_admin', true)
		ON CONFLICT (tenant_id, name) WHERE deleted_at IS NULL DO NOTHING
	`, tenantID)
	if err != nil {
		return fmt.Errorf("seed role: %w", err)
	}

	var roleID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM roles WHERE tenant_id = $1 AND name = 'super_admin'`,
		tenantID,
	).Scan(&roleID); err != nil {
		return fmt.Errorf("seed: fetch role id: %w", err)
	}
	logger.Info().Str("role", "super_admin").Int64("id", roleID).Msg("seed role ensured")

	// 3. Seed super-admin user (idempotent via partial index users_tenant_email_tenant_level_key).
	_, err = pool.Exec(ctx, `
		INSERT INTO users (tenant_id, email, first_name, last_name, role_id, is_active)
		VALUES ($1, 'admin@emc.local', 'Super', 'Admin', $2, true)
		ON CONFLICT (tenant_id, email) WHERE application_id IS NULL AND deleted_at IS NULL DO NOTHING
	`, tenantID, roleID)
	if err != nil {
		return fmt.Errorf("seed user: %w", err)
	}

	var userID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM users WHERE tenant_id = $1 AND email = 'admin@emc.local' AND deleted_at IS NULL`,
		tenantID,
	).Scan(&userID); err != nil {
		return fmt.Errorf("seed: fetch user id: %w", err)
	}
	logger.Info().Str("email", "admin@emc.local").Int64("id", userID).Msg("seed user ensured")

	// 4. Seed password for super-admin (bcrypt cost 12 per AUTH-02 requirement).
	hash, err := bcrypt.GenerateFromPassword([]byte(seedPassword), 12)
	if err != nil {
		return fmt.Errorf("hash seed password: %w", err)
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO user_credentials (user_id, tenant_id, password_hash)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO NOTHING
	`, userID, tenantID, string(hash))
	if err != nil {
		return fmt.Errorf("seed credentials: %w", err)
	}
	logger.Info().Msg("seed credentials ensured")

	// 5. Seed base permissions for the emc tenant (tenant:manage + admin:access).
	_, err = pool.Exec(ctx, `
		INSERT INTO permissions (tenant_id, name, description)
		VALUES
		  ($1, 'tenant:manage',  'Create, update, and deactivate tenants (super_admin only)'),
		  ($1, 'admin:access',   'Access tenant admin operations (roles, permissions, user pool)')
		ON CONFLICT (tenant_id, name) WHERE deleted_at IS NULL DO NOTHING
	`, tenantID)
	if err != nil {
		return fmt.Errorf("seed permissions: %w", err)
	}
	logger.Info().Msg("seed permissions ensured")

	// 6. Assign both permissions to the super_admin role (idempotent).
	_, err = pool.Exec(ctx, `
		INSERT INTO role_permissions (role_id, permission_id, tenant_id)
		SELECT $1, p.id, $2
		FROM permissions p
		WHERE p.tenant_id = $2 AND p.name IN ('tenant:manage', 'admin:access')
		ON CONFLICT DO NOTHING
	`, roleID, tenantID)
	if err != nil {
		return fmt.Errorf("seed role_permissions: %w", err)
	}
	logger.Info().Msg("seed role_permissions ensured")

	return nil
}
