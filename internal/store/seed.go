package store

import (
	"context"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

// Well-known UUIDs for seed data — deterministic so ON CONFLICT works reliably.
var (
	SeedTenantID         = uuid.MustParse("00000000-0000-0000-0000-000000000001")
	SeedRoleID           = uuid.MustParse("00000000-0000-0000-0000-000000000010")
	SeedUserID           = uuid.MustParse("00000000-0000-0000-0000-000000000100")
	SeedPermTenantManage = uuid.MustParse("00000000-0000-0000-0000-000000000201")
	SeedPermAdminAccess  = uuid.MustParse("00000000-0000-0000-0000-000000000202")
)

const defaultSeedPassword = "ChangeMe123!"

// RunSeed creates the default emc tenant, super_admin role, and super-admin user.
// All inserts use ON CONFLICT DO NOTHING for idempotency — safe to run multiple times.
// The admin password is read from SEED_ADMIN_PASSWORD env var; falls back to "ChangeMe123!"
// with a prominent warning log.
func RunSeed(ctx context.Context, pool *pgxpool.Pool, logger zerolog.Logger) error {
	// 1. Determine seed password
	seedPassword := os.Getenv("SEED_ADMIN_PASSWORD")
	if seedPassword == "" {
		seedPassword = defaultSeedPassword
		logger.Warn().Msg("SEED_ADMIN_PASSWORD not set — using default password. Override this in production!")
	}

	// 2. Seed default tenant (idempotent)
	_, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, name, slug, jwt_secret, is_active)
		VALUES ($1, 'EMC', 'emc', gen_random_uuid()::text, true)
		ON CONFLICT (id) DO NOTHING
	`, SeedTenantID)
	if err != nil {
		return fmt.Errorf("seed tenant: %w", err)
	}
	logger.Info().Str("tenant", "emc").Str("id", SeedTenantID.String()).Msg("seed tenant ensured")

	// 3. Seed super_admin role (idempotent)
	_, err = pool.Exec(ctx, `
		INSERT INTO roles (id, tenant_id, name, is_system)
		VALUES ($1, $2, 'super_admin', true)
		ON CONFLICT (id) DO NOTHING
	`, SeedRoleID, SeedTenantID)
	if err != nil {
		return fmt.Errorf("seed role: %w", err)
	}
	logger.Info().Str("role", "super_admin").Msg("seed role ensured")

	// 4. Seed super-admin user (idempotent — targets partial index idx_users_email_active)
	_, err = pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, first_name, last_name, role_id, is_active)
		VALUES ($1, $2, 'admin@emc.local', 'Super', 'Admin', $3, true)
		ON CONFLICT (tenant_id, email) WHERE deleted_at IS NULL DO NOTHING
	`, SeedUserID, SeedTenantID, SeedRoleID)
	if err != nil {
		return fmt.Errorf("seed user: %w", err)
	}
	logger.Info().Str("email", "admin@emc.local").Msg("seed user ensured")

	// 5. Seed password for super-admin (bcrypt cost 12 per AUTH-02 requirement)
	hash, err := bcrypt.GenerateFromPassword([]byte(seedPassword), 12)
	if err != nil {
		return fmt.Errorf("hash seed password: %w", err)
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO user_credentials (user_id, tenant_id, password_hash)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO NOTHING
	`, SeedUserID, SeedTenantID, string(hash))
	if err != nil {
		return fmt.Errorf("seed credentials: %w", err)
	}
	logger.Info().Msg("seed credentials ensured")

	// 6. Seed base permissions for the emc tenant (tenant:manage + admin:access).
	// These are the two built-in permissions that gate admin API access.
	// All other permissions are created by tenant admins via the API.
	_, err = pool.Exec(ctx, `
		INSERT INTO permissions (id, tenant_id, name, description)
		VALUES
		  ($1, $2, 'tenant:manage',  'Create, update, and deactivate tenants (super_admin only)'),
		  ($3, $2, 'admin:access',   'Access tenant admin operations (roles, permissions, user pool)')
		ON CONFLICT (id) DO NOTHING
	`, SeedPermTenantManage, SeedTenantID, SeedPermAdminAccess)
	if err != nil {
		return fmt.Errorf("seed permissions: %w", err)
	}
	logger.Info().Msg("seed permissions ensured")

	// 7. Assign both permissions to the super_admin role (idempotent).
	_, err = pool.Exec(ctx, `
		INSERT INTO role_permissions (role_id, permission_id, tenant_id)
		VALUES
		  ($1, $2, $4),
		  ($1, $3, $4)
		ON CONFLICT DO NOTHING
	`, SeedRoleID, SeedPermTenantManage, SeedPermAdminAccess, SeedTenantID)
	if err != nil {
		return fmt.Errorf("seed role_permissions: %w", err)
	}
	logger.Info().Msg("seed role_permissions ensured")

	return nil
}
