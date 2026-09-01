package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/engineersmind/emc-auth-server/internal/password"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

const defaultSeedPassword = "ChangeMe123!"

// generateTenantSecret returns 32 bytes of crypto/rand as hex — the same strength
// the admin API's tenant creation has always used. Kept here (rather than shared
// with internal/admin) because store must not import admin.
func generateTenantSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

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
	//
	// The secret is generated with crypto/rand rather than gen_random_uuid()::text
	// (issue #95). A v4 UUID carries ~122 bits of entropy in a fixed, recognisable
	// 36-character shape; this is 256 bits of unstructured hex, matching what the
	// admin API's generateSecret() has always produced. Seeded tenants were the
	// weakest signing keys in the system purely because the value was convenient
	// to write in SQL — and the seed tenant is the one every deployment has.
	seedSecret, err := generateTenantSecret()
	if err != nil {
		return fmt.Errorf("seed: generate tenant jwt_secret: %w", err)
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ('EMC', 'emc', $1, true)
		ON CONFLICT (slug) WHERE deleted_at IS NULL DO NOTHING
	`, seedSecret)
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
		ON CONFLICT (tenant_id, name) WHERE application_id IS NULL AND deleted_at IS NULL DO NOTHING
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

	// 4. Seed password for super-admin, hashed through the same package as every
	// other credential so the seeded account is never the odd one out — a literal
	// cost here would silently diverge the moment the parameters move, and the
	// super-admin is the last account that should be weaker than the rest.
	hash, err := password.NewHasher(password.DefaultParams()).Hash(ctx, seedPassword)
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
		ON CONFLICT (tenant_id, name) WHERE application_id IS NULL AND deleted_at IS NULL DO NOTHING
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

	// 7. Re-seed the platform-default session policy (idempotent).
	//
	// Migration 00067 inserts this row, but a migration runs once and the row does
	// not survive: session_policies has a foreign key to tenants, and
	// `TRUNCATE tenants CASCADE` — which the test helper runs, and which truncates
	// every REFERENCING TABLE rather than just the matching rows — empties it
	// completely. A developer who ran the test suite was then left with a database
	// whose policy table was empty, so every login logged
	// "no session policy row matched (platform default missing?)" and silently fell
	// back to compiled-in defaults.
	//
	// Seeding is the right home for it: unlike a migration, seed runs on every
	// start, so the row is restored rather than gone until someone re-migrates from
	// scratch. Values match auth.DefaultSessionPolicy and migration 00067.
	if _, err = pool.Exec(ctx, `
		INSERT INTO session_policies
		    (tenant_id, application_id, idle_ttl_seconds, non_persistent_idle_ttl_seconds,
		     absolute_ttl_seconds, max_concurrent_sessions, allow_persistent)
		SELECT NULL, NULL, 604800, 86400, 2592000, 20, true
		WHERE NOT EXISTS (
			SELECT 1 FROM session_policies WHERE tenant_id IS NULL AND application_id IS NULL
		)
	`); err != nil {
		return fmt.Errorf("seed platform session policy: %w", err)
	}
	logger.Info().Msg("seed session policy ensured")

	// Platform-default LOCKOUT policy, re-seeded here for exactly the reasons above
	// (issue #72). Migration 00070 seeds this row, but goose records the migration as
	// applied and never runs it again — so once the row is gone it stays gone, and
	// the only way back is a migration from scratch.
	//
	// It disappears the same way the session policy did: lockout_policies has a
	// foreign key to tenants, so `TRUNCATE tenants CASCADE` in the test helper
	// empties the whole table, platform-default row included. Without this, a
	// developer who had run the suite would see every login log
	// "no lockout policy row matched (platform default missing?)" and silently fall
	// back to compiled-in defaults — which for lockout means the console would show
	// one policy while the login path enforced another.
	//
	// Values match auth.DefaultLockoutPolicy and migration 00086, an agreement
	// TestDefaultLockoutPolicyMatchesSeed enforces.
	if _, err = pool.Exec(ctx, `
		INSERT INTO lockout_policies
		    (tenant_id, application_id, notify_user_threshold,
		     soft_lock_threshold, soft_lock_duration_seconds,
		     hard_lock_threshold, hard_lock_duration_seconds,
		     failure_window_seconds, tenant_spike_threshold)
		SELECT NULL, NULL, 3, 5, 900, 10, 1800, 900, 10
		WHERE NOT EXISTS (
			SELECT 1 FROM lockout_policies WHERE tenant_id IS NULL AND application_id IS NULL
		)
	`); err != nil {
		return fmt.Errorf("seed platform lockout policy: %w", err)
	}
	logger.Info().Msg("seed lockout policy ensured")

	return nil
}
