package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

// Demo seed — recognisable tenants + users for local dev and QA.
// Triggered when SEED_DEMO_DATA=true is set in the environment.
// Safe to re-run — all inserts are idempotent via ON CONFLICT.
//
// Login summary after seeding:
//
//	SUPER ADMIN  admin@emc.local         / SEED_ADMIN_PASSWORD  (tenant: emc)
//	─────────────────────────────────────────────────────────────────────────
//	OUTREACH     admin@outreach.local     / Demo1234!  (admin)
//	             alice@outreach.local     / Demo1234!  (member)
//	             bob@outreach.local       / Demo1234!  (member)
//	─────────────────────────────────────────────────────────────────────────
//	SENIE        admin@senie.local        / Demo1234!  (admin)
//	             carol@senie.local        / Demo1234!  (member)
//	             david@senie.local        / Demo1234!  (member)
//	─────────────────────────────────────────────────────────────────────────
//	ACME         admin@acme.local         / Demo1234!  (admin)
//	             frank@acme.local         / Demo1234!  (member)
//	             grace@acme.local         / Demo1234!  (member)

const demoPassword = "Demo1234!"

type demoTenant struct {
	name  string
	slug  string
	users []demoUser
}

type demoUser struct {
	email     string
	firstName string
	lastName  string
	isAdmin   bool
}

var demoTenants = []demoTenant{
	{
		name: "Outreach",
		slug: "outreach",
		users: []demoUser{
			{"admin@outreach.local", "Outreach", "Admin", true},
			{"alice@outreach.local", "Alice", "Johnson", false},
			{"bob@outreach.local", "Bob", "Smith", false},
		},
	},
	{
		name: "Senie",
		slug: "senie",
		users: []demoUser{
			{"admin@senie.local", "Senie", "Admin", true},
			{"carol@senie.local", "Carol", "Williams", false},
			{"david@senie.local", "David", "Brown", false},
		},
	},
	{
		name: "Acme Corp",
		slug: "acme",
		users: []demoUser{
			{"admin@acme.local", "Acme", "Admin", true},
			{"frank@acme.local", "Frank", "Miller", false},
			{"grace@acme.local", "Grace", "Davis", false},
		},
	},
}

// RunDemoSeed seeds 3 demo tenants with recognisable users, roles, and permissions.
func RunDemoSeed(ctx context.Context, pool *pgxpool.Pool, logger zerolog.Logger) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(demoPassword), 12)
	if err != nil {
		return fmt.Errorf("hash demo password: %w", err)
	}
	hashStr := string(hash)

	for _, t := range demoTenants {
		if err := seedDemoTenant(ctx, pool, logger, t, hashStr); err != nil {
			return fmt.Errorf("seed demo tenant %s: %w", t.slug, err)
		}
	}
	logger.Info().Msg("demo seed complete — 3 tenants, 9 users")
	return nil
}

func seedDemoTenant(ctx context.Context, pool *pgxpool.Pool, logger zerolog.Logger, t demoTenant, pwHash string) error {
	// Tenant — slug unique constraint (migration 00038).
	_, err := pool.Exec(ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ($1, $2, gen_random_uuid()::text, true)
		ON CONFLICT (slug) DO NOTHING
	`, t.name, t.slug)
	if err != nil {
		return fmt.Errorf("tenant: %w", err)
	}

	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = $1`, t.slug).Scan(&tenantID); err != nil {
		return fmt.Errorf("tenant id lookup: %w", err)
	}

	// Permission: admin:access.
	// permissions.id is GENERATED ALWAYS AS IDENTITY — never insert an explicit id.
	// DO UPDATE is a no-op touch that ensures RETURNING id works on conflict too.
	var permAdminID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO permissions (tenant_id, name, description)
		VALUES ($1, 'admin:access', 'Access tenant admin operations')
		ON CONFLICT (tenant_id, name) WHERE deleted_at IS NULL
		DO UPDATE SET description = EXCLUDED.description
		RETURNING id
	`, tenantID).Scan(&permAdminID); err != nil {
		return fmt.Errorf("permission: %w", err)
	}

	// Roles: admin + member.
	// roles.id is GENERATED ALWAYS AS IDENTITY.
	var roleAdminID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO roles (tenant_id, name, is_system)
		VALUES ($1, 'admin', false)
		ON CONFLICT (tenant_id, name) WHERE deleted_at IS NULL
		DO UPDATE SET is_system = EXCLUDED.is_system
		RETURNING id
	`, tenantID).Scan(&roleAdminID); err != nil {
		return fmt.Errorf("role admin: %w", err)
	}

	var roleMemberID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO roles (tenant_id, name, is_system)
		VALUES ($1, 'member', false)
		ON CONFLICT (tenant_id, name) WHERE deleted_at IS NULL
		DO UPDATE SET is_system = EXCLUDED.is_system
		RETURNING id
	`, tenantID).Scan(&roleMemberID); err != nil {
		return fmt.Errorf("role member: %w", err)
	}

	// Assign admin:access to admin role.
	_, err = pool.Exec(ctx, `
		INSERT INTO role_permissions (role_id, permission_id, tenant_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (role_id, permission_id) DO NOTHING
	`, roleAdminID, permAdminID, tenantID)
	if err != nil {
		return fmt.Errorf("role_permissions: %w", err)
	}

	// Users + credentials.
	// users.id is GENERATED ALWAYS AS IDENTITY.
	for _, u := range t.users {
		roleID := roleMemberID
		if u.isAdmin {
			roleID = roleAdminID
		}

		var userID int64
		if err := pool.QueryRow(ctx, `
			INSERT INTO users (tenant_id, email, first_name, last_name, role_id, is_active)
			VALUES ($1, $2, $3, $4, $5, true)
			ON CONFLICT (tenant_id, email) WHERE application_id IS NULL AND deleted_at IS NULL
			DO UPDATE SET role_id = EXCLUDED.role_id
			RETURNING id
		`, tenantID, u.email, u.firstName, u.lastName, roleID).Scan(&userID); err != nil {
			return fmt.Errorf("user %s: %w", u.email, err)
		}

		_, err = pool.Exec(ctx, `
			INSERT INTO user_credentials (user_id, tenant_id, password_hash)
			VALUES ($1, $2, $3)
			ON CONFLICT (user_id) DO NOTHING
		`, userID, tenantID, pwHash)
		if err != nil {
			return fmt.Errorf("credentials %s: %w", u.email, err)
		}
	}

	logger.Info().Str("tenant", t.slug).Int("users", len(t.users)).Msg("demo tenant seeded")
	return nil
}
