package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

// Demo seed — recognisable tenants + users for local dev and QA.
// Triggered when SEED_DEMO_DATA=true is set in the environment.
// All UUID IDs are deterministic so this is fully idempotent (safe to re-run).
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

// demoTenant describes one demo tenant to seed.
// id is not stored here — tenants.id is GENERATED ALWAYS AS IDENTITY (BIGINT)
// and is fetched from the DB after the upsert.
type demoTenant struct {
	name  string
	slug  string
	users []demoUser
}

type demoUser struct {
	id        uuid.UUID
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
			{uuid.MustParse("00000000-0000-0000-0002-000000000001"), "admin@outreach.local", "Outreach", "Admin", true},
			{uuid.MustParse("00000000-0000-0000-0002-000000000002"), "alice@outreach.local", "Alice", "Johnson", false},
			{uuid.MustParse("00000000-0000-0000-0002-000000000003"), "bob@outreach.local", "Bob", "Smith", false},
		},
	},
	{
		name: "Senie",
		slug: "senie",
		users: []demoUser{
			{uuid.MustParse("00000000-0000-0000-0003-000000000001"), "admin@senie.local", "Senie", "Admin", true},
			{uuid.MustParse("00000000-0000-0000-0003-000000000002"), "carol@senie.local", "Carol", "Williams", false},
			{uuid.MustParse("00000000-0000-0000-0003-000000000003"), "david@senie.local", "David", "Brown", false},
		},
	},
	{
		name: "Acme Corp",
		slug: "acme",
		users: []demoUser{
			{uuid.MustParse("00000000-0000-0000-0004-000000000001"), "admin@acme.local", "Acme", "Admin", true},
			{uuid.MustParse("00000000-0000-0000-0004-000000000002"), "frank@acme.local", "Frank", "Miller", false},
			{uuid.MustParse("00000000-0000-0000-0004-000000000003"), "grace@acme.local", "Grace", "Davis", false},
		},
	},
}

// RunDemoSeed seeds 3 demo tenants with recognisable users, roles, and permissions.
// Each tenant gets: admin role (admin:access), member role (no extra permissions).
// All demo users share the password "Demo1234!".
// Safe to call multiple times — all inserts use ON CONFLICT DO NOTHING.
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
	// Insert tenant without explicit id — tenants.id is GENERATED ALWAYS AS IDENTITY.
	// ON CONFLICT (slug) makes this idempotent on re-runs.
	_, err := pool.Exec(ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ($1, $2, gen_random_uuid()::text, true)
		ON CONFLICT (slug) DO NOTHING
	`, t.name, t.slug)
	if err != nil {
		return fmt.Errorf("tenant: %w", err)
	}

	// Fetch the generated (or pre-existing) BIGINT tenant id.
	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = $1`, t.slug).Scan(&tenantID); err != nil {
		return fmt.Errorf("tenant id lookup: %w", err)
	}

	// Derive a deterministic UUID namespace from the slug so all child UUIDs
	// are stable across re-runs without relying on the BIGINT tenant id.
	ns := uuid.NewSHA1(uuid.NameSpaceOID, []byte(t.slug))

	// Permissions: admin:access for this tenant
	permAdminID := uuid.NewSHA1(ns, []byte("perm:admin:access"))
	_, err = pool.Exec(ctx, `
		INSERT INTO permissions (id, tenant_id, name, description)
		VALUES ($1, $2, 'admin:access', 'Access tenant admin operations')
		ON CONFLICT (id) DO NOTHING
	`, permAdminID, tenantID)
	if err != nil {
		return fmt.Errorf("permission: %w", err)
	}

	// Roles: admin (has admin:access) + member (no permissions)
	roleAdminID := uuid.NewSHA1(ns, []byte("role:admin"))
	roleMemberID := uuid.NewSHA1(ns, []byte("role:member"))

	_, err = pool.Exec(ctx, `
		INSERT INTO roles (id, tenant_id, name, is_system)
		VALUES ($1, $2, 'admin', false), ($3, $2, 'member', false)
		ON CONFLICT (id) DO NOTHING
	`, roleAdminID, tenantID, roleMemberID)
	if err != nil {
		return fmt.Errorf("roles: %w", err)
	}

	// Assign admin:access to admin role
	_, err = pool.Exec(ctx, `
		INSERT INTO role_permissions (role_id, permission_id)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING
	`, roleAdminID, permAdminID)
	if err != nil {
		return fmt.Errorf("role_permissions: %w", err)
	}

	// Users
	for _, u := range t.users {
		roleID := roleMemberID
		if u.isAdmin {
			roleID = roleAdminID
		}

		_, err = pool.Exec(ctx, `
			INSERT INTO users (id, tenant_id, email, first_name, last_name, role_id, is_active)
			VALUES ($1, $2, $3, $4, $5, $6, true)
			ON CONFLICT (tenant_id, email) DO NOTHING
		`, u.id, tenantID, u.email, u.firstName, u.lastName, roleID)
		if err != nil {
			return fmt.Errorf("user %s: %w", u.email, err)
		}

		_, err = pool.Exec(ctx, `
			INSERT INTO user_credentials (user_id, tenant_id, password_hash)
			VALUES ($1, $2, $3)
			ON CONFLICT (user_id) DO NOTHING
		`, u.id, tenantID, pwHash)
		if err != nil {
			return fmt.Errorf("credentials %s: %w", u.email, err)
		}
	}

	logger.Info().Str("tenant", t.slug).Int("users", len(t.users)).Msg("demo tenant seeded")
	return nil
}
