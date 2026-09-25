package auth_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// Permission resolution against soft-deleted roles — issue #146.
//
// loadPermissions resolves users.role_id -> role_permissions and never joined
// roles, so there was no alias to filter deleted_at on. That was harmless while
// DeleteRole issued a hard DELETE, because ON DELETE CASCADE removed the grants
// with the role. #146 made the delete soft, and without the join a tombstoned
// role would go on granting its full permission set at every login — deletion
// would GRANT permissions rather than revoke them. These tests read permissions
// out of a real token, which is the only place the question actually matters.

// roleFixture is a tenant, an application, and a default role carrying one
// permission — the minimum needed to log in and inspect a token's claims.
type roleFixture struct {
	pool     *pgxpool.Pool
	svc      *auth.AuthService
	jwtSvc   *auth.JWTService
	app      *auth.AppResult
	tenantID int64
	roleID   int64
}

func newRoleFixture(t *testing.T, appName, permName string) roleFixture {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	logger := testhelper.TestLogger()
	ctx := context.Background()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	t.Cleanup(func() { testhelper.CleanupTables(t, pool) })

	var tenantID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant id: %v", err)
	}

	appSvc := auth.NewApplicationService(pool, logger)
	app, err := appSvc.CreateApplication(ctx, tenantID, appName, "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication() error = %v", err)
	}
	var appID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM oauth_clients WHERE client_id = $1`, app.ClientID).Scan(&appID); err != nil {
		t.Fatalf("fetch app id: %v", err)
	}

	var permID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO permissions (tenant_id, name, description) VALUES ($1, $2, '')
		RETURNING id
	`, tenantID, permName).Scan(&permID); err != nil {
		t.Fatalf("insert permission: %v", err)
	}

	var roleID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO roles (tenant_id, application_id, name, is_system, is_default, created_at)
		VALUES ($1, $2, 'viewer', false, true, NOW())
		RETURNING id
	`, tenantID, appID).Scan(&roleID); err != nil {
		t.Fatalf("insert default role: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO role_permissions (role_id, permission_id, tenant_id) VALUES ($1, $2, $3)
	`, roleID, permID, tenantID); err != nil {
		t.Fatalf("assign permission to role: %v", err)
	}

	jwtSvc := newTestJWTService(t, pool, "https://auth.emc.local")
	svc := auth.NewAuthService(pool, jwtSvc, logger).WithApplications(appSvc)

	return roleFixture{pool: pool, svc: svc, jwtSvc: jwtSvc, app: app, tenantID: tenantID, roleID: roleID}
}

// registerAndLogin returns the claims on a freshly minted access token.
func (f roleFixture) registerAndLogin(t *testing.T, email string) *auth.Claims {
	t.Helper()
	ctx := context.Background()

	reg, err := f.svc.Register(ctx, auth.RegisterInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		Email: email, Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	login, err := f.svc.Login(ctx, auth.LoginInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		Email: reg.Email, Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	claims, err := f.jwtSvc.Verify(ctx, login.Token.AccessToken)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	return claims
}

func TestLoadPermissions_IgnoresSoftDeletedRoles(t *testing.T) {
	f := newRoleFixture(t, "soft-deleted-role-app", "widgets:read")
	ctx := context.Background()

	// Baseline: the grant resolves while the role is live, so a later empty set
	// is attributable to the deletion rather than to a broken fixture.
	claims := f.registerAndLogin(t, uniqueEmail("perm-live"))
	if len(claims.Permissions) != 1 || claims.Permissions[0] != "widgets:read" {
		t.Fatalf("precondition: token permissions = %v, want [widgets:read]", claims.Permissions)
	}

	// Soft-delete the role WITHOUT detaching holders or stripping grants — the
	// state DeleteRole's explicit cleanup exists to prevent, reproduced directly
	// so this tests the query rather than the cleanup.
	if _, err := f.pool.Exec(ctx,
		`UPDATE roles SET deleted_at = NOW() WHERE id = $1`, f.roleID); err != nil {
		t.Fatalf("soft-delete role: %v", err)
	}

	after := f.registerAndLogin(t, uniqueEmail("perm-deleted"))
	if len(after.Permissions) != 0 {
		t.Errorf("token permissions = %v after the role was soft-deleted, want none; "+
			"a deleted role is still granting permissions", after.Permissions)
	}
}

func TestLoadPermissions_KeepsDirectGrantsWhenTheRoleIsDeleted(t *testing.T) {
	f := newRoleFixture(t, "direct-grant-app", "widgets:read")
	ctx := context.Background()

	email := uniqueEmail("perm-direct")
	claims := f.registerAndLogin(t, email)
	userID := claims.UserID

	var permID int64
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO permissions (tenant_id, name, description) VALUES ($1, 'reports:read', '')
		RETURNING id
	`, f.tenantID).Scan(&permID); err != nil {
		t.Fatalf("insert direct permission: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO user_permissions (user_id, tenant_id, permission_id)
		VALUES ($1::BIGINT, $2, $3)
	`, userID, f.tenantID, permID); err != nil {
		t.Fatalf("grant permission directly: %v", err)
	}
	if _, err := f.pool.Exec(ctx,
		`UPDATE roles SET deleted_at = NOW() WHERE id = $1`, f.roleID); err != nil {
		t.Fatalf("soft-delete role: %v", err)
	}

	// The UNION's second half attaches to the ACCOUNT, not to any role, so the
	// role filter must not reach it. Getting this wrong would strip permissions
	// an operator granted the person directly.
	login, err := f.svc.Login(ctx, auth.LoginInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		Email: email, Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	after, err := f.jwtSvc.Verify(ctx, login.Token.AccessToken)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if len(after.Permissions) != 1 || after.Permissions[0] != "reports:read" {
		t.Errorf("token permissions = %v, want [reports:read]: a direct grant must "+
			"survive its holder's role being deleted", after.Permissions)
	}
}

func TestRegister_IgnoresSoftDeletedDefaultRole(t *testing.T) {
	f := newRoleFixture(t, "deleted-default-role-app", "widgets:read")
	ctx := context.Background()

	// is_default deliberately left set, which is the state a soft delete written
	// by anything other than DeleteRole would leave behind.
	if _, err := f.pool.Exec(ctx,
		`UPDATE roles SET deleted_at = NOW() WHERE id = $1`, f.roleID); err != nil {
		t.Fatalf("soft-delete role: %v", err)
	}

	reg, err := f.svc.Register(ctx, auth.RegisterInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		Email: uniqueEmail("deleted-default"), Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	// Otherwise every account created after the deletion inherits a role the
	// operator believed they had removed.
	if reg.Role != "" {
		t.Errorf("Register() assigned role = %q, want empty: a soft-deleted role "+
			"must not be handed out as an application default", reg.Role)
	}
}
