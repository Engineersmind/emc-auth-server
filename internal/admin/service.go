// Package admin implements the Admin API business logic:
// tenant management (super_admin only), user pool CRUD, role CRUD,
// and permission CRUD (all tenant-scoped).
package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// Sentinel errors returned by service methods.
var (
	// ErrNotFound is returned when a requested resource does not exist within the caller's tenant.
	ErrNotFound = errors.New("not found")
	// ErrAlreadyExists is returned when a unique constraint would be violated.
	ErrAlreadyExists = errors.New("already exists")
)

// ---------------------------------------------------------------------------
// Result types (returned to handlers → JSON)
// ---------------------------------------------------------------------------

// TenantResult is the public representation of a tenant (jwt_secret is never exposed).
type TenantResult struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
}

// PermissionResult is the public representation of a tenant-scoped permission.
type PermissionResult struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// RoleResult is the public representation of a tenant-scoped role with its permissions.
type RoleResult struct {
	ID          string             `json:"id"`
	TenantID    string             `json:"tenant_id"`
	Name        string             `json:"name"`
	IsSystem    bool               `json:"is_system"`
	Permissions []PermissionResult `json:"permissions"`
	CreatedAt   time.Time          `json:"created_at"`
}

// UserResult is the public representation of a user in the pool.
type UserResult struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Role      string    `json:"role"`
	RoleID    *string   `json:"role_id"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
}

// UsersPage wraps a paginated user list.
type UsersPage struct {
	Users      []UserResult `json:"users"`
	Total      int          `json:"total"`
	Page       int          `json:"page"`
	TotalPages int          `json:"total_pages"`
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

// Service implements all Admin API operations.
type Service struct {
	pool     *pgxpool.Pool
	resetSvc *auth.ResetService
	logger   zerolog.Logger
}

// New creates a Service.
func New(pool *pgxpool.Pool, resetSvc *auth.ResetService, logger zerolog.Logger) *Service {
	return &Service{pool: pool, resetSvc: resetSvc, logger: logger}
}

// ---------------------------------------------------------------------------
// Tenant management (super_admin only — caller must hold "tenant:manage" perm)
// ---------------------------------------------------------------------------

// CreateTenant creates a new tenant with a freshly generated JWT secret.
func (s *Service) CreateTenant(ctx context.Context, name, slug string) (*TenantResult, error) {
	secret, err := generateSecret()
	if err != nil {
		return nil, fmt.Errorf("generate jwt secret: %w", err)
	}

	var id int64
	var t TenantResult
	err = s.pool.QueryRow(ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ($1, $2, $3, true)
		RETURNING id, name, slug, is_active, created_at
	`, name, slug, secret).Scan(&id, &t.Name, &t.Slug, &t.IsActive, &t.CreatedAt)
	if err != nil {
		if isDuplicateErr(err) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("create tenant: %w", err)
	}
	t.ID = strconv.FormatInt(id, 10)
	s.logger.Info().Str("slug", slug).Str("id", t.ID).Msg("admin: tenant created")
	return &t, nil
}

// ListTenants returns all tenants (active and inactive).
func (s *Service) ListTenants(ctx context.Context) ([]TenantResult, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, slug, is_active, created_at
		FROM tenants
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	defer rows.Close()

	var tenants []TenantResult
	for rows.Next() {
		var t TenantResult
		var id int64
		if err := rows.Scan(&id, &t.Name, &t.Slug, &t.IsActive, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		t.ID = strconv.FormatInt(id, 10)
		tenants = append(tenants, t)
	}
	if tenants == nil {
		tenants = []TenantResult{}
	}
	return tenants, rows.Err()
}

// UpdateTenant updates the tenant's display name.
func (s *Service) UpdateTenant(ctx context.Context, tenantID int64, name string) (*TenantResult, error) {
	var t TenantResult
	var id int64
	err := s.pool.QueryRow(ctx, `
		UPDATE tenants SET name = $1, updated_at = NOW()
		WHERE id = $2
		RETURNING id, name, slug, is_active, created_at
	`, name, tenantID).Scan(&id, &t.Name, &t.Slug, &t.IsActive, &t.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("update tenant: %w", err)
	}
	t.ID = strconv.FormatInt(id, 10)
	return &t, nil
}

// DeactivateTenant soft-deactivates a tenant (sets is_active = false).
func (s *Service) DeactivateTenant(ctx context.Context, tenantID int64) error {
	ct, err := s.pool.Exec(ctx, `
		UPDATE tenants SET is_active = false, updated_at = NOW()
		WHERE id = $1
	`, tenantID)
	if err != nil {
		return fmt.Errorf("deactivate tenant: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	s.logger.Info().Str("tenant_id", strconv.FormatInt(tenantID, 10)).Msg("admin: tenant deactivated")
	return nil
}

// UpdateTenantCORSOrigins replaces the allowed CORS origins for a tenant.
func (s *Service) UpdateTenantCORSOrigins(ctx context.Context, tenantID int64, origins []string) error {
	if origins == nil {
		origins = []string{}
	}
	ct, err := s.pool.Exec(ctx, `
		UPDATE tenants SET cors_origins = $2, updated_at = NOW()
		WHERE id = $1
	`, tenantID, origins)
	if err != nil {
		return fmt.Errorf("update cors_origins: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------------
// Permission management (tenant-scoped)
// ---------------------------------------------------------------------------

// CreatePermission adds a new permission to the given tenant.
func (s *Service) CreatePermission(ctx context.Context, tenantID int64, name, description string) (*PermissionResult, error) {
	var p PermissionResult
	var id, tid int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO permissions (tenant_id, name, description)
		VALUES ($1, $2, $3)
		RETURNING id, tenant_id, name, description, created_at
	`, tenantID, name, description).Scan(&id, &tid, &p.Name, &p.Description, &p.CreatedAt)
	if err != nil {
		if isDuplicateErr(err) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("create permission: %w", err)
	}
	p.ID = strconv.FormatInt(id, 10)
	p.TenantID = strconv.FormatInt(tid, 10)
	return &p, nil
}

// ListPermissions returns all permissions for the given tenant.
func (s *Service) ListPermissions(ctx context.Context, tenantID int64) ([]PermissionResult, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, description, created_at
		FROM permissions
		WHERE tenant_id = $1
		ORDER BY name
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}
	defer rows.Close()

	var perms []PermissionResult
	for rows.Next() {
		var p PermissionResult
		var id, tid int64
		if err := rows.Scan(&id, &tid, &p.Name, &p.Description, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		p.ID = strconv.FormatInt(id, 10)
		p.TenantID = strconv.FormatInt(tid, 10)
		perms = append(perms, p)
	}
	if perms == nil {
		perms = []PermissionResult{}
	}
	return perms, rows.Err()
}

// DeletePermission removes a permission from the tenant.
// Cascades to role_permissions and user_permissions automatically (FK ON DELETE CASCADE).
func (s *Service) DeletePermission(ctx context.Context, tenantID, permissionID int64) error {
	ct, err := s.pool.Exec(ctx, `
		DELETE FROM permissions WHERE id = $1 AND tenant_id = $2
	`, permissionID, tenantID)
	if err != nil {
		return fmt.Errorf("delete permission: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------------
// Role management (tenant-scoped)
// ---------------------------------------------------------------------------

// CreateRole creates a role and optionally assigns permissions to it.
func (s *Service) CreateRole(ctx context.Context, tenantID int64, name string, permissionIDs []int64) (*RoleResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin create role tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var roleID int64
	var createdAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO roles (tenant_id, name, is_system, created_at)
		VALUES ($1, $2, false, NOW())
		RETURNING id, created_at
	`, tenantID, name).Scan(&roleID, &createdAt)
	if err != nil {
		if isDuplicateErr(err) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("insert role: %w", err)
	}

	for _, permID := range permissionIDs {
		_, err = tx.Exec(ctx, `
			INSERT INTO role_permissions (role_id, permission_id)
			SELECT $1, id FROM permissions WHERE id = $2 AND tenant_id = $3
			ON CONFLICT DO NOTHING
		`, roleID, permID, tenantID)
		if err != nil {
			return nil, fmt.Errorf("assign permission to role: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit create role: %w", err)
	}

	return s.getRoleByID(ctx, tenantID, roleID)
}

// ListRoles returns all roles for the tenant, each with their assigned permissions.
func (s *Service) ListRoles(ctx context.Context, tenantID int64) ([]RoleResult, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, is_system, created_at
		FROM roles
		WHERE tenant_id = $1
		ORDER BY name
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	defer rows.Close()

	var roles []RoleResult
	for rows.Next() {
		var r RoleResult
		var id, tid int64
		if err := rows.Scan(&id, &tid, &r.Name, &r.IsSystem, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		r.ID = strconv.FormatInt(id, 10)
		r.TenantID = strconv.FormatInt(tid, 10)
		r.Permissions = []PermissionResult{}
		roles = append(roles, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if roles == nil {
		return []RoleResult{}, nil
	}

	for i := range roles {
		roleIDInt, _ := strconv.ParseInt(roles[i].ID, 10, 64)
		perms, err := s.loadRolePermissions(ctx, roleIDInt)
		if err != nil {
			return nil, err
		}
		roles[i].Permissions = perms
	}

	return roles, nil
}

// UpdateRolePermissions replaces the permission set on a role.
func (s *Service) UpdateRolePermissions(ctx context.Context, tenantID, roleID int64, permissionIDs []int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin update role perms tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var exists bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM roles WHERE id = $1 AND tenant_id = $2)`, roleID, tenantID).Scan(&exists)
	if err != nil || !exists {
		return ErrNotFound
	}

	_, err = tx.Exec(ctx, `DELETE FROM role_permissions WHERE role_id = $1`, roleID)
	if err != nil {
		return fmt.Errorf("clear role permissions: %w", err)
	}

	for _, permID := range permissionIDs {
		_, err = tx.Exec(ctx, `
			INSERT INTO role_permissions (role_id, permission_id)
			SELECT $1, id FROM permissions WHERE id = $2 AND tenant_id = $3
			ON CONFLICT DO NOTHING
		`, roleID, permID, tenantID)
		if err != nil {
			return fmt.Errorf("assign permission: %w", err)
		}
	}

	return tx.Commit(ctx)
}

// DeleteRole removes a role from the tenant.
func (s *Service) DeleteRole(ctx context.Context, tenantID, roleID int64) error {
	ct, err := s.pool.Exec(ctx, `
		DELETE FROM roles WHERE id = $1 AND tenant_id = $2 AND is_system = false
	`, roleID, tenantID)
	if err != nil {
		return fmt.Errorf("delete role: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------------
// User pool management (tenant-scoped)
// ---------------------------------------------------------------------------

// ListUsers returns a paginated, searchable list of users in the tenant.
func (s *Service) ListUsers(ctx context.Context, tenantID int64, search string, page, limit int) (*UsersPage, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	offset := (page - 1) * limit

	searchPattern := "%" + search + "%"

	var total int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM users
		WHERE tenant_id = $1
		  AND deleted_at IS NULL
		  AND ($2 = '%%' OR email ILIKE $2 OR first_name ILIKE $2 OR last_name ILIKE $2)
	`, tenantID, searchPattern).Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("count users: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT u.id, u.tenant_id, u.email, u.first_name, u.last_name,
		       COALESCE(r.name, '') as role_name, u.role_id, u.is_active, u.created_at
		FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.tenant_id = $1
		  AND u.deleted_at IS NULL
		  AND ($2 = '%%' OR u.email ILIKE $2 OR u.first_name ILIKE $2 OR u.last_name ILIKE $2)
		ORDER BY u.created_at DESC
		LIMIT $3 OFFSET $4
	`, tenantID, searchPattern, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []UserResult
	for rows.Next() {
		var u UserResult
		var id, tid int64
		var roleID *int64
		if err := rows.Scan(&id, &tid, &u.Email, &u.FirstName, &u.LastName,
			&u.Role, &roleID, &u.IsActive, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		u.ID = strconv.FormatInt(id, 10)
		u.TenantID = strconv.FormatInt(tid, 10)
		if roleID != nil {
			rs := strconv.FormatInt(*roleID, 10)
			u.RoleID = &rs
		}
		users = append(users, u)
	}
	if users == nil {
		users = []UserResult{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	totalPages := (total + limit - 1) / limit
	if totalPages == 0 {
		totalPages = 1
	}
	return &UsersPage{
		Users:      users,
		Total:      total,
		Page:       page,
		TotalPages: totalPages,
	}, nil
}

// CreateUser creates a new user in the tenant with a hashed password.
func (s *Service) CreateUser(ctx context.Context, tenantID int64, email, password, firstName, lastName string, roleID *int64) (*UserResult, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), auth.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin create user tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var userID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO users (tenant_id, email, first_name, last_name, role_id, is_active)
		VALUES ($1, $2, $3, $4, $5, true)
		RETURNING id
	`, tenantID, email, firstName, lastName, roleID).Scan(&userID)
	if err != nil {
		if isDuplicateErr(err) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("insert user: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO user_credentials (user_id, tenant_id, password_hash)
		VALUES ($1, $2, $3)
	`, userID, tenantID, string(hash))
	if err != nil {
		return nil, fmt.Errorf("insert credentials: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit create user: %w", err)
	}

	return s.getUserByID(ctx, tenantID, userID)
}

// GetUser fetches a single user by ID within the tenant.
func (s *Service) GetUser(ctx context.Context, tenantID, userID int64) (*UserResult, error) {
	return s.getUserByID(ctx, tenantID, userID)
}

// UpdateUser updates a user's profile fields.
func (s *Service) UpdateUser(ctx context.Context, tenantID, userID int64, email, firstName, lastName string) (*UserResult, error) {
	ct, err := s.pool.Exec(ctx, `
		UPDATE users
		SET email = $1, first_name = $2, last_name = $3, updated_at = NOW()
		WHERE id = $4 AND tenant_id = $5 AND deleted_at IS NULL
	`, email, firstName, lastName, userID, tenantID)
	if err != nil {
		if isDuplicateErr(err) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("update user: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.getUserByID(ctx, tenantID, userID)
}

// AssignUserRole sets the role for a user within the tenant.
func (s *Service) AssignUserRole(ctx context.Context, tenantID, userID, roleID int64) error {
	var roleExists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM roles WHERE id = $1 AND tenant_id = $2)`, roleID, tenantID).Scan(&roleExists)
	if err != nil || !roleExists {
		return ErrNotFound
	}

	ct, err := s.pool.Exec(ctx, `
		UPDATE users SET role_id = $1, updated_at = NOW()
		WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL
	`, roleID, userID, tenantID)
	if err != nil {
		return fmt.Errorf("assign role: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteUser soft-deletes a user (sets deleted_at, is_active = false).
func (s *Service) DeleteUser(ctx context.Context, tenantID, userID int64) error {
	ct, err := s.pool.Exec(ctx, `
		UPDATE users SET deleted_at = NOW(), is_active = false, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`, userID, tenantID)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ForcePasswordReset dispatches a password reset email to the specified user.
func (s *Service) ForcePasswordReset(ctx context.Context, tenantID, userID int64) error {
	var email, tenantSlug string
	err := s.pool.QueryRow(ctx, `
		SELECT u.email, t.slug
		FROM users u
		JOIN tenants t ON t.id = u.tenant_id
		WHERE u.id = $1 AND u.tenant_id = $2 AND u.is_active = true AND u.deleted_at IS NULL
	`, userID, tenantID).Scan(&email, &tenantSlug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("lookup user for force reset: %w", err)
	}

	s.logger.Info().Str("user_id", strconv.FormatInt(userID, 10)).Str("tenant", tenantSlug).Msg("admin: force password reset dispatched")
	return s.resetSvc.ForgotPassword(ctx, tenantSlug, email)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (s *Service) getUserByID(ctx context.Context, tenantID, userID int64) (*UserResult, error) {
	var u UserResult
	var id, tid int64
	var roleID *int64
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, u.tenant_id, u.email, u.first_name, u.last_name,
		       COALESCE(r.name, '') as role_name, u.role_id, u.is_active, u.created_at
		FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.id = $1 AND u.tenant_id = $2 AND u.deleted_at IS NULL
	`, userID, tenantID).Scan(
		&id, &tid, &u.Email, &u.FirstName, &u.LastName,
		&u.Role, &roleID, &u.IsActive, &u.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get user: %w", err)
	}
	u.ID = strconv.FormatInt(id, 10)
	u.TenantID = strconv.FormatInt(tid, 10)
	if roleID != nil {
		rs := strconv.FormatInt(*roleID, 10)
		u.RoleID = &rs
	}
	return &u, nil
}

func (s *Service) getRoleByID(ctx context.Context, tenantID, roleID int64) (*RoleResult, error) {
	var r RoleResult
	var id, tid int64
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, is_system, created_at
		FROM roles WHERE id = $1 AND tenant_id = $2
	`, roleID, tenantID).Scan(&id, &tid, &r.Name, &r.IsSystem, &r.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get role: %w", err)
	}
	r.ID = strconv.FormatInt(id, 10)
	r.TenantID = strconv.FormatInt(tid, 10)
	perms, err := s.loadRolePermissions(ctx, roleID)
	if err != nil {
		return nil, err
	}
	r.Permissions = perms
	return &r, nil
}

func (s *Service) loadRolePermissions(ctx context.Context, roleID int64) ([]PermissionResult, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT p.id, p.tenant_id, p.name, p.description, p.created_at
		FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		WHERE rp.role_id = $1
		ORDER BY p.name
	`, roleID)
	if err != nil {
		return nil, fmt.Errorf("load role permissions: %w", err)
	}
	defer rows.Close()

	var perms []PermissionResult
	for rows.Next() {
		var p PermissionResult
		var id, tid int64
		if err := rows.Scan(&id, &tid, &p.Name, &p.Description, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan role permission: %w", err)
		}
		p.ID = strconv.FormatInt(id, 10)
		p.TenantID = strconv.FormatInt(tid, 10)
		perms = append(perms, p)
	}
	if perms == nil {
		perms = []PermissionResult{}
	}
	return perms, rows.Err()
}

// generateSecret generates a 32-byte random hex string for use as a JWT secret.
func generateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// isDuplicateErr returns true when err is a PostgreSQL unique_violation (code 23505).
func isDuplicateErr(err error) bool {
	if err == nil {
		return false
	}
	e := err.Error()
	return containsSubstr(e, "23505") || containsSubstr(e, "duplicate") || containsSubstr(e, "unique")
}

func containsSubstr(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
