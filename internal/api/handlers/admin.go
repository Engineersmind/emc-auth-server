package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
)

// AdminHandler holds handlers for all Admin API endpoints.
type AdminHandler struct {
	svc         *admin.Service
	appLimitSvc *auth.AppRateLimitService
	corsSvc     *mw.TenantCORSService
	audit       *audit.Logger
	logger      zerolog.Logger
}

// NewAdminHandler creates an AdminHandler.
func NewAdminHandler(svc *admin.Service, auditLog *audit.Logger, logger zerolog.Logger) *AdminHandler {
	return &AdminHandler{svc: svc, audit: auditLog, logger: logger}
}

// WithAppRateLimits attaches the AppRateLimitService for CRUD handler support.
func (h *AdminHandler) WithAppRateLimits(svc *auth.AppRateLimitService) *AdminHandler {
	h.appLimitSvc = svc
	return h
}

// WithCORS attaches the TenantCORSService for cache invalidation on origin updates.
func (h *AdminHandler) WithCORS(svc *mw.TenantCORSService) *AdminHandler {
	h.corsSvc = svc
	return h
}

// claimsFromCtx extracts *auth.Claims injected by JWTRequired middleware.
func claimsFromCtx(c echo.Context) (*auth.Claims, bool) {
	claims, ok := c.Get("user").(*auth.Claims)
	return claims, ok && claims != nil
}

// tenantIDFromClaims parses the tenant UUID from JWT claims.
func tenantIDFromClaims(claims *auth.Claims) (uuid.UUID, error) {
	return uuid.Parse(claims.TenantID)
}

// ---------------------------------------------------------------------------
// Tenant management (requires "tenant:manage" permission)
// ---------------------------------------------------------------------------

// CreateTenantRequest is the body for POST /api/v1/admin/tenants.
type CreateTenantRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// UpdateTenantRequest is the body for PUT /api/v1/admin/tenants/:id.
type UpdateTenantRequest struct {
	Name string `json:"name"`
}

// CreateTenant handles POST /api/v1/admin/tenants.
//
// @Summary      Create tenant
// @Description  Creates a new isolated tenant. Requires tenant:manage permission (super_admin only).
// @Tags         admin-tenants
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      CreateTenantRequest         true  "Tenant details"
// @Success      201   {object}  admin.TenantResult
// @Failure      400   {object}  map[string]string
// @Failure      403   {object}  map[string]string
// @Failure      409   {object}  map[string]string  "Slug already taken"
// @Router       /api/v1/admin/tenants [post]
func (h *AdminHandler) CreateTenant(c echo.Context) error {
	var req CreateTenantRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.Name == "" || req.Slug == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "name and slug are required"})
	}

	claims, _ := claimsFromCtx(c)
	result, err := h.svc.CreateTenant(c.Request().Context(), req.Name, req.Slug)
	if err != nil {
		if errors.Is(err, admin.ErrAlreadyExists) {
			return c.JSON(http.StatusConflict, map[string]string{"error": "slug already taken"})
		}
		h.logger.Error().Err(err).Msg("admin: create tenant failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create tenant"})
	}
	h.auditAdmin(c, claims, audit.ActionAdminTenantCreated, "tenant", result.ID)
	return c.JSON(http.StatusCreated, result)
}

// ListTenants handles GET /api/v1/admin/tenants.
//
// @Summary      List tenants
// @Description  Returns all tenants. Requires tenant:manage permission.
// @Tags         admin-tenants
// @Produce      json
// @Security     BearerAuth
// @Success      200  {array}   admin.TenantResult
// @Failure      403  {object}  map[string]string
// @Router       /api/v1/admin/tenants [get]
func (h *AdminHandler) ListTenants(c echo.Context) error {
	tenants, err := h.svc.ListTenants(c.Request().Context())
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: list tenants failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list tenants"})
	}
	return c.JSON(http.StatusOK, tenants)
}

// UpdateTenant handles PUT /api/v1/admin/tenants/:id.
//
// @Summary      Update tenant
// @Description  Updates the tenant's display name. Requires tenant:manage permission.
// @Tags         admin-tenants
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      string              true  "Tenant ID (UUID)"
// @Param        body  body      UpdateTenantRequest true  "Updated fields"
// @Success      200   {object}  admin.TenantResult
// @Failure      400   {object}  map[string]string
// @Failure      404   {object}  map[string]string
// @Router       /api/v1/admin/tenants/{id} [put]
func (h *AdminHandler) UpdateTenant(c echo.Context) error {
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	var req UpdateTenantRequest
	if err := c.Bind(&req); err != nil || req.Name == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "name is required"})
	}
	result, err := h.svc.UpdateTenant(c.Request().Context(), tenantID, req.Name)
	if err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "tenant not found"})
		}
		h.logger.Error().Err(err).Msg("admin: update tenant failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update tenant"})
	}
	claims, _ := claimsFromCtx(c)
	h.auditAdmin(c, claims, audit.ActionAdminTenantUpdated, "tenant", tenantID.String())
	return c.JSON(http.StatusOK, result)
}

// DeactivateTenant handles DELETE /api/v1/admin/tenants/:id.
//
// @Summary      Deactivate tenant
// @Description  Soft-deactivates a tenant (sets is_active=false). Requires tenant:manage permission.
// @Tags         admin-tenants
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Tenant ID (UUID)"
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/admin/tenants/{id} [delete]
func (h *AdminHandler) DeactivateTenant(c echo.Context) error {
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	if err := h.svc.DeactivateTenant(c.Request().Context(), tenantID); err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "tenant not found"})
		}
		h.logger.Error().Err(err).Msg("admin: deactivate tenant failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to deactivate tenant"})
	}
	claims, _ := claimsFromCtx(c)
	h.auditAdmin(c, claims, audit.ActionAdminTenantDeactivated, "tenant", tenantID.String())
	return c.JSON(http.StatusOK, map[string]string{"message": "tenant deactivated"})
}

// ---------------------------------------------------------------------------
// Permission management (tenant-scoped, requires "admin:access")
// ---------------------------------------------------------------------------

// CreatePermissionRequest is the body for POST /api/v1/admin/permissions.
type CreatePermissionRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// CreatePermission handles POST /api/v1/admin/permissions.
//
// @Summary      Create permission
// @Description  Creates a new permission within the caller's tenant. Requires admin:access.
// @Tags         admin-rbac
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      CreatePermissionRequest  true  "Permission details"
// @Success      201   {object}  admin.PermissionResult
// @Failure      400   {object}  map[string]string
// @Failure      409   {object}  map[string]string  "Permission name already exists in this tenant"
// @Router       /api/v1/admin/permissions [post]
func (h *AdminHandler) CreatePermission(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	var req CreatePermissionRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.Name == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "name is required"})
	}

	result, err := h.svc.CreatePermission(c.Request().Context(), tenantID, req.Name, req.Description)
	if err != nil {
		if errors.Is(err, admin.ErrAlreadyExists) {
			return c.JSON(http.StatusConflict, map[string]string{"error": "permission already exists in this tenant"})
		}
		h.logger.Error().Err(err).Msg("admin: create permission failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create permission"})
	}
	h.auditAdmin(c, claims, audit.ActionAdminPermissionCreated, "permission", result.ID)
	return c.JSON(http.StatusCreated, result)
}

// ListPermissions handles GET /api/v1/admin/permissions.
//
// @Summary      List permissions
// @Description  Returns all permissions for the caller's tenant. Requires admin:access.
// @Tags         admin-rbac
// @Produce      json
// @Security     BearerAuth
// @Success      200  {array}   admin.PermissionResult
// @Router       /api/v1/admin/permissions [get]
func (h *AdminHandler) ListPermissions(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	perms, err := h.svc.ListPermissions(c.Request().Context(), tenantID)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: list permissions failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list permissions"})
	}
	return c.JSON(http.StatusOK, perms)
}

// DeletePermission handles DELETE /api/v1/admin/permissions/:id.
//
// @Summary      Delete permission
// @Description  Deletes a permission from the caller's tenant. Cascades to roles and users. Requires admin:access.
// @Tags         admin-rbac
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Permission ID (UUID)"
// @Success      200  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/admin/permissions/{id} [delete]
func (h *AdminHandler) DeletePermission(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	permID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid permission id"})
	}

	if err := h.svc.DeletePermission(c.Request().Context(), tenantID, permID); err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "permission not found"})
		}
		h.logger.Error().Err(err).Msg("admin: delete permission failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete permission"})
	}
	h.auditAdmin(c, claims, audit.ActionAdminPermissionDeleted, "permission", permID.String())
	return c.JSON(http.StatusOK, map[string]string{"message": "permission deleted"})
}

// ---------------------------------------------------------------------------
// Role management (tenant-scoped, requires "admin:access")
// ---------------------------------------------------------------------------

// CreateRoleRequest is the body for POST /api/v1/admin/roles.
type CreateRoleRequest struct {
	Name          string   `json:"name"`
	PermissionIDs []string `json:"permission_ids"`
}

// UpdateRolePermissionsRequest is the body for PUT /api/v1/admin/roles/:id/permissions.
type UpdateRolePermissionsRequest struct {
	PermissionIDs []string `json:"permission_ids"`
}

// CreateRole handles POST /api/v1/admin/roles.
//
// @Summary      Create role
// @Description  Creates a role in the caller's tenant with optional permission assignments. Requires admin:access.
// @Tags         admin-rbac
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      CreateRoleRequest  true  "Role details"
// @Success      201   {object}  admin.RoleResult
// @Failure      400   {object}  map[string]string
// @Failure      409   {object}  map[string]string  "Role name already exists"
// @Router       /api/v1/admin/roles [post]
func (h *AdminHandler) CreateRole(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	var req CreateRoleRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.Name == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "name is required"})
	}

	permUUIDs, err := parseUUIDs(req.PermissionIDs)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid permission_id: " + err.Error()})
	}

	result, err := h.svc.CreateRole(c.Request().Context(), tenantID, req.Name, permUUIDs)
	if err != nil {
		if errors.Is(err, admin.ErrAlreadyExists) {
			return c.JSON(http.StatusConflict, map[string]string{"error": "role name already exists in this tenant"})
		}
		h.logger.Error().Err(err).Msg("admin: create role failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create role"})
	}
	h.auditAdmin(c, claims, audit.ActionAdminRoleCreated, "role", result.ID)
	return c.JSON(http.StatusCreated, result)
}

// ListRoles handles GET /api/v1/admin/roles.
//
// @Summary      List roles
// @Description  Returns all roles in the caller's tenant with their permission lists. Requires admin:access.
// @Tags         admin-rbac
// @Produce      json
// @Security     BearerAuth
// @Success      200  {array}   admin.RoleResult
// @Router       /api/v1/admin/roles [get]
func (h *AdminHandler) ListRoles(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	roles, err := h.svc.ListRoles(c.Request().Context(), tenantID)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: list roles failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list roles"})
	}
	return c.JSON(http.StatusOK, roles)
}

// UpdateRolePermissions handles PUT /api/v1/admin/roles/:id/permissions.
//
// @Summary      Update role permissions
// @Description  Replaces the permission set on a role. Requires admin:access.
// @Tags         admin-rbac
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      string                       true  "Role ID (UUID)"
// @Param        body  body      UpdateRolePermissionsRequest true  "Permission IDs to assign"
// @Success      200   {object}  map[string]string
// @Failure      404   {object}  map[string]string
// @Router       /api/v1/admin/roles/{id}/permissions [put]
func (h *AdminHandler) UpdateRolePermissions(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	roleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role id"})
	}

	var req UpdateRolePermissionsRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	permUUIDs, err := parseUUIDs(req.PermissionIDs)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid permission_id: " + err.Error()})
	}

	if err := h.svc.UpdateRolePermissions(c.Request().Context(), tenantID, roleID, permUUIDs); err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "role not found"})
		}
		h.logger.Error().Err(err).Msg("admin: update role permissions failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update role permissions"})
	}
	h.auditAdmin(c, claims, audit.ActionAdminRolePermissionsUpdated, "role", roleID.String())
	return c.JSON(http.StatusOK, map[string]string{"message": "role permissions updated"})
}

// DeleteRole handles DELETE /api/v1/admin/roles/:id.
//
// @Summary      Delete role
// @Description  Deletes a non-system role from the tenant. Users assigned this role will have their role cleared. Requires admin:access.
// @Tags         admin-rbac
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Role ID (UUID)"
// @Success      200  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/admin/roles/{id} [delete]
func (h *AdminHandler) DeleteRole(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	roleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role id"})
	}

	if err := h.svc.DeleteRole(c.Request().Context(), tenantID, roleID); err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "role not found or is a system role"})
		}
		h.logger.Error().Err(err).Msg("admin: delete role failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete role"})
	}
	h.auditAdmin(c, claims, audit.ActionAdminRoleDeleted, "role", roleID.String())
	return c.JSON(http.StatusOK, map[string]string{"message": "role deleted"})
}

// ---------------------------------------------------------------------------
// User pool management (tenant-scoped, requires "admin:access")
// ---------------------------------------------------------------------------

// CreateUserAdminRequest is the body for POST /api/v1/admin/users.
type CreateUserAdminRequest struct {
	Email     string  `json:"email"`
	Password  string  `json:"password"`
	FirstName string  `json:"first_name"`
	LastName  string  `json:"last_name"`
	RoleID    *string `json:"role_id"`
}

// UpdateUserAdminRequest is the body for PUT /api/v1/admin/users/:id.
type UpdateUserAdminRequest struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// AssignRoleRequest is the body for PUT /api/v1/admin/users/:id/role.
type AssignRoleRequest struct {
	RoleID string `json:"role_id"`
}

// ListUsers handles GET /api/v1/admin/users.
//
// @Summary      List users
// @Description  Returns a paginated, searchable list of users in the caller's tenant. Requires admin:access.
// @Tags         admin-users
// @Produce      json
// @Security     BearerAuth
// @Param        search  query     string  false  "Search by email, first name, or last name"
// @Param        page    query     int     false  "Page number (default: 1)"
// @Param        limit   query     int     false  "Page size (default: 20, max: 100)"
// @Success      200     {object}  admin.UsersPage
// @Router       /api/v1/admin/users [get]
func (h *AdminHandler) ListUsers(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	search := c.QueryParam("search")
	page, _ := strconv.Atoi(c.QueryParam("page"))
	limit, _ := strconv.Atoi(c.QueryParam("limit"))

	result, err := h.svc.ListUsers(c.Request().Context(), tenantID, search, page, limit)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: list users failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list users"})
	}
	return c.JSON(http.StatusOK, result)
}

// CreateAdminUser handles POST /api/v1/admin/users.
//
// @Summary      Create user
// @Description  Creates a user in the caller's tenant with an optional role. Requires admin:access.
// @Tags         admin-users
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      CreateUserAdminRequest  true  "User details"
// @Success      201   {object}  admin.UserResult
// @Failure      400   {object}  map[string]string
// @Failure      409   {object}  map[string]string  "Email already registered"
// @Router       /api/v1/admin/users [post]
func (h *AdminHandler) CreateAdminUser(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	var req CreateUserAdminRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.Email == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "email is required"})
	}
	if len(req.Password) < 8 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
	}

	var roleID *uuid.UUID
	if req.RoleID != nil && *req.RoleID != "" {
		rid, err := uuid.Parse(*req.RoleID)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role_id"})
		}
		roleID = &rid
	}

	result, err := h.svc.CreateUser(c.Request().Context(), tenantID, req.Email, req.Password, req.FirstName, req.LastName, roleID)
	if err != nil {
		if errors.Is(err, admin.ErrAlreadyExists) {
			return c.JSON(http.StatusConflict, map[string]string{"error": "email already registered in this tenant"})
		}
		h.logger.Error().Err(err).Msg("admin: create user failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create user"})
	}
	h.auditAdmin(c, claims, audit.ActionAdminUserCreated, "user", result.ID)
	return c.JSON(http.StatusCreated, result)
}

// GetAdminUser handles GET /api/v1/admin/users/:id.
//
// @Summary      Get user
// @Description  Returns a user's details. Requires admin:access.
// @Tags         admin-users
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "User ID (UUID)"
// @Success      200  {object}  admin.UserResult
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/admin/users/{id} [get]
func (h *AdminHandler) GetAdminUser(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user id"})
	}

	result, err := h.svc.GetUser(c.Request().Context(), tenantID, userID)
	if err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
		}
		h.logger.Error().Err(err).Msg("admin: get user failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get user"})
	}
	return c.JSON(http.StatusOK, result)
}

// UpdateAdminUser handles PUT /api/v1/admin/users/:id.
//
// @Summary      Update user
// @Description  Updates a user's profile (email, name). Requires admin:access.
// @Tags         admin-users
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      string                 true  "User ID (UUID)"
// @Param        body  body      UpdateUserAdminRequest true  "Updated fields"
// @Success      200   {object}  admin.UserResult
// @Failure      400   {object}  map[string]string
// @Failure      404   {object}  map[string]string
// @Router       /api/v1/admin/users/{id} [put]
func (h *AdminHandler) UpdateAdminUser(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user id"})
	}

	var req UpdateUserAdminRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.Email == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "email is required"})
	}

	result, err := h.svc.UpdateUser(c.Request().Context(), tenantID, userID, req.Email, req.FirstName, req.LastName)
	if err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
		}
		if errors.Is(err, admin.ErrAlreadyExists) {
			return c.JSON(http.StatusConflict, map[string]string{"error": "email already taken"})
		}
		h.logger.Error().Err(err).Msg("admin: update user failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update user"})
	}
	h.auditAdmin(c, claims, audit.ActionAdminUserUpdated, "user", userID.String())
	return c.JSON(http.StatusOK, result)
}

// AssignUserRole handles PUT /api/v1/admin/users/:id/role.
//
// @Summary      Assign role to user
// @Description  Sets the user's role within the tenant. Requires admin:access.
// @Tags         admin-users
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      string            true  "User ID (UUID)"
// @Param        body  body      AssignRoleRequest true  "Role ID to assign"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  map[string]string
// @Failure      404   {object}  map[string]string
// @Router       /api/v1/admin/users/{id}/role [put]
func (h *AdminHandler) AssignUserRole(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user id"})
	}

	var req AssignRoleRequest
	if err := c.Bind(&req); err != nil || req.RoleID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "role_id is required"})
	}
	roleID, err := uuid.Parse(req.RoleID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role_id"})
	}

	if err := h.svc.AssignUserRole(c.Request().Context(), tenantID, userID, roleID); err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "user or role not found"})
		}
		h.logger.Error().Err(err).Msg("admin: assign role failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to assign role"})
	}
	h.auditAdmin(c, claims, audit.ActionAdminUserRoleAssigned, "user", userID.String())
	return c.JSON(http.StatusOK, map[string]string{"message": "role assigned"})
}

// DeleteAdminUser handles DELETE /api/v1/admin/users/:id.
//
// @Summary      Delete user
// @Description  Soft-deletes a user (is_deleted=true, is_active=false). ID preserved for audit. Requires admin:access.
// @Tags         admin-users
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "User ID (UUID)"
// @Success      200  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/admin/users/{id} [delete]
func (h *AdminHandler) DeleteAdminUser(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user id"})
	}

	if err := h.svc.DeleteUser(c.Request().Context(), tenantID, userID); err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
		}
		h.logger.Error().Err(err).Msg("admin: delete user failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete user"})
	}
	h.auditAdmin(c, claims, audit.ActionAdminUserDeleted, "user", userID.String())
	return c.JSON(http.StatusOK, map[string]string{"message": "user deleted"})
}

// ForcePasswordReset handles POST /api/v1/admin/users/:id/force-password-reset.
//
// @Summary      Force password reset
// @Description  Sends a password reset email to the specified user. Requires admin:access.
// @Tags         admin-users
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "User ID (UUID)"
// @Success      200  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/admin/users/{id}/force-password-reset [post]
func (h *AdminHandler) ForcePasswordReset(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user id"})
	}

	if err := h.svc.ForcePasswordReset(c.Request().Context(), tenantID, userID); err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found or inactive"})
		}
		h.logger.Error().Err(err).Msg("admin: force password reset failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to dispatch password reset"})
	}
	h.auditAdmin(c, claims, audit.ActionAdminForcePasswordReset, "user", userID.String())
	return c.JSON(http.StatusOK, map[string]string{"message": "password reset email dispatched"})
}

// ---------------------------------------------------------------------------
// Monitoring stats endpoints
// ---------------------------------------------------------------------------

// GetStats handles GET /api/v1/admin/stats — tenant-scoped summary for admins.
func (h *AdminHandler) GetStats(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}
	result, err := h.audit.Stats(c.Request().Context(), &tenantID)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: stats query failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to query stats"})
	}
	return c.JSON(http.StatusOK, result)
}

// GetSystemStats handles GET /api/v1/admin/stats/system — system-wide, super_admin only.
func (h *AdminHandler) GetSystemStats(c echo.Context) error {
	result, err := h.audit.Stats(c.Request().Context(), nil)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: system stats query failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to query system stats"})
	}
	return c.JSON(http.StatusOK, result)
}

// ---------------------------------------------------------------------------
// Audit log query endpoints
// ---------------------------------------------------------------------------

// GetTenantAuditLogs handles GET /api/v1/admin/audit-logs.
//
// @Summary      Tenant audit log
// @Description  Returns paginated audit events scoped to the caller's tenant. Requires admin:access.
// @Tags         admin-audit
// @Produce      json
// @Security     BearerAuth
// @Param        action   query     string  false  "Filter by action (e.g. auth.login)"
// @Param        user_id  query     string  false  "Filter by user UUID"
// @Param        from     query     string  false  "From datetime (RFC3339, e.g. 2026-01-01T00:00:00Z)"
// @Param        to       query     string  false  "To datetime (RFC3339)"
// @Param        page     query     int     false  "Page (default 1)"
// @Param        limit    query     int     false  "Page size (default 50, max 200)"
// @Success      200      {object}  audit.LogsPage
// @Router       /api/v1/admin/audit-logs [get]
func (h *AdminHandler) GetTenantAuditLogs(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	p := auditQueryParams(c)
	p.TenantID = &tenantID

	result, err := h.audit.Query(c.Request().Context(), p)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: audit log query failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to query audit logs"})
	}
	return c.JSON(http.StatusOK, result)
}

// GetSystemAuditLogs handles GET /api/v1/admin/audit-logs/system.
//
// @Summary      System-wide audit log
// @Description  Returns paginated audit events across ALL tenants. Requires tenant:manage (super_admin only).
// @Tags         admin-audit
// @Produce      json
// @Security     BearerAuth
// @Param        action   query     string  false  "Filter by action"
// @Param        user_id  query     string  false  "Filter by user UUID"
// @Param        from     query     string  false  "From datetime (RFC3339)"
// @Param        to       query     string  false  "To datetime (RFC3339)"
// @Param        page     query     int     false  "Page (default 1)"
// @Param        limit    query     int     false  "Page size (default 50, max 200)"
// @Success      200      {object}  audit.LogsPage
// @Router       /api/v1/admin/audit-logs/system [get]
func (h *AdminHandler) GetSystemAuditLogs(c echo.Context) error {
	p := auditQueryParams(c)
	// No TenantID filter — returns all tenants.

	result, err := h.audit.Query(c.Request().Context(), p)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: system audit log query failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to query audit logs"})
	}
	return c.JSON(http.StatusOK, result)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// auditAdmin logs an admin action with caller identity from JWT claims.
func (h *AdminHandler) auditAdmin(c echo.Context, claims *auth.Claims, action, resourceType, resourceID string) {
	if claims == nil {
		return
	}
	tid, _ := uuid.Parse(claims.TenantID)
	uid, _ := uuid.Parse(claims.UserID)
	h.audit.Log(c.Request().Context(), audit.Event{
		TenantID:     &tid,
		UserID:       &uid,
		ActorEmail:   claims.Email,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	})
}

// auditQueryParams parses common audit log query parameters from the request.
func auditQueryParams(c echo.Context) audit.QueryParams {
	page, _ := strconv.Atoi(c.QueryParam("page"))
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	p := audit.QueryParams{
		Action:  c.QueryParam("action"),
		UserID:  c.QueryParam("user_id"),
		AgentID: c.QueryParam("agent_id"),
		Page:    page,
		Limit:   limit,
	}
	if from := c.QueryParam("from"); from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			p.From = &t
		}
	}
	if to := c.QueryParam("to"); to != "" {
		if t, err := time.Parse(time.RFC3339, to); err == nil {
			p.To = &t
		}
	}
	return p
}

// parseUUIDs parses a slice of UUID strings into uuid.UUID values.
func parseUUIDs(strs []string) ([]uuid.UUID, error) {
	result := make([]uuid.UUID, 0, len(strs))
	for _, s := range strs {
		id, err := uuid.Parse(s)
		if err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Tenant CORS origins management (requires "tenant:manage")
// ---------------------------------------------------------------------------

// UpdateCORSOriginsRequest is the body for PUT /api/v1/admin/tenants/:id/cors-origins.
type UpdateCORSOriginsRequest struct {
	Origins []string `json:"origins"` // e.g. ["https://app.example.com"]
}

// UpdateTenantCORSOrigins handles PUT /api/v1/admin/tenants/:id/cors-origins.
//
// @Summary      Update tenant CORS origins
// @Description  Replaces the list of allowed CORS origins for a tenant. Pass an empty array to disable CORS enforcement. Requires tenant:manage.
// @Tags         admin-tenants
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      string                  true  "Tenant ID (UUID)"
// @Param        body  body      UpdateCORSOriginsRequest true  "Allowed origins"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  map[string]string
// @Failure      404   {object}  map[string]string
// @Router       /api/v1/admin/tenants/{id}/cors-origins [put]
func (h *AdminHandler) UpdateTenantCORSOrigins(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}

	var req UpdateCORSOriginsRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	if err := h.svc.UpdateTenantCORSOrigins(c.Request().Context(), tenantID, req.Origins); err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "tenant not found"})
		}
		h.logger.Error().Err(err).Msg("admin: update cors origins failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update CORS origins"})
	}

	// Invalidate CORS cache for the tenant slug so changes take effect immediately.
	if h.corsSvc != nil {
		callerClaims := claims
		if callerClaims != nil {
			// We only have the tenant ID here; slug invalidation happens lazily on next miss.
			// For an exact flush, the caller can pass X-Tenant-Slug as a query param.
			if slug := c.QueryParam("slug"); slug != "" {
				h.corsSvc.InvalidateCache(c.Request().Context(), slug)
			}
		}
	}

	h.auditAdmin(c, claims, audit.ActionAdminCORSUpdated, "tenant", tenantID.String())
	return c.JSON(http.StatusOK, map[string]string{"message": "CORS origins updated"})
}

// ---------------------------------------------------------------------------
// Per-app rate limit management (08-02, requires "admin:access")
// ---------------------------------------------------------------------------

// AppLimitRequest is the body for create/update app rate limit endpoints.
type AppLimitRequest struct {
	AppID       string `json:"app_id"`
	RPM         int    `json:"requests_per_minute"`
	Burst       int    `json:"burst"`
	Description string `json:"description"`
}

// CreateAppLimit handles POST /api/v1/admin/app-limits.
//
// @Summary      Create app rate limit
// @Description  Sets a custom per-minute request limit for an application identified by X-App-ID. Requires admin:access.
// @Tags         admin-rate-limits
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      AppLimitRequest      true  "App limit config"
// @Success      201   {object}  auth.AppRateLimit
// @Failure      400   {object}  map[string]string
// @Failure      409   {object}  map[string]string  "app_id already has a rate limit config"
// @Router       /api/v1/admin/app-limits [post]
func (h *AdminHandler) CreateAppLimit(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	var req AppLimitRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.AppID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "app_id is required"})
	}

	limit, err := h.appLimitSvc.CreateAppLimit(c.Request().Context(), tenantID, req.AppID, req.RPM, req.Burst, req.Description)
	if err != nil {
		if containsMsg(err, "already has a rate limit") {
			return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
		}
		h.logger.Error().Err(err).Msg("admin: create app limit failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create app rate limit"})
	}
	h.auditAdmin(c, claims, audit.ActionAdminAppLimitCreated, "app_rate_limit", req.AppID)
	return c.JSON(http.StatusCreated, limit)
}

// ListAppLimits handles GET /api/v1/admin/app-limits.
//
// @Summary      List app rate limits
// @Description  Returns all per-app rate limit configs for the caller's tenant. Requires admin:access.
// @Tags         admin-rate-limits
// @Produce      json
// @Security     BearerAuth
// @Success      200  {array}   auth.AppRateLimit
// @Router       /api/v1/admin/app-limits [get]
func (h *AdminHandler) ListAppLimits(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	limits, err := h.appLimitSvc.ListAppLimits(c.Request().Context(), tenantID)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: list app limits failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list app rate limits"})
	}
	return c.JSON(http.StatusOK, limits)
}

// UpdateAppLimit handles PUT /api/v1/admin/app-limits/:app_id.
//
// @Summary      Update app rate limit
// @Description  Updates the rate limit config for an existing app_id in the tenant. Requires admin:access.
// @Tags         admin-rate-limits
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        app_id  path      string          true  "App ID"
// @Param        body    body      AppLimitRequest true  "Updated limit config"
// @Success      200     {object}  auth.AppRateLimit
// @Failure      404     {object}  map[string]string
// @Router       /api/v1/admin/app-limits/{app_id} [put]
func (h *AdminHandler) UpdateAppLimit(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	appID := c.Param("app_id")
	if appID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "app_id path param required"})
	}

	var req AppLimitRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	limit, err := h.appLimitSvc.UpdateAppLimit(c.Request().Context(), tenantID, appID, req.RPM, req.Burst, req.Description)
	if err != nil {
		if containsMsg(err, "not found") {
			return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
		}
		h.logger.Error().Err(err).Msg("admin: update app limit failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update app rate limit"})
	}
	h.auditAdmin(c, claims, audit.ActionAdminAppLimitUpdated, "app_rate_limit", appID)
	return c.JSON(http.StatusOK, limit)
}

// DeleteAppLimit handles DELETE /api/v1/admin/app-limits/:app_id.
//
// @Summary      Delete app rate limit
// @Description  Removes the custom rate limit for an app_id; it falls back to the default limit. Requires admin:access.
// @Tags         admin-rate-limits
// @Produce      json
// @Security     BearerAuth
// @Param        app_id  path      string  true  "App ID"
// @Success      200     {object}  map[string]string
// @Failure      404     {object}  map[string]string
// @Router       /api/v1/admin/app-limits/{app_id} [delete]
func (h *AdminHandler) DeleteAppLimit(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	appID := c.Param("app_id")
	if appID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "app_id path param required"})
	}

	if err := h.appLimitSvc.DeleteAppLimit(c.Request().Context(), tenantID, appID); err != nil {
		if containsMsg(err, "not found") {
			return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
		}
		h.logger.Error().Err(err).Msg("admin: delete app limit failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete app rate limit"})
	}
	h.auditAdmin(c, claims, audit.ActionAdminAppLimitDeleted, "app_rate_limit", appID)
	return c.JSON(http.StatusOK, map[string]string{"message": "app rate limit deleted"})
}

// ---------------------------------------------------------------------------
// Cross-tenant management — super_admin only (tenant:manage permission)
// All handlers below accept :tid as the target tenant UUID in the path.
// The caller's own tenant is irrelevant; authority is checked by middleware.
// ---------------------------------------------------------------------------

// targetTenantID parses :tid from the request path.
func targetTenantID(c echo.Context) (uuid.UUID, error) {
	return uuid.Parse(c.Param("tid"))
}

// --- Permissions under a tenant ---

// TenantListPermissions handles GET /api/v1/admin/tenants/:tid/permissions.
func (h *AdminHandler) TenantListPermissions(c echo.Context) error {
	tid, err := targetTenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	perms, err := h.svc.ListPermissions(c.Request().Context(), tid)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: tenant list permissions failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list permissions"})
	}
	return c.JSON(http.StatusOK, perms)
}

// TenantCreatePermission handles POST /api/v1/admin/tenants/:tid/permissions.
func (h *AdminHandler) TenantCreatePermission(c echo.Context) error {
	tid, err := targetTenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := c.Bind(&req); err != nil || req.Name == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "name is required"})
	}
	result, err := h.svc.CreatePermission(c.Request().Context(), tid, req.Name, req.Description)
	if err != nil {
		if errors.Is(err, admin.ErrAlreadyExists) {
			return c.JSON(http.StatusConflict, map[string]string{"error": "permission name already exists in this tenant"})
		}
		h.logger.Error().Err(err).Msg("admin: tenant create permission failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create permission"})
	}
	claims, _ := claimsFromCtx(c)
	h.auditAdmin(c, claims, audit.ActionAdminPermissionCreated, "permission", result.ID)
	return c.JSON(http.StatusCreated, result)
}

// TenantDeletePermission handles DELETE /api/v1/admin/tenants/:tid/permissions/:pid.
func (h *AdminHandler) TenantDeletePermission(c echo.Context) error {
	tid, err := targetTenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	pid, err := uuid.Parse(c.Param("pid"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid permission id"})
	}
	if err := h.svc.DeletePermission(c.Request().Context(), tid, pid); err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "permission not found"})
		}
		h.logger.Error().Err(err).Msg("admin: tenant delete permission failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete permission"})
	}
	claims, _ := claimsFromCtx(c)
	h.auditAdmin(c, claims, audit.ActionAdminPermissionDeleted, "permission", pid.String())
	return c.JSON(http.StatusOK, map[string]string{"message": "permission deleted"})
}

// --- Roles under a tenant ---

// TenantListRoles handles GET /api/v1/admin/tenants/:tid/roles.
func (h *AdminHandler) TenantListRoles(c echo.Context) error {
	tid, err := targetTenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	roles, err := h.svc.ListRoles(c.Request().Context(), tid)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: tenant list roles failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list roles"})
	}
	return c.JSON(http.StatusOK, roles)
}

// TenantCreateRole handles POST /api/v1/admin/tenants/:tid/roles.
func (h *AdminHandler) TenantCreateRole(c echo.Context) error {
	tid, err := targetTenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	var req CreateRoleRequest
	if err := c.Bind(&req); err != nil || req.Name == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "name is required"})
	}
	permUUIDs, err := parseUUIDs(req.PermissionIDs)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid permission_id: " + err.Error()})
	}
	result, err := h.svc.CreateRole(c.Request().Context(), tid, req.Name, permUUIDs)
	if err != nil {
		if errors.Is(err, admin.ErrAlreadyExists) {
			return c.JSON(http.StatusConflict, map[string]string{"error": "role name already exists in this tenant"})
		}
		h.logger.Error().Err(err).Msg("admin: tenant create role failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create role"})
	}
	claims, _ := claimsFromCtx(c)
	h.auditAdmin(c, claims, audit.ActionAdminRoleCreated, "role", result.ID)
	return c.JSON(http.StatusCreated, result)
}

// TenantUpdateRolePermissions handles PUT /api/v1/admin/tenants/:tid/roles/:rid/permissions.
func (h *AdminHandler) TenantUpdateRolePermissions(c echo.Context) error {
	tid, err := targetTenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	rid, err := uuid.Parse(c.Param("rid"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role id"})
	}
	var req UpdateRolePermissionsRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	permUUIDs, err := parseUUIDs(req.PermissionIDs)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid permission_id: " + err.Error()})
	}
	if err := h.svc.UpdateRolePermissions(c.Request().Context(), tid, rid, permUUIDs); err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "role not found"})
		}
		h.logger.Error().Err(err).Msg("admin: tenant update role permissions failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update role permissions"})
	}
	claims, _ := claimsFromCtx(c)
	h.auditAdmin(c, claims, audit.ActionAdminRolePermissionsUpdated, "role", rid.String())
	return c.JSON(http.StatusOK, map[string]string{"message": "role permissions updated"})
}

// TenantDeleteRole handles DELETE /api/v1/admin/tenants/:tid/roles/:rid.
func (h *AdminHandler) TenantDeleteRole(c echo.Context) error {
	tid, err := targetTenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	rid, err := uuid.Parse(c.Param("rid"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role id"})
	}
	if err := h.svc.DeleteRole(c.Request().Context(), tid, rid); err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "role not found or is a system role"})
		}
		h.logger.Error().Err(err).Msg("admin: tenant delete role failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete role"})
	}
	claims, _ := claimsFromCtx(c)
	h.auditAdmin(c, claims, audit.ActionAdminRoleDeleted, "role", rid.String())
	return c.JSON(http.StatusOK, map[string]string{"message": "role deleted"})
}

// --- Users under a tenant ---

// TenantListUsers handles GET /api/v1/admin/tenants/:tid/users.
func (h *AdminHandler) TenantListUsers(c echo.Context) error {
	tid, err := targetTenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	page, _ := strconv.Atoi(c.QueryParam("page"))
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	search := c.QueryParam("search")
	users, err := h.svc.ListUsers(c.Request().Context(), tid, search, page, limit)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: tenant list users failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list users"})
	}
	return c.JSON(http.StatusOK, users)
}

// TenantCreateUser handles POST /api/v1/admin/tenants/:tid/users.
func (h *AdminHandler) TenantCreateUser(c echo.Context) error {
	tid, err := targetTenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	var req CreateUserAdminRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.Email == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "email is required"})
	}
	if len(req.Password) < 8 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
	}
	var roleID *uuid.UUID
	if req.RoleID != nil && *req.RoleID != "" {
		rid, err := uuid.Parse(*req.RoleID)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role_id"})
		}
		roleID = &rid
	}
	result, err := h.svc.CreateUser(c.Request().Context(), tid, req.Email, req.Password, req.FirstName, req.LastName, roleID)
	if err != nil {
		if errors.Is(err, admin.ErrAlreadyExists) {
			return c.JSON(http.StatusConflict, map[string]string{"error": "email already registered in this tenant"})
		}
		h.logger.Error().Err(err).Msg("admin: tenant create user failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create user"})
	}
	claims, _ := claimsFromCtx(c)
	h.auditAdmin(c, claims, audit.ActionAdminUserCreated, "user", result.ID)
	return c.JSON(http.StatusCreated, result)
}

// TenantDeleteUser handles DELETE /api/v1/admin/tenants/:tid/users/:uid.
func (h *AdminHandler) TenantDeleteUser(c echo.Context) error {
	tid, err := targetTenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	uid, err := uuid.Parse(c.Param("uid"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user id"})
	}
	if err := h.svc.DeleteUser(c.Request().Context(), tid, uid); err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
		}
		h.logger.Error().Err(err).Msg("admin: tenant delete user failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete user"})
	}
	claims, _ := claimsFromCtx(c)
	h.auditAdmin(c, claims, audit.ActionAdminUserDeleted, "user", uid.String())
	return c.JSON(http.StatusOK, map[string]string{"message": "user deleted"})
}
