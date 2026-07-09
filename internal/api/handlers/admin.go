package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"regexp"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// AdminHandler holds handlers for all Admin API endpoints.
type AdminHandler struct {
	svc         *admin.Service
	appLimitSvc *auth.AppRateLimitService
	appSvc      *auth.ApplicationService
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

// WithApplications attaches the ApplicationService for application CRUD handlers.
func (h *AdminHandler) WithApplications(svc *auth.ApplicationService) *AdminHandler {
	h.appSvc = svc
	return h
}

// claimsFromCtx extracts *auth.Claims injected by JWTRequired middleware.
func claimsFromCtx(c echo.Context) (*auth.Claims, bool) {
	claims, ok := c.Get("user").(*auth.Claims)
	return claims, ok && claims != nil
}

// tenantIDFromClaims parses the tenant ID from JWT claims.
func tenantIDFromClaims(claims *auth.Claims) (int64, error) {
	return strconv.ParseInt(claims.TenantID, 10, 64)
}

// hasPermission reports whether claims carries the given permission string.
func hasPermission(claims *auth.Claims, permission string) bool {
	if claims == nil {
		return false
	}
	for _, p := range claims.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Tenant management (requires "tenant:manage" permission)
// ---------------------------------------------------------------------------

// validPlans is the allowed set of plan values.
var validPlans = map[string]bool{"free": true, "pro": true, "enterprise": true}

// slugPattern restricts tenant slugs to lowercase alphanumeric segments
// separated by single hyphens, since the slug is used verbatim in
// X-Tenant-Slug lookups.
var slugPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// CreateTenantRequest is the body for POST /api/v1/admin/tenants.
type CreateTenantRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Domain      string `json:"domain"`
	Region      string `json:"region"`
	Description string `json:"description"`
	Plan        string `json:"plan"`
	OwnerEmail  string `json:"owner_email"`
}

// UpdateTenantRequest is the body for PUT /api/v1/admin/tenants/:id.
type UpdateTenantRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Domain      string `json:"domain"`
	Region      string `json:"region"`
	Description string `json:"description"`
	Plan        string `json:"plan"`
}

// SlugCheckResponse is returned by GET /api/v1/admin/tenants/check-slug.
type SlugCheckResponse struct {
	Slug      string `json:"slug"`
	Available bool   `json:"available"`
}

// CreateTenant handles POST /api/v1/tenants.
//
// @Summary      Create tenant
// @Description  Creates a new isolated tenant and auto-seeds an owner role with 8 default permissions and an owner user using the provided owner_email. The owner.temp_password in the response is shown once and never stored — hand it to the tenant owner. Requires tenant:manage permission (super_admin only).
// @Tags         admin-tenants
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      CreateTenantRequest      true  "Tenant details"
// @Success      201   {object}  admin.CreateTenantResult
// @Failure      400   {object}  map[string]string
// @Failure      403   {object}  map[string]string
// @Failure      409   {object}  map[string]string  "Slug already taken"
// @Router       /api/v1/tenants [post]
func (h *AdminHandler) CreateTenant(c echo.Context) error {
	var req CreateTenantRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.Name == "" || req.Slug == "" || req.OwnerEmail == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "name, slug, and owner_email are required"})
	}
	if !slugPattern.MatchString(req.Slug) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "slug must be lowercase alphanumeric with single hyphens (e.g. acme-corp)"})
	}
	if _, err := mail.ParseAddress(req.OwnerEmail); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "owner_email must be a valid email address"})
	}
	if req.Plan != "" && !validPlans[req.Plan] {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "plan must be one of: free, pro, enterprise"})
	}

	claims, _ := claimsFromCtx(c)
	result, err := h.svc.CreateTenant(c.Request().Context(), admin.CreateTenantInput{
		Name:        req.Name,
		Slug:        req.Slug,
		DisplayName: req.DisplayName,
		Domain:      req.Domain,
		Region:      req.Region,
		Description: req.Description,
		Plan:        req.Plan,
		OwnerEmail:  req.OwnerEmail,
	})
	if err != nil {
		if errors.Is(err, admin.ErrAlreadyExists) {
			return c.JSON(http.StatusConflict, map[string]string{"error": "slug already taken"})
		}
		h.logger.Error().Err(err).Msg("admin: create tenant failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create tenant"})
	}
	h.auditAdmin(c, claims, audit.ActionAdminTenantCreated, "tenant", result.Tenant.ID)
	return c.JSON(http.StatusCreated, result)
}

// ListTenants handles GET /api/v1/admin/tenants.
//
// @Summary      List tenants
// @Description  Returns tenants scoped to the caller's permissions: callers with tenant:manage get a paginated, filtered list of every tenant; any other authenticated caller gets only the tenants tied to their own account email, each with their role and usage stats (search/status/region/pagination params are ignored in that case).
// @Tags         admin-tenants
// @Produce      json
// @Security     BearerAuth
// @Param        search    query     string  false  "Search by name, display name, or domain"
// @Param        status    query     string  false  "Filter by status: active | inactive | suspended (suspended maps to inactive)"
// @Param        region    query     string  false  "Filter by region (exact match)"
// @Param        page      query     int     false  "Page number (default 1)"
// @Param        per_page  query     int     false  "Rows per page (default 25, max 100); alias: limit"
// @Success      200       {object}  admin.TenantsPage
// @Failure      403       {object}  map[string]string
// @Router       /api/v1/tenants [get]
func (h *AdminHandler) ListTenants(c echo.Context) error {
	claims, _ := claimsFromCtx(c)

	// Platform admins (tenant:manage) see every tenant. Anyone else authenticated
	// (e.g. a tenant owner, who only has tenant-scoped permissions) sees only the
	// tenants tied to their own email — never the full platform list.
	if !hasPermission(claims, "tenant:manage") {
		if claims == nil || claims.Email == "" {
			return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
		}
		owned, err := h.svc.ListOwnedTenants(c.Request().Context(), claims.Email)
		if err != nil {
			h.logger.Error().Err(err).Msg("list owned tenants failed")
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list tenants"})
		}
		return c.JSON(http.StatusOK, map[string]any{
			"data":        owned,
			"total":       len(owned),
			"page":        1,
			"total_pages": 1,
			"per_page":    len(owned),
		})
	}

	page, _ := strconv.Atoi(c.QueryParam("page"))

	perPage, _ := strconv.Atoi(c.QueryParam("per_page"))
	if perPage == 0 {
		perPage, _ = strconv.Atoi(c.QueryParam("limit"))
	}

	status := c.QueryParam("status")
	if status == "suspended" {
		status = "inactive"
	}

	filter := admin.TenantFilter{
		Search: c.QueryParam("search"),
		Status: status,
		Region: c.QueryParam("region"),
		Page:   page,
		Limit:  perPage,
	}

	result, err := h.svc.ListTenantsPaginated(c.Request().Context(), filter)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: list tenants failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list tenants"})
	}
	return c.JSON(http.StatusOK, result)
}

// GetTenant handles GET /api/v1/admin/tenants/:id.
//
// @Summary      Get tenant
// @Description  Returns a single tenant by ID. Requires tenant:manage permission.
// @Tags         admin-tenants
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Tenant ID"
// @Success      200  {object}  admin.TenantResult
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/tenants/{id} [get]
func (h *AdminHandler) GetTenant(c echo.Context) error {
	tenantID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	result, err := h.svc.GetTenantByID(c.Request().Context(), tenantID)
	if err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "tenant not found"})
		}
		h.logger.Error().Err(err).Msg("admin: get tenant failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get tenant"})
	}
	return c.JSON(http.StatusOK, result)
}

// UpdateTenant handles PUT /api/v1/admin/tenants/:id.
//
// @Summary      Update tenant
// @Description  Updates editable fields on a tenant. Requires tenant:manage permission.
// @Tags         admin-tenants
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      string              true  "Tenant ID"
// @Param        body  body      UpdateTenantRequest true  "Updated fields"
// @Success      200   {object}  admin.TenantResult
// @Failure      400   {object}  map[string]string
// @Failure      404   {object}  map[string]string
// @Router       /api/v1/tenants/{id} [put]
func (h *AdminHandler) UpdateTenant(c echo.Context) error {
	tenantID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	var req UpdateTenantRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.Name == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "name is required"})
	}
	if req.Plan != "" && !validPlans[req.Plan] {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "plan must be one of: free, pro, enterprise"})
	}

	result, err := h.svc.UpdateTenant(c.Request().Context(), tenantID, admin.UpdateTenantInput{
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Domain:      req.Domain,
		Region:      req.Region,
		Description: req.Description,
		Plan:        req.Plan,
	})
	if err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "tenant not found"})
		}
		h.logger.Error().Err(err).Msg("admin: update tenant failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update tenant"})
	}
	claims, _ := claimsFromCtx(c)
	h.auditAdmin(c, claims, audit.ActionAdminTenantUpdated, "tenant", strconv.FormatInt(tenantID, 10))
	return c.JSON(http.StatusOK, result)
}

// ActivateTenant handles PUT /api/v1/admin/tenants/:id/activate.
//
// @Summary      Activate tenant
// @Description  Sets is_active=true for a previously deactivated tenant. Requires tenant:manage permission.
// @Tags         admin-tenants
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Tenant ID"
// @Success      200  {object}  admin.TenantResult
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      409  {object}  map[string]string  "Tenant already active"
// @Router       /api/v1/tenants/{id}/activate [put]
func (h *AdminHandler) ActivateTenant(c echo.Context) error {
	tenantID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	result, err := h.svc.ActivateTenant(c.Request().Context(), tenantID)
	if err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "tenant not found"})
		}
		if errors.Is(err, admin.ErrAlreadyActive) {
			return c.JSON(http.StatusConflict, map[string]string{"error": "tenant already active"})
		}
		h.logger.Error().Err(err).Msg("admin: activate tenant failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to activate tenant"})
	}
	claims, _ := claimsFromCtx(c)
	h.auditAdmin(c, claims, audit.ActionAdminTenantUpdated, "tenant", strconv.FormatInt(tenantID, 10))
	return c.JSON(http.StatusOK, result)
}

// CheckSlug handles GET /api/v1/admin/tenants/check-slug.
//
// @Summary      Check slug availability
// @Description  Returns whether a tenant slug is available. Always responds 200. Requires tenant:manage permission.
// @Tags         admin-tenants
// @Produce      json
// @Security     BearerAuth
// @Param        slug  query     string  true  "Slug to check"
// @Success      200   {object}  SlugCheckResponse
// @Failure      400   {object}  map[string]string
// @Router       /api/v1/tenants/check-slug [get]
func (h *AdminHandler) CheckSlug(c echo.Context) error {
	slug := c.QueryParam("slug")
	if slug == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "slug is required"})
	}
	available, err := h.svc.CheckSlugAvailable(c.Request().Context(), slug)
	if err != nil {
		h.logger.Error().Err(err).Str("slug", slug).Msg("admin: check slug failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to check slug"})
	}
	return c.JSON(http.StatusOK, SlugCheckResponse{Slug: slug, Available: available})
}

// GetTenantDashboardStats handles GET /api/v1/admin/stats/tenants.
//
// @Summary      Tenant dashboard stats
// @Description  Returns stats scoped to the caller's permissions: callers with tenant:manage get system-wide tenant/application/user counts with month-over-month deltas; any other authenticated caller gets counts aggregated only across the tenants tied to their own account email (no deltas).
// @Tags         admin-tenants
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  admin.TenantDashboardStats
// @Failure      403  {object}  map[string]string
// @Router       /api/v1/tenants/stats [get]
func (h *AdminHandler) GetTenantDashboardStats(c echo.Context) error {
	claims, _ := claimsFromCtx(c)

	// Same split as ListTenants: platform admins get system-wide stats;
	// everyone else gets stats aggregated only across their own owned tenants.
	if !hasPermission(claims, "tenant:manage") {
		if claims == nil || claims.Email == "" {
			return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
		}
		owned, err := h.svc.ListOwnedTenants(c.Request().Context(), claims.Email)
		if err != nil {
			h.logger.Error().Err(err).Msg("owned tenant stats failed")
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to retrieve dashboard stats"})
		}
		stats := admin.TenantDashboardStats{TotalTenants: len(owned)}
		for _, t := range owned {
			if t.IsActive {
				stats.ActiveTenants++
			}
			stats.TotalApplications += t.Stats.AppCount
			stats.TotalUsers += t.Stats.UserCount
		}
		return c.JSON(http.StatusOK, stats)
	}

	result, err := h.svc.GetTenantDashboardStats(c.Request().Context())
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: tenant dashboard stats failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to retrieve dashboard stats"})
	}
	return c.JSON(http.StatusOK, result)
}

// DeactivateTenant handles DELETE /api/v1/admin/tenants/:id.
//
// @Summary      Deactivate tenant
// @Description  Soft-deactivates a tenant (sets is_active=false). Requires tenant:manage permission.
// @Tags         admin-tenants
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Tenant ID"
// @Success      204  "No Content"
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/tenants/{id} [delete]
func (h *AdminHandler) DeactivateTenant(c echo.Context) error {
	tenantID, err := strconv.ParseInt(c.Param("id"), 10, 64)
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
	h.auditAdmin(c, claims, audit.ActionAdminTenantDeactivated, "tenant", strconv.FormatInt(tenantID, 10))
	return c.NoContent(http.StatusNoContent)
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
// @Router       /api/v1/permissions [post]
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
// @Router       /api/v1/permissions [get]
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
// @Param        id   path      string  true  "Permission ID"
// @Success      200  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/permissions/{id} [delete]
func (h *AdminHandler) DeletePermission(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	permID, err := strconv.ParseInt(c.Param("id"), 10, 64)
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
	h.auditAdmin(c, claims, audit.ActionAdminPermissionDeleted, "permission", strconv.FormatInt(permID, 10))
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
// @Router       /api/v1/roles [post]
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

	permIDs, err := parseInt64s(req.PermissionIDs)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid permission_id: " + err.Error()})
	}

	result, err := h.svc.CreateRole(c.Request().Context(), tenantID, req.Name, permIDs)
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
// @Router       /api/v1/roles [get]
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
// @Param        id    path      string                       true  "Role ID"
// @Param        body  body      UpdateRolePermissionsRequest true  "Permission IDs to assign"
// @Success      200   {object}  map[string]string
// @Failure      404   {object}  map[string]string
// @Router       /api/v1/roles/{id}/permissions [put]
func (h *AdminHandler) UpdateRolePermissions(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	roleID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role id"})
	}

	var req UpdateRolePermissionsRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	permIDs, err := parseInt64s(req.PermissionIDs)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid permission_id: " + err.Error()})
	}

	if err := h.svc.UpdateRolePermissions(c.Request().Context(), tenantID, roleID, permIDs); err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "role not found"})
		}
		h.logger.Error().Err(err).Msg("admin: update role permissions failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update role permissions"})
	}
	h.auditAdmin(c, claims, audit.ActionAdminRolePermissionsUpdated, "role", strconv.FormatInt(roleID, 10))
	return c.JSON(http.StatusOK, map[string]string{"message": "role permissions updated"})
}

// DeleteRole handles DELETE /api/v1/admin/roles/:id.
//
// @Summary      Delete role
// @Description  Deletes a non-system role from the tenant. Users assigned this role will have their role cleared. Requires admin:access.
// @Tags         admin-rbac
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Role ID"
// @Success      200  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/roles/{id} [delete]
func (h *AdminHandler) DeleteRole(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	roleID, err := strconv.ParseInt(c.Param("id"), 10, 64)
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
	h.auditAdmin(c, claims, audit.ActionAdminRoleDeleted, "role", strconv.FormatInt(roleID, 10))
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
// @Router       /api/v1/users [get]
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
// @Router       /api/v1/users [post]
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

	var roleID *int64
	if req.RoleID != nil && *req.RoleID != "" {
		rid, err := strconv.ParseInt(*req.RoleID, 10, 64)
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
// @Param        id   path      string  true  "User ID"
// @Success      200  {object}  admin.UserResult
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/users/{id} [get]
func (h *AdminHandler) GetAdminUser(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	userID, err := strconv.ParseInt(c.Param("id"), 10, 64)
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
// @Param        id    path      string                 true  "User ID"
// @Param        body  body      UpdateUserAdminRequest true  "Updated fields"
// @Success      200   {object}  admin.UserResult
// @Failure      400   {object}  map[string]string
// @Failure      404   {object}  map[string]string
// @Router       /api/v1/users/{id} [put]
func (h *AdminHandler) UpdateAdminUser(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	userID, err := strconv.ParseInt(c.Param("id"), 10, 64)
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
	h.auditAdmin(c, claims, audit.ActionAdminUserUpdated, "user", strconv.FormatInt(userID, 10))
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
// @Param        id    path      string            true  "User ID"
// @Param        body  body      AssignRoleRequest true  "Role ID to assign"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  map[string]string
// @Failure      404   {object}  map[string]string
// @Router       /api/v1/users/{id}/role [put]
func (h *AdminHandler) AssignUserRole(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	userID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user id"})
	}

	var req AssignRoleRequest
	if err := c.Bind(&req); err != nil || req.RoleID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "role_id is required"})
	}
	roleID, err := strconv.ParseInt(req.RoleID, 10, 64)
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
	h.auditAdmin(c, claims, audit.ActionAdminUserRoleAssigned, "user", strconv.FormatInt(userID, 10))
	return c.JSON(http.StatusOK, map[string]string{"message": "role assigned"})
}

// DeleteAdminUser handles DELETE /api/v1/admin/users/:id.
//
// @Summary      Delete user
// @Description  Soft-deletes a user (is_deleted=true, is_active=false). ID preserved for audit. Requires admin:access.
// @Tags         admin-users
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "User ID"
// @Success      200  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/users/{id} [delete]
func (h *AdminHandler) DeleteAdminUser(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	userID, err := strconv.ParseInt(c.Param("id"), 10, 64)
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
	h.auditAdmin(c, claims, audit.ActionAdminUserDeleted, "user", strconv.FormatInt(userID, 10))
	return c.JSON(http.StatusOK, map[string]string{"message": "user deleted"})
}

// ForcePasswordReset handles POST /api/v1/admin/users/:id/force-password-reset.
//
// @Summary      Force password reset
// @Description  Sends a password reset email to the specified user. Requires admin:access.
// @Tags         admin-users
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "User ID"
// @Success      200  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/users/{id}/force-password-reset [post]
func (h *AdminHandler) ForcePasswordReset(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant in token"})
	}

	userID, err := strconv.ParseInt(c.Param("id"), 10, 64)
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
	h.auditAdmin(c, claims, audit.ActionAdminForcePasswordReset, "user", strconv.FormatInt(userID, 10))
	return c.JSON(http.StatusOK, map[string]string{"message": "password reset email dispatched"})
}

// ---------------------------------------------------------------------------
// Monitoring stats endpoints
// ---------------------------------------------------------------------------

// GetStats handles GET /api/v1/admin/stats.
//
// @Summary      Tenant activity stats
// @Description  Returns audit-log-based activity counts scoped to the caller's tenant. Requires admin:access.
// @Tags         admin-audit
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  audit.StatsResult
// @Failure      401  {object}  map[string]string
// @Router       /api/v1/stats [get]
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

// GetSystemStats handles GET /api/v1/admin/stats/system.
//
// @Summary      System-wide activity stats
// @Description  Returns audit-log-based activity counts across all tenants. Requires tenant:manage permission.
// @Tags         admin-audit
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  audit.StatsResult
// @Failure      403  {object}  map[string]string
// @Router       /api/v1/stats/system [get]
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
// @Param        user_id  query     string  false  "Filter by user ID"
// @Param        from     query     string  false  "From datetime (RFC3339, e.g. 2026-01-01T00:00:00Z)"
// @Param        to       query     string  false  "To datetime (RFC3339)"
// @Param        page     query     int     false  "Page (default 1)"
// @Param        limit    query     int     false  "Page size (default 50, max 200)"
// @Success      200      {object}  audit.LogsPage
// @Router       /api/v1/audit-logs [get]
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
// @Param        user_id  query     string  false  "Filter by user ID"
// @Param        from     query     string  false  "From datetime (RFC3339)"
// @Param        to       query     string  false  "To datetime (RFC3339)"
// @Param        page     query     int     false  "Page (default 1)"
// @Param        limit    query     int     false  "Page size (default 50, max 200)"
// @Success      200      {object}  audit.LogsPage
// @Router       /api/v1/audit-logs/system [get]
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
	tid, _ := strconv.ParseInt(claims.TenantID, 10, 64)
	// Service tokens carry the public client_id in the UserID claim, which is
	// not a users.id — record no user rather than a garbage zero.
	var uidPtr *int64
	if uid, err := strconv.ParseInt(claims.UserID, 10, 64); err == nil {
		uidPtr = &uid
	}
	h.audit.Log(c.Request().Context(), audit.Event{
		TenantID:     &tid,
		UserID:       uidPtr,
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

// parseInt64s parses a slice of numeric ID strings into int64 values.
func parseInt64s(strs []string) ([]int64, error) {
	result := make([]int64, 0, len(strs))
	for _, s := range strs {
		id, err := strconv.ParseInt(s, 10, 64)
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
// @Param        id    path      string                  true  "Tenant ID"
// @Param        body  body      UpdateCORSOriginsRequest true  "Allowed origins"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  map[string]string
// @Failure      404   {object}  map[string]string
// @Router       /api/v1/tenants/{id}/cors-origins [put]
func (h *AdminHandler) UpdateTenantCORSOrigins(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := strconv.ParseInt(c.Param("id"), 10, 64)
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
	if h.corsSvc != nil && claims != nil {
		if slug := c.QueryParam("slug"); slug != "" {
			h.corsSvc.InvalidateCache(c.Request().Context(), slug)
		}
	}

	h.auditAdmin(c, claims, audit.ActionAdminCORSUpdated, "tenant", strconv.FormatInt(tenantID, 10))
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
// @Router       /api/v1/app-limits [post]
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
// @Router       /api/v1/app-limits [get]
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
// @Router       /api/v1/app-limits/{app_id} [put]
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
// @Router       /api/v1/app-limits/{app_id} [delete]
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
// All handlers below accept :tid as the target tenant ID in the path.
// ---------------------------------------------------------------------------

// targetTenantID parses :tid from the request path.
func targetTenantID(c echo.Context) (int64, error) {
	return strconv.ParseInt(c.Param("tid"), 10, 64)
}

// --- Permissions under a tenant ---

// TenantListPermissions handles GET /api/v1/admin/tenants/:tid/permissions.
//
// @Summary      List permissions for a target tenant
// @Description  Returns all permissions belonging to the specified tenant. Requires tenant:manage permission.
// @Tags         admin-cross-tenant
// @Produce      json
// @Security     BearerAuth
// @Param        tid  path      string  true  "Target tenant ID"
// @Success      200  {array}   admin.PermissionResult
// @Failure      400  {object}  map[string]string
// @Router       /api/v1/tenants/{tid}/permissions [get]
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
//
// @Summary      Create permission in a target tenant
// @Description  Adds a new permission to the specified tenant. Requires tenant:manage permission.
// @Tags         admin-cross-tenant
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        tid   path      string                   true  "Target tenant ID"
// @Param        body  body      CreatePermissionRequest  true  "Permission details"
// @Success      201   {object}  admin.PermissionResult
// @Failure      400   {object}  map[string]string
// @Failure      409   {object}  map[string]string  "Permission name already exists"
// @Router       /api/v1/tenants/{tid}/permissions [post]
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
//
// @Summary      Delete permission from a target tenant
// @Description  Removes a permission from the specified tenant. Requires tenant:manage permission.
// @Tags         admin-cross-tenant
// @Produce      json
// @Security     BearerAuth
// @Param        tid  path      string  true  "Target tenant ID"
// @Param        pid  path      string  true  "Permission ID"
// @Success      200  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/tenants/{tid}/permissions/{pid} [delete]
func (h *AdminHandler) TenantDeletePermission(c echo.Context) error {
	tid, err := targetTenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	pid, err := strconv.ParseInt(c.Param("pid"), 10, 64)
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
	h.auditAdmin(c, claims, audit.ActionAdminPermissionDeleted, "permission", strconv.FormatInt(pid, 10))
	return c.JSON(http.StatusOK, map[string]string{"message": "permission deleted"})
}

// --- Roles under a tenant ---

// TenantListRoles handles GET /api/v1/admin/tenants/:tid/roles.
//
// @Summary      List roles for a target tenant
// @Description  Returns all roles (with permissions) belonging to the specified tenant. Requires tenant:manage permission.
// @Tags         admin-cross-tenant
// @Produce      json
// @Security     BearerAuth
// @Param        tid  path      string  true  "Target tenant ID"
// @Success      200  {array}   admin.RoleResult
// @Failure      400  {object}  map[string]string
// @Router       /api/v1/tenants/{tid}/roles [get]
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
//
// @Summary      Create role in a target tenant
// @Description  Creates a role and optionally assigns permissions to it. Requires tenant:manage permission.
// @Tags         admin-cross-tenant
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        tid   path      string             true  "Target tenant ID"
// @Param        body  body      CreateRoleRequest  true  "Role details"
// @Success      201   {object}  admin.RoleResult
// @Failure      400   {object}  map[string]string
// @Failure      409   {object}  map[string]string  "Role name already exists"
// @Router       /api/v1/tenants/{tid}/roles [post]
func (h *AdminHandler) TenantCreateRole(c echo.Context) error {
	tid, err := targetTenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	var req CreateRoleRequest
	if err := c.Bind(&req); err != nil || req.Name == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "name is required"})
	}
	permIDs, err := parseInt64s(req.PermissionIDs)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid permission_id: " + err.Error()})
	}
	result, err := h.svc.CreateRole(c.Request().Context(), tid, req.Name, permIDs)
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
//
// @Summary      Replace permissions on a target-tenant role
// @Description  Replaces the full permission set on a role in the target tenant. Requires tenant:manage.
// @Tags         admin-cross-tenant
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        tid   path      string                        true  "Target tenant ID"
// @Param        rid   path      string                        true  "Role ID"
// @Param        body  body      UpdateRolePermissionsRequest  true  "Permission IDs"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  map[string]string
// @Failure      404   {object}  map[string]string
// @Router       /api/v1/tenants/{tid}/roles/{rid}/permissions [put]
func (h *AdminHandler) TenantUpdateRolePermissions(c echo.Context) error {
	tid, err := targetTenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	rid, err := strconv.ParseInt(c.Param("rid"), 10, 64)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role id"})
	}
	var req UpdateRolePermissionsRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	permIDs, err := parseInt64s(req.PermissionIDs)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid permission_id: " + err.Error()})
	}
	if err := h.svc.UpdateRolePermissions(c.Request().Context(), tid, rid, permIDs); err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "role not found"})
		}
		h.logger.Error().Err(err).Msg("admin: tenant update role permissions failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update role permissions"})
	}
	claims, _ := claimsFromCtx(c)
	h.auditAdmin(c, claims, audit.ActionAdminRolePermissionsUpdated, "role", strconv.FormatInt(rid, 10))
	return c.JSON(http.StatusOK, map[string]string{"message": "role permissions updated"})
}

// TenantDeleteRole handles DELETE /api/v1/admin/tenants/:tid/roles/:rid.
//
// @Summary      Delete a role from a target tenant
// @Description  Permanently deletes a role from the target tenant. Requires tenant:manage.
// @Tags         admin-cross-tenant
// @Produce      json
// @Security     BearerAuth
// @Param        tid  path      string  true  "Target tenant ID"
// @Param        rid  path      string  true  "Role ID"
// @Success      200  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/tenants/{tid}/roles/{rid} [delete]
func (h *AdminHandler) TenantDeleteRole(c echo.Context) error {
	tid, err := targetTenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	rid, err := strconv.ParseInt(c.Param("rid"), 10, 64)
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
	h.auditAdmin(c, claims, audit.ActionAdminRoleDeleted, "role", strconv.FormatInt(rid, 10))
	return c.JSON(http.StatusOK, map[string]string{"message": "role deleted"})
}

// --- Users under a tenant ---

// TenantListUsers handles GET /api/v1/admin/tenants/:tid/users.
//
// @Summary      List users in a target tenant
// @Description  Returns paginated users for the specified tenant. Requires tenant:manage.
// @Tags         admin-cross-tenant
// @Produce      json
// @Security     BearerAuth
// @Param        tid     path      string  true   "Target tenant ID"
// @Param        page    query     int     false  "Page number (default 1)"
// @Param        limit   query     int     false  "Items per page (default 20)"
// @Param        search  query     string  false  "Search by email or name"
// @Success      200     {array}   admin.UserResult
// @Failure      400     {object}  map[string]string
// @Router       /api/v1/tenants/{tid}/users [get]
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
//
// @Summary      Create a user in a target tenant
// @Description  Creates a new user in the specified tenant. Requires tenant:manage.
// @Tags         admin-cross-tenant
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        tid   path      string                true  "Target tenant ID"
// @Param        body  body      CreateUserAdminRequest  true  "User details"
// @Success      201   {object}  admin.UserResult
// @Failure      400   {object}  map[string]string
// @Failure      409   {object}  map[string]string  "Email already registered"
// @Router       /api/v1/tenants/{tid}/users [post]
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
	var roleID *int64
	if req.RoleID != nil && *req.RoleID != "" {
		rid, err := strconv.ParseInt(*req.RoleID, 10, 64)
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
//
// @Summary      Soft-delete a user from a target tenant
// @Description  Marks the user as deleted (is_deleted=true). Requires tenant:manage.
// @Tags         admin-cross-tenant
// @Produce      json
// @Security     BearerAuth
// @Param        tid  path      string  true  "Target tenant ID"
// @Param        uid  path      string  true  "User ID"
// @Success      200  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/tenants/{tid}/users/{uid} [delete]
func (h *AdminHandler) TenantDeleteUser(c echo.Context) error {
	tid, err := targetTenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	uid, err := strconv.ParseInt(c.Param("uid"), 10, 64)
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
	h.auditAdmin(c, claims, audit.ActionAdminUserDeleted, "user", strconv.FormatInt(uid, 10))
	return c.JSON(http.StatusOK, map[string]string{"message": "user deleted"})
}

// ---------------------------------------------------------------------------
// Application management (requires admin:access)
// ---------------------------------------------------------------------------

// CreateApplicationRequest is the body for POST /api/v1/applications.
// Scopes become the permissions claim of the app's client_credentials tokens.
type CreateApplicationRequest struct {
	Name    string   `json:"name"`
	AppType string   `json:"app_type"` // web | spa | m2m | native; defaults to web
	Scopes  []string `json:"scopes"`   // resource:action strings; optional
}

// UpdateApplicationRequest is the body for PUT /api/v1/applications/:id.
// Empty fields are left unchanged. Scopes omitted = unchanged; scopes: [] clears.
type UpdateApplicationRequest struct {
	Name    string   `json:"name"`
	AppType string   `json:"app_type"`
	Scopes  []string `json:"scopes"`
}

// tenantFromClaimsOrPath resolves the target tenant for application handlers.
// Cross-tenant routes carry :tid in the path (guarded by tenant:manage);
// tenant-scoped routes derive the tenant from the caller's JWT.
func (h *AdminHandler) tenantFromClaimsOrPath(c echo.Context) (int64, *auth.Claims, error) {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return 0, nil, fmt.Errorf("forbidden")
	}
	if c.Param("tid") != "" {
		tid, err := targetTenantID(c)
		if err != nil {
			return 0, claims, fmt.Errorf("invalid tenant id")
		}
		return tid, claims, nil
	}
	tenantID, err := tenantIDFromClaims(claims)
	if err != nil {
		return 0, claims, fmt.Errorf("forbidden")
	}
	return tenantID, claims, nil
}

// appFilterFromQuery parses list query params shared by both list routes.
func appFilterFromQuery(c echo.Context) auth.AppFilter {
	page, _ := strconv.Atoi(c.QueryParam("page"))
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	return auth.AppFilter{
		Search: c.QueryParam("search"),
		Type:   c.QueryParam("type"),
		Status: c.QueryParam("status"),
		Page:   page,
		Limit:  limit,
	}
}

// CreateApplication handles POST /api/v1/applications and
// POST /api/v1/tenants/:tid/applications.
//
// @Summary      Create application
// @Description  Registers a new application for the tenant. Returns client_id and client_secret — secret is shown exactly once and can never be retrieved again (only rotated).
// @Tags         admin-applications
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      CreateApplicationRequest  true  "Application name and optional type (web|spa|m2m|native)"
// @Success      201   {object}  auth.AppResult
// @Failure      400   {object}  map[string]string
// @Failure      403   {object}  map[string]string
// @Router       /api/v1/applications [post]
func (h *AdminHandler) CreateApplication(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}

	var req CreateApplicationRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.Name == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "name is required"})
	}

	result, err := h.appSvc.CreateApplication(c.Request().Context(), tenantID, req.Name, req.AppType, req.Scopes)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidAppType) || errors.Is(err, auth.ErrInvalidScope) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		if containsMsg(err, "duplicate") || containsMsg(err, "unique") {
			return c.JSON(http.StatusConflict, map[string]string{"error": "an application with this name already exists"})
		}
		h.logger.Error().Err(err).Msg("admin: create application failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create application"})
	}

	h.auditAdmin(c, claims, audit.ActionAdminApplicationCreated, "application", result.ID)
	return c.JSON(http.StatusCreated, result)
}

// ListApplications handles GET /api/v1/applications and
// GET /api/v1/tenants/:tid/applications.
//
// @Summary      List applications (paginated)
// @Description  Returns a paginated, filtered list of the tenant's applications. Secrets are never included.
// @Tags         admin-applications
// @Produce      json
// @Security     BearerAuth
// @Param        search  query     string  false  "Match on name or client_id"
// @Param        type    query     string  false  "Filter by app type (web|spa|m2m|native)"
// @Param        status  query     string  false  "Filter by status (active|inactive); empty = all"
// @Param        page    query     int     false  "Page (default 1)"
// @Param        limit   query     int     false  "Page size (default 25, max 100)"
// @Success      200     {object}  auth.AppsPage
// @Failure      400     {object}  map[string]string
// @Failure      403     {object}  map[string]string
// @Router       /api/v1/applications [get]
func (h *AdminHandler) ListApplications(c echo.Context) error {
	tenantID, _, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}

	page, err := h.appSvc.ListApplicationsPaginated(c.Request().Context(), tenantID, appFilterFromQuery(c))
	if err != nil {
		if errors.Is(err, auth.ErrInvalidAppType) || containsMsg(err, "invalid status") {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		h.logger.Error().Err(err).Msg("admin: list applications failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list applications"})
	}
	return c.JSON(http.StatusOK, page)
}

// GetApplication handles GET /api/v1/applications/:id and
// GET /api/v1/tenants/:tid/applications/:id.
//
// @Summary      Get application
// @Description  Returns one application (active or inactive) by ID. The secret is never included.
// @Tags         admin-applications
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      int  true  "Application ID"
// @Success      200  {object}  auth.AppDetail
// @Failure      400  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/applications/{id} [get]
func (h *AdminHandler) GetApplication(c echo.Context) error {
	tenantID, _, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	appID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid application id"})
	}

	app, err := h.appSvc.GetApplication(c.Request().Context(), tenantID, appID)
	if err != nil {
		if errors.Is(err, auth.ErrAppNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "application not found"})
		}
		h.logger.Error().Err(err).Msg("admin: get application failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get application"})
	}
	return c.JSON(http.StatusOK, app)
}

// UpdateApplication handles PUT /api/v1/applications/:id and
// PUT /api/v1/tenants/:tid/applications/:id.
//
// @Summary      Update application
// @Description  Updates an active application's name and/or type. Empty fields are left unchanged.
// @Tags         admin-applications
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      int                       true  "Application ID"
// @Param        body  body      UpdateApplicationRequest  true  "Fields to update"
// @Success      200   {object}  auth.AppDetail
// @Failure      400   {object}  map[string]string
// @Failure      403   {object}  map[string]string
// @Failure      404   {object}  map[string]string
// @Router       /api/v1/applications/{id} [put]
func (h *AdminHandler) UpdateApplication(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	appID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid application id"})
	}

	var req UpdateApplicationRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	app, err := h.appSvc.UpdateApplication(c.Request().Context(), tenantID, appID, req.Name, req.AppType, req.Scopes)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrAppNotFound):
			return c.JSON(http.StatusNotFound, map[string]string{"error": "application not found"})
		case errors.Is(err, auth.ErrInvalidAppType), errors.Is(err, auth.ErrInvalidScope), containsMsg(err, "nothing to update"):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		case containsMsg(err, "duplicate"), containsMsg(err, "unique"):
			return c.JSON(http.StatusConflict, map[string]string{"error": "an application with this name already exists"})
		}
		h.logger.Error().Err(err).Msg("admin: update application failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update application"})
	}

	h.auditAdmin(c, claims, audit.ActionAdminApplicationUpdated, "application", app.ID)
	return c.JSON(http.StatusOK, app)
}

// RotateApplicationSecret handles POST /api/v1/applications/:id/rotate-secret and
// POST /api/v1/tenants/:tid/applications/:id/rotate-secret.
//
// @Summary      Rotate application client secret
// @Description  Generates a new client_secret for the application. The old secret stops working immediately. The new secret is returned exactly once — it is stored only as a hash and can never be revealed later.
// @Tags         admin-applications
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      int  true  "Application ID"
// @Success      200  {object}  auth.AppResult
// @Failure      400  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/applications/{id}/rotate-secret [post]
func (h *AdminHandler) RotateApplicationSecret(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	appID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid application id"})
	}

	result, err := h.appSvc.RotateSecret(c.Request().Context(), tenantID, appID)
	if err != nil {
		if errors.Is(err, auth.ErrAppNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "application not found"})
		}
		h.logger.Error().Err(err).Msg("admin: rotate application secret failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to rotate secret"})
	}

	h.auditAdmin(c, claims, audit.ActionAdminApplicationSecretRotated, "application", result.ID)
	return c.JSON(http.StatusOK, result)
}

// DeactivateApplication handles DELETE /api/v1/applications/:id and
// DELETE /api/v1/tenants/:tid/applications/:id.
//
// @Summary      Deactivate application
// @Description  Soft-deletes an application. Its client_id is immediately rejected on login, register, and the client_credentials grant.
// @Tags         admin-applications
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      int  true  "Application ID"
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/applications/{id} [delete]
func (h *AdminHandler) DeactivateApplication(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}

	appID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid application id"})
	}

	if err := h.appSvc.DeactivateApplication(c.Request().Context(), tenantID, appID); err != nil {
		if errors.Is(err, auth.ErrAppNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "application not found"})
		}
		h.logger.Error().Err(err).Msg("admin: deactivate application failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to deactivate application"})
	}

	h.auditAdmin(c, claims, audit.ActionAdminApplicationDeleted, "application", strconv.FormatInt(appID, 10))
	return c.JSON(http.StatusOK, map[string]string{"message": "application deactivated"})
}

// TenantGetStats handles GET /api/v1/tenants/:tid/stats.
//
// @Summary      Activity stats for a target tenant
// @Description  Returns audit-log-based activity counts for the specified tenant. Requires tenant:manage (super_admin only).
// @Tags         admin-cross-tenant
// @Produce      json
// @Security     BearerAuth
// @Param        tid  path      string  true  "Target tenant ID"
// @Success      200  {object}  audit.StatsResult
// @Failure      400  {object}  map[string]string
// @Router       /api/v1/tenants/{tid}/stats [get]
func (h *AdminHandler) TenantGetStats(c echo.Context) error {
	tid, err := targetTenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	result, err := h.audit.Stats(c.Request().Context(), &tid)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: tenant stats query failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to query stats"})
	}
	return c.JSON(http.StatusOK, result)
}

// TenantGetActivity handles GET /api/v1/tenants/:tid/activity.
//
// @Summary      Activity feed for a target tenant
// @Description  Returns paginated audit events for the specified tenant. Requires tenant:manage (super_admin only).
// @Tags         admin-cross-tenant
// @Produce      json
// @Security     BearerAuth
// @Param        tid      path      string  true   "Target tenant ID"
// @Param        action   query     string  false  "Filter by action (e.g. auth.login)"
// @Param        user_id  query     string  false  "Filter by user ID"
// @Param        from     query     string  false  "From datetime (RFC3339)"
// @Param        to       query     string  false  "To datetime (RFC3339)"
// @Param        page     query     int     false  "Page (default 1)"
// @Param        limit    query     int     false  "Page size (default 50, max 200)"
// @Success      200      {object}  audit.LogsPage
// @Failure      400      {object}  map[string]string
// @Router       /api/v1/tenants/{tid}/activity [get]
func (h *AdminHandler) TenantGetActivity(c echo.Context) error {
	tid, err := targetTenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
	}
	p := auditQueryParams(c)
	p.TenantID = &tid

	result, err := h.audit.Query(c.Request().Context(), p)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: tenant activity query failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to query activity"})
	}
	return c.JSON(http.StatusOK, result)
}
