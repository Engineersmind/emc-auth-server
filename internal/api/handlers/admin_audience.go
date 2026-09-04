package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// Admin API for per-application audience grants — issue #131 stage C.
//
// Every handler here is registered twice, at the flat path and at the
// tenant-scoped mirror, following the precedent set by the rate-limit and
// passkey-policy handlers. tenantFromClaimsOrPath gives that for free: a
// super_admin addresses /tenants/:tid/applications/:appID/grants and a tenant's
// own administrator addresses /applications/:appID/grants, and the handler is
// identical because the tenant it resolves to is authoritative either way.
//
// The tenant is NEVER read from a request body. It comes from the caller's JWT
// or from a :tid path segment guarded by tenant:manage, and it is what gets
// written into oauth_client_grants.tenant_id — which the composite foreign key
// from migration 00087 then uses to make a cross-tenant grant impossible at the
// database level as well as here.

// GrantRequest is the body for creating or updating an audience grant.
type GrantRequest struct {
	// Audience is required on create and ignored on update.
	//
	// A grant's audience is not editable by design: an operator who wants a
	// client to reach a different API creates that grant and deletes the old
	// one, leaving two explicit decisions in the audit trail rather than one
	// silent re-point of a grant a resource server may already be relying on.
	Audience string `json:"audience"`
	// Scopes narrows what a token for this audience may carry. An empty or
	// absent list means the grant permits no scopes — the fail-closed reading,
	// matching how oauth_clients.scopes already behaves at /oauth/authorize.
	// It is not "unrestricted": that would make a forgotten field the most
	// permissive possible configuration.
	Scopes []string `json:"scopes"`
}

// ListApplicationGrants handles GET /api/v1/applications/:appID/grants.
//
// @Summary      List an application's audience grants
// @Description  Returns the audiences this application is permitted to request tokens for. Requires apps:read.
// @Tags         admin-audiences
// @Produce      json
// @Security     BearerAuth
// @Param        appID  path      string  true   "Application ID"
// @Param        tid    path      string  false  "Tenant ID (super_admin cross-tenant mirror)"
// @Success      200    {array}   auth.ClientGrant
// @Failure      403    {object}  map[string]string
// @Failure      404    {object}  map[string]string  "Application not found"
// @Router       /api/v1/applications/{appID}/grants [get]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/grants [get]
func (h *AdminHandler) ListApplicationGrants(c echo.Context) error {
	tenantID, _, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	if h.audienceSvc == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "audience service not configured"})
	}
	appID, ok := h.applicationOwnedByTenant(c, tenantID)
	if !ok {
		return nil
	}

	grants, err := h.audienceSvc.ListGrants(c.Request().Context(), tenantID, appID)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: list audience grants failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list audience grants"})
	}
	return c.JSON(http.StatusOK, grants)
}

// CreateApplicationGrant handles POST /api/v1/applications/:appID/grants.
//
// @Summary      Grant an application access to an audience
// @Description  Permits this application to request tokens for an audience owned by another application in the same tenant. Requires apps:write.
// @Tags         admin-audiences
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        appID  path      string        true   "Application ID (the grantee)"
// @Param        tid    path      string        false  "Tenant ID (super_admin cross-tenant mirror)"
// @Param        body   body      GrantRequest  true   "Audience and scopes"
// @Success      201    {object}  auth.ClientGrant
// @Failure      400    {object}  map[string]string  "Malformed or reserved audience"
// @Failure      404    {object}  map[string]string  "Audience does not exist in this tenant"
// @Failure      409    {object}  map[string]string  "Grant already exists"
// @Router       /api/v1/applications/{appID}/grants [post]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/grants [post]
func (h *AdminHandler) CreateApplicationGrant(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	if h.audienceSvc == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "audience service not configured"})
	}
	appID, ok := h.applicationOwnedByTenant(c, tenantID)
	if !ok {
		return nil
	}

	var req GrantRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.Audience == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "audience is required"})
	}

	grant, err := h.audienceSvc.CreateGrant(c.Request().Context(), tenantID, appID, req.Audience, req.Scopes)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrReservedAudience):
			// Named explicitly, unlike at the token endpoint where every refusal
			// is byte-identical. The audience here is an authenticated
			// administrator configuring their own tenant, and telling them the
			// namespace is reserved is the difference between a five-second fix
			// and a support ticket. It leaks nothing: the reserved prefix is
			// documented and identical for every deployment.
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		case errors.Is(err, auth.ErrInvalidAudienceFormat), errors.Is(err, auth.ErrInvalidScope):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		case errors.Is(err, auth.ErrTooManyGrants):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		case errors.Is(err, auth.ErrInvalidTarget):
			// The composite foreign key refused it: the audience does not exist
			// in THIS tenant. 404 rather than 400 — the caller named a resource
			// that is not there, and for an administrator inside their own
			// tenant that is not an information leak, because they can list
			// every audience they could legitimately have named.
			return c.JSON(http.StatusNotFound, map[string]string{
				"error": "no application in this tenant owns that audience — a client cannot be granted an audience belonging to another tenant",
			})
		case containsMsg(err, "already has a grant"):
			return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
		}
		h.logger.Error().Err(err).Msg("admin: create audience grant failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create audience grant"})
	}

	h.auditAdminApp(c, claims, audit.ActionAdminAudienceGrantCreated, "oauth_client_grant", grant.ID, &appID)
	return c.JSON(http.StatusCreated, grant)
}

// UpdateApplicationGrant handles PUT /api/v1/applications/:appID/grants/:id.
//
// @Summary      Update an audience grant's scopes
// @Description  Replaces the scopes on an existing grant. The audience itself is immutable — delete and recreate to change it. Requires apps:write.
// @Tags         admin-audiences
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        appID  path      string        true   "Application ID"
// @Param        id     path      string        true   "Grant ID"
// @Param        tid    path      string        false  "Tenant ID (super_admin cross-tenant mirror)"
// @Param        body   body      GrantRequest  true   "Scopes"
// @Success      200    {object}  auth.ClientGrant
// @Failure      404    {object}  map[string]string
// @Router       /api/v1/applications/{appID}/grants/{id} [put]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/grants/{id} [put]
func (h *AdminHandler) UpdateApplicationGrant(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	if h.audienceSvc == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "audience service not configured"})
	}
	appID, ok := h.applicationOwnedByTenant(c, tenantID)
	if !ok {
		return nil
	}
	grantID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid grant id"})
	}

	var req GrantRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	// An audience in the body is refused rather than ignored. Ignoring it would
	// return 200 alongside a grant that still points where it always did, and
	// the caller would believe the re-point had happened.
	if req.Audience != "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "a grant's audience cannot be changed — delete this grant and create a new one",
		})
	}

	grant, err := h.audienceSvc.UpdateGrant(c.Request().Context(), tenantID, appID, grantID, req.Scopes)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrGrantNotFound):
			return c.JSON(http.StatusNotFound, map[string]string{"error": "grant not found"})
		case errors.Is(err, auth.ErrInvalidScope):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		h.logger.Error().Err(err).Msg("admin: update audience grant failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update audience grant"})
	}

	h.auditAdminApp(c, claims, audit.ActionAdminAudienceGrantUpdated, "oauth_client_grant", grant.ID, &appID)
	return c.JSON(http.StatusOK, grant)
}

// DeleteApplicationGrant handles DELETE /api/v1/applications/:appID/grants/:id.
//
// @Summary      Revoke an audience grant
// @Description  Removes the grant. Tokens already issued for that audience remain valid until they expire (15 minutes); the next mint and every refresh are refused. Requires apps:write.
// @Tags         admin-audiences
// @Produce      json
// @Security     BearerAuth
// @Param        appID  path      string  true   "Application ID"
// @Param        id     path      string  true   "Grant ID"
// @Param        tid    path      string  false  "Tenant ID (super_admin cross-tenant mirror)"
// @Success      200    {object}  map[string]string
// @Failure      404    {object}  map[string]string
// @Router       /api/v1/applications/{appID}/grants/{id} [delete]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/grants/{id} [delete]
func (h *AdminHandler) DeleteApplicationGrant(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	if h.audienceSvc == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "audience service not configured"})
	}
	appID, ok := h.applicationOwnedByTenant(c, tenantID)
	if !ok {
		return nil
	}
	grantID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid grant id"})
	}

	if err := h.audienceSvc.DeleteGrant(c.Request().Context(), tenantID, appID, grantID); err != nil {
		if errors.Is(err, auth.ErrGrantNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "grant not found"})
		}
		h.logger.Error().Err(err).Msg("admin: delete audience grant failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete audience grant"})
	}

	h.auditAdminApp(c, claims, audit.ActionAdminAudienceGrantDeleted, "oauth_client_grant",
		strconv.FormatInt(grantID, 10), &appID)
	return c.JSON(http.StatusOK, map[string]string{"message": "audience grant deleted"})
}

// ListAudiences handles GET /api/v1/audiences.
//
// This is the catalogue an administrator grants FROM: every audience registered
// within their tenant, with the application that owns each one.
//
// Tenant-scoped with no cross-tenant read, which is the point — a tenant has no
// business enumerating another tenant's API inventory, and this endpoint
// existing at all is why the token endpoint's invalid_target must stay
// byte-identical for every reason.
//
// @Summary      List the tenant's audiences
// @Description  Returns every audience registered in the tenant, with its owning application. This is the list to pick from when creating a grant. Requires apps:read.
// @Tags         admin-audiences
// @Produce      json
// @Security     BearerAuth
// @Param        tid  path      string  false  "Tenant ID (super_admin cross-tenant mirror)"
// @Success      200  {array}   auth.AudienceEntry
// @Failure      403  {object}  map[string]string
// @Router       /api/v1/audiences [get]
// @Router       /api/v1/tenants/{tid}/audiences [get]
func (h *AdminHandler) ListAudiences(c echo.Context) error {
	tenantID, _, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	if h.audienceSvc == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "audience service not configured"})
	}

	entries, err := h.audienceSvc.ListAudiences(c.Request().Context(), tenantID)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: list audiences failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list audiences"})
	}
	return c.JSON(http.StatusOK, entries)
}
