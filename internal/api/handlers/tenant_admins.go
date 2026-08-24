package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Tenant administration endpoints (issue #97).
//
// These manage who administers a tenant — owners (tenant-wide) and co-owners
// (specific applications). They are tenant-level routes, so RequireTenantSelfOrAny
// already refuses a co-owner: an administrator scoped to some applications has
// no say in who else administers the tenant.
// ---------------------------------------------------------------------------

// InviteTenantAdminRequest is the body for POST /api/v1/tenants/:tid/admins.
type InviteTenantAdminRequest struct {
	Email string `json:"email"`
	// Role is "owner" or "co_owner".
	Role string `json:"role"`
	// ApplicationIDs is required for a co-owner and must be absent for an
	// owner, whose reach is every application in the tenant.
	ApplicationIDs []string `json:"application_ids"`
}

// SetTenantAdminGrantsRequest is the body for
// PUT /api/v1/tenants/:tid/admins/:adminID/applications.
type SetTenantAdminGrantsRequest struct {
	ApplicationIDs []string `json:"application_ids"`
}

// ListTenantAdmins handles GET /api/v1/tenants/:tid/admins.
//
// @Summary      List tenant administrators
// @Description  Returns the tenant's owners and co-owners. An owner's applications array is empty because they administer every application in the tenant, present and future — read it together with role. status is "pending_invitation" until the invitation is accepted and the address verified.
// @Tags         admin-tenant-admins
// @Produce      json
// @Security     BearerAuth
// @Param        tid  path      int  true  "Tenant ID"
// @Success      200  {array}   admin.TenantAdminResult
// @Failure      403  {object}  map[string]string
// @Router       /api/v1/tenants/{tid}/admins [get]
func (h *AdminHandler) ListTenantAdmins(c echo.Context) error {
	tenantID, _, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	admins, err := h.svc.ListTenantAdmins(c.Request().Context(), tenantID)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: list tenant admins failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list administrators"})
	}
	return c.JSON(http.StatusOK, admins)
}

// InviteTenantAdmin handles POST /api/v1/tenants/:tid/admins.
//
// @Summary      Invite a tenant administrator
// @Description  Adds an owner (tenant-wide) or co-owner (specific applications). An address that is already a TENANT-LEVEL user is promoted in place and no second identity is created; an application-scoped user with the same address is unrelated and never collides, so being a customer of an application and an administrator of its tenant are compatible. The response's action field reports what happened: "invited" (new account, invitation sent), "grants_added" (existing user promoted or widened), or "invitation_resent". An invitation that would change nothing returns 409, as does a tenant already holding the maximum number of administrators. A repeat resend to the same address within a minute returns 429. Returns 503 when the server has no email delivery configured — nothing is recorded, because an administrator who cannot be told they are one could never sign in.
// @Tags         admin-tenant-admins
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        tid   path      int                       true  "Tenant ID"
// @Param        body  body      InviteTenantAdminRequest  true  "Administrator details"
// @Success      201   {object}  admin.InviteTenantAdminResult
// @Failure      400   {object}  map[string]string
// @Failure      403   {object}  map[string]string
// @Failure      409   {object}  map[string]string  "Already an administrator with these grants, or the administrator limit is reached"
// @Failure      429   {object}  map[string]string  "An invitation was sent to this address moments ago"
// @Failure      503   {object}  map[string]string  "Invitations are not configured; nothing was recorded"
// @Router       /api/v1/tenants/{tid}/admins [post]
func (h *AdminHandler) InviteTenantAdmin(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	var req InviteTenantAdminRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.Email == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "email is required"})
	}
	appIDs, err := parseIDs(req.ApplicationIDs)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "application_ids must be numeric"})
	}

	actor := grantActorFromClaims(claims)
	result, err := h.svc.InviteTenantAdmin(c.Request().Context(), admin.InviteTenantAdminInput{
		TenantID:       tenantID,
		Email:          req.Email,
		Role:           req.Role,
		ApplicationIDs: appIDs,
		InviterName:    claims.Email,
		Actor:          &actor,
	})
	if err != nil {
		return h.tenantAdminError(c, err, "invite tenant admin")
	}
	h.auditAdmin(c, claims, audit.ActionAdminTenantAdminInvited, "tenant_admin", result.Admin.ID)
	return c.JSON(http.StatusCreated, result)
}

// SetTenantAdminGrants handles PUT /api/v1/tenants/:tid/admins/:adminID/applications.
//
// @Summary      Replace a co-owner's application grants
// @Description  Sets exactly which applications a co-owner administers. An empty list is rejected — grants only ever narrow, so an administrator with none could reach nothing; use DELETE to revoke administration outright. Owners cannot be granted specific applications: they administer all of them. Every live access token for the affected account is invalidated so a revoked grant cannot outlive this call.
// @Tags         admin-tenant-admins
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        tid      path      int                          true  "Tenant ID"
// @Param        adminID  path      int                          true  "Administrator ID"
// @Param        body     body      SetTenantAdminGrantsRequest  true  "Application IDs"
// @Success      200      {object}  admin.TenantAdminResult
// @Failure      400      {object}  map[string]string
// @Failure      403      {object}  map[string]string
// @Failure      404      {object}  map[string]string
// @Router       /api/v1/tenants/{tid}/admins/{adminID}/applications [put]
func (h *AdminHandler) SetTenantAdminGrants(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	adminID, err := strconv.ParseInt(c.Param("adminID"), 10, 64)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid administrator id"})
	}
	var req SetTenantAdminGrantsRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	appIDs, err := parseIDs(req.ApplicationIDs)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "application_ids must be numeric"})
	}

	result, err := h.svc.SetTenantAdminGrants(c.Request().Context(), tenantID, adminID, appIDs)
	if err != nil {
		return h.tenantAdminError(c, err, "set tenant admin grants")
	}
	h.auditAdmin(c, claims, audit.ActionAdminTenantAdminGrantsSet, "tenant_admin", result.ID)
	return c.JSON(http.StatusOK, result)
}

// RemoveTenantAdmin handles DELETE /api/v1/tenants/:tid/admins/:adminID.
//
// @Summary      Remove a tenant administrator
// @Description  Withdraws administration and revokes the administrator's live sessions, so a removed administrator cannot keep rotating a refresh token into fresh access tokens that still carry their old reach. The user account itself survives — losing an administrative role must not take the person's identity or audit history with it. Removing the last owner who can actually log in returns 409: a tenant with no usable owner is administrable only by a platform admin. Removing a co-owner also returns 409 when they are the tenant's only administrator who can sign in, which happens when the owner never accepted their invitation. An administrator who has not yet accepted does not count as usable, and removing such a pending administrator is always allowed — they could not sign in, so their removal takes nothing away.
// @Tags         admin-tenant-admins
// @Produce      json
// @Security     BearerAuth
// @Param        tid      path      int  true  "Tenant ID"
// @Param        adminID  path      int  true  "Administrator ID"
// @Success      204
// @Failure      403      {object}  map[string]string
// @Failure      404      {object}  map[string]string
// @Failure      409      {object}  map[string]string  "Would leave the tenant without an administrator who can sign in"
// @Router       /api/v1/tenants/{tid}/admins/{adminID} [delete]
func (h *AdminHandler) RemoveTenantAdmin(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	adminID, err := strconv.ParseInt(c.Param("adminID"), 10, 64)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid administrator id"})
	}
	if err := h.svc.RemoveTenantAdminAs(c.Request().Context(), tenantID, adminID, grantActorFromClaims(claims)); err != nil {
		return h.tenantAdminError(c, err, "remove tenant admin")
	}
	h.auditAdmin(c, claims, audit.ActionAdminTenantAdminRemoved, "tenant_admin", c.Param("adminID"))
	return c.NoContent(http.StatusNoContent)
}

// ListPlatformAdministrators handles GET /api/v1/administrators.
//
// @Summary      Directory of every administrator across all tenants
// @Description  Lists owners and co-owners in EVERY tenant, for platform oversight — the per-tenant equivalent is /tenants/{tid}/admins. Rows carry the tenant, sign-in history and second-factor state because the reader has no other context. An owner's applications array is empty because they administer every application in their tenant; a co-owner's lists exactly theirs, so read it together with role. Requires tenant:manage (super_admin only).
// @Tags         admin-platform
// @Produce      json
// @Security     BearerAuth
// @Param        search  query     string  false  "Match on email, name, tenant name or slug"
// @Param        role    query     string  false  "owner | co_owner"
// @Param        status  query     string  false  "active | pending_invitation | blocked"
// @Param        page    query     int     false  "1-based page number"
// @Param        limit   query     int     false  "Rows per page (default 25, max 100)"
// @Success      200     {object}  admin.PlatformAdminsPage
// @Failure      400     {object}  map[string]string
// @Failure      403     {object}  map[string]string
// @Router       /api/v1/administrators [get]
func (h *AdminHandler) ListPlatformAdministrators(c echo.Context) error {
	page, _ := strconv.Atoi(c.QueryParam("page"))
	limit, _ := strconv.Atoi(c.QueryParam("limit"))

	result, err := h.svc.ListPlatformAdministrators(c.Request().Context(), admin.PlatformAdminFilter{
		Search: strings.TrimSpace(c.QueryParam("search")),
		Role:   c.QueryParam("role"),
		Status: c.QueryParam("status"),
		Page:   page,
		Limit:  limit,
	})
	if err != nil {
		// The only errors here are a bad role or status, which are the caller's.
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, result)
}

// PlatformAdminSummary handles GET /api/v1/administrators/stats.
//
// @Summary      Administrator directory summary
// @Description  Counts across every tenant: total administrators, owners, co-owners, unaccepted invitations, administrators without a second factor, and tenants with no owner who can sign in. The last two are the numbers worth acting on — privileged accounts protected by a password alone, and tenants nobody has taken ownership of. Requires tenant:manage.
// @Tags         admin-platform
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  admin.PlatformAdminStats
// @Failure      403  {object}  map[string]string
// @Router       /api/v1/administrators/stats [get]
func (h *AdminHandler) PlatformAdminSummary(c echo.Context) error {
	stats, err := h.svc.PlatformAdminSummary(c.Request().Context())
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: platform administrator summary failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to summarise administrators"})
	}
	return c.JSON(http.StatusOK, stats)
}

// tenantAdminError maps the service's sentinels onto status codes. Each carries
// its own message: "forbidden" tells an operator nothing about which rule they
// hit, and these rules are ones callers are expected to run into legitimately.
func (h *AdminHandler) tenantAdminError(c echo.Context, err error, op string) error {
	switch {
	// Privilege-escalation refusals (grant_escalation.go). 403 rather than 400:
	// the request was well-formed and the caller may write here in general — what
	// they may not do is write THIS. Audited by the handler so the attempt is
	// visible even though nothing changed.
	case errors.Is(err, admin.ErrOwnerCannotGrantOwnership):
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "only a platform administrator may grant tenant ownership",
			"code":  "owner_cannot_grant_ownership",
		})
	case errors.Is(err, admin.ErrOwnerCannotRemoveOwner):
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "only a platform administrator may remove a tenant owner",
			"code":  "owner_cannot_remove_owner",
		})
	case errors.Is(err, admin.ErrCannotModifyOwnGrant):
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "an administrator cannot modify their own grant",
			"code":  "cannot_modify_own_grant",
		})
	case errors.Is(err, admin.ErrForbiddenGrantWrite):
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "your administrative role does not permit this change",
			"code":  "forbidden_grant_write",
		})
	case errors.Is(err, admin.ErrNotFound):
		return c.JSON(http.StatusNotFound, map[string]string{"error": "administrator not found"})
	case errors.Is(err, admin.ErrLastOwner):
		return c.JSON(http.StatusConflict, map[string]string{
			"error": "this tenant would be left without an owner who can sign in; appoint another owner first",
			"code":  "last_owner",
		})
	case errors.Is(err, admin.ErrAlreadyAdmin):
		return c.JSON(http.StatusConflict, map[string]string{
			"error": "this address already administers the tenant with exactly these applications",
			"code":  "already_granted",
		})
	case errors.Is(err, admin.ErrInviteWouldDemote):
		// 409, not 400: the request is well formed, it conflicts with the reach the
		// account already holds. Owner covers every application, so co-owner of one
		// is a reduction — and an invitation must never quietly reduce anybody.
		//
		// The message stops at stating the conflict. It deliberately does NOT
		// suggest "change their role instead", because no such route exists:
		// SetTenantAdminGrants refuses owners (ErrGrantsForOwner) and there is no
		// PUT for admin_role. Reducing an owner today means removing them and
		// re-inviting as a co-owner, which is a different decision with its own
		// last-owner guard — so pointing at a phantom endpoint would be worse than
		// saying nothing.
		return c.JSON(http.StatusConflict, map[string]string{
			"error": "this account already owns the tenant, which includes every application; an owner cannot also be a co-owner",
			"code":  "invite_would_demote",
		})
	case errors.Is(err, admin.ErrGrantsRequired):
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "a co-owner must be granted at least one application",
			"code":  "grants_required",
		})
	case errors.Is(err, admin.ErrGrantsForOwner):
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "an owner administers every application in the tenant and cannot be granted specific ones",
			"code":  "grants_for_owner",
		})
	case errors.Is(err, admin.ErrUnknownApplication):
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "one or more application_ids do not belong to this tenant",
			"code":  "unknown_application",
		})
	case errors.Is(err, admin.ErrTooManyAdmins):
		return c.JSON(http.StatusConflict, map[string]string{
			"error": err.Error(),
			"code":  "admin_limit_reached",
		})
	case errors.Is(err, admin.ErrInviteCooldown):
		c.Response().Header().Set("Retry-After", "60")
		return c.JSON(http.StatusTooManyRequests, map[string]string{
			"error": "an invitation was sent to this address moments ago; wait a minute before resending",
			"code":  "invite_cooldown",
		})
	case errors.Is(err, admin.ErrInvitationsUnavailable):
		// 503, not 500: the request is valid and will succeed once the server is
		// configured to send mail.
		return c.JSON(http.StatusServiceUnavailable, map[string]string{
			"error": "this server cannot send invitations, so an administrator cannot be added; configure email delivery first",
			"code":  "invitations_unavailable",
		})
	case errors.Is(err, auth.ErrInvitationSuppressed):
		return c.JSON(http.StatusConflict, map[string]string{
			"error": "the invitation email template is disabled at this scope, so no invitation could be sent",
			"code":  "invitation_suppressed",
		})
	}
	h.logger.Error().Err(err).Msgf("admin: %s failed", op)
	return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
}

// parseIDs converts JSON string ids to int64. Ids cross the wire as strings
// throughout this API because JSON numbers lose precision above 2^53.
func parseIDs(in []string) ([]int64, error) {
	out := make([]int64, 0, len(in))
	for _, s := range in {
		id, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

// grantActorFromClaims builds the escalation-rule actor from a caller's claims.
//
// IsPlatformAdmin comes from tenant:manage, the permission the tenant guards
// short-circuit on — a platform administrator holds no tenant_admins or
// admin_grants row at all, so their authority cannot be discovered by looking for
// one (migration 00062).
//
// A UserID that fails to parse is left at 0, which matches no account. That fails
// closed: the rules then see a non-platform actor with no grant anywhere and
// refuse the write.
func grantActorFromClaims(claims *auth.Claims) admin.GrantActor {
	a := admin.GrantActor{}
	if claims == nil {
		return a
	}
	if uid, err := strconv.ParseInt(claims.UserID, 10, 64); err == nil {
		a.UserID = uid
	}
	for _, p := range claims.Permissions {
		if p == "tenant:manage" {
			a.IsPlatformAdmin = true
			break
		}
	}
	return a
}
