package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Organizations HTTP surface.
//
// The same management operations are served to two callers:
//
//   - an application's own BACKEND, authenticated with its client_id and
//     client_secret in the Authorization: Basic header — the pattern
//     /auth/apps/users/roles already uses. The scope is the authenticated
//     application, so a leaked secret is confined to it;
//   - the ADMIN CONSOLE, under /admin/tenants/:tid/applications/:appID, behind
//     the existing tenant and application guards.
//
// Each operation is written once and given a scope resolver per mount, so the
// two surfaces cannot drift apart. Every route answers 404 while
// ORGANIZATIONS_ENABLED is false, indistinguishable from a route that does not
// exist.
// ---------------------------------------------------------------------------

// OrganizationHandler serves organisation management and the end-user
// organisation flows (selection, switching, invitations).
type OrganizationHandler struct {
	orgs      *auth.OrganizationService
	authSvc   *auth.AuthService
	appSvc    *auth.ApplicationService
	jwtSvc    *auth.JWTService
	audit     *audit.Logger
	cookieCfg mw.CookieConfig
	logger    zerolog.Logger
}

// NewOrganizationHandler builds the handler.
func NewOrganizationHandler(orgs *auth.OrganizationService, authSvc *auth.AuthService, appSvc *auth.ApplicationService,
	jwtSvc *auth.JWTService, auditLog *audit.Logger, cookieCfg mw.CookieConfig, logger zerolog.Logger) *OrganizationHandler {
	return &OrganizationHandler{
		orgs: orgs, authSvc: authSvc, appSvc: appSvc, jwtSvc: jwtSvc,
		audit: auditLog, cookieCfg: cookieCfg, logger: logger,
	}
}

// orgActor is who performed a management call: an administrator (userID set)
// or an application backend (clientID set, no user).
type orgActor struct {
	userID   *int64
	email    string
	clientID string
}

// orgScopeFunc resolves the scope of a management call. ok false means the
// response has already been written.
type orgScopeFunc func(c echo.Context) (sc auth.OrganizationScope, actor orgActor, ok bool)

// AppScope authenticates an application backend from the Authorization: Basic
// header. Credential failures are answered generically so the endpoint cannot
// tell a registered client_id from an unregistered one.
func (h *OrganizationHandler) AppScope(c echo.Context) (auth.OrganizationScope, orgActor, bool) {
	if !h.orgs.Enabled() {
		_ = fail(c, http.StatusNotFound, "not_found")
		return auth.OrganizationScope{}, orgActor{}, false
	}
	clientID, clientSecret, errResp := appCredentialsFromRequest(c)
	if errResp != nil {
		_ = c.JSON(http.StatusBadRequest, errResp)
		return auth.OrganizationScope{}, orgActor{}, false
	}
	tenantID, appRowID, err := h.appSvc.AuthenticateClient(c.Request().Context(), clientID, clientSecret)
	if err != nil {
		h.logger.Warn().Str("client_id", clientID).Str("ip", c.RealIP()).
			Msg("organizations: invalid client credentials")
		_ = orgFail(c, http.StatusUnauthorized, "invalid_client", "Invalid client credentials.")
		return auth.OrganizationScope{}, orgActor{}, false
	}
	return auth.OrganizationScope{TenantID: tenantID, AppRowID: appRowID}, orgActor{clientID: clientID}, true
}

// AdminScope resolves the scope from /admin/tenants/:tid/applications/:appID.
// The route guards have already authorised the caller for the tenant and the
// application; this pins the application to the tenant.
func (h *OrganizationHandler) AdminScope(c echo.Context) (auth.OrganizationScope, orgActor, bool) {
	if !h.orgs.Enabled() {
		_ = fail(c, http.StatusNotFound, "not_found")
		return auth.OrganizationScope{}, orgActor{}, false
	}
	claims, ok := claimsFromCtx(c)
	if !ok {
		_ = orgFail(c, http.StatusForbidden, "forbidden", "You do not have access to this application.")
		return auth.OrganizationScope{}, orgActor{}, false
	}
	tid, err := targetTenantID(c)
	if err != nil {
		_ = orgFail(c, http.StatusBadRequest, "invalid_request", "Invalid tenant id.")
		return auth.OrganizationScope{}, orgActor{}, false
	}
	appID, err := strconv.ParseInt(c.Param("appID"), 10, 64)
	if err != nil {
		_ = orgFail(c, http.StatusBadRequest, "invalid_request", "Invalid application id.")
		return auth.OrganizationScope{}, orgActor{}, false
	}
	sc := auth.OrganizationScope{TenantID: tid, AppRowID: appID}
	if err := h.orgs.VerifyScope(c.Request().Context(), sc); err != nil {
		if errors.Is(err, auth.ErrOrganizationNotFound) {
			_ = orgFail(c, http.StatusNotFound, "application_not_found", "Application not found.")
		} else {
			h.logger.Error().Err(err).Msg("organizations: verify application scope failed")
			_ = orgFail(c, http.StatusInternalServerError, "internal_error", "Failed to verify the application.")
		}
		return auth.OrganizationScope{}, orgActor{}, false
	}
	actor := orgActor{email: claims.Email}
	if uid, err := strconv.ParseInt(claims.UserID, 10, 64); err == nil {
		actor.userID = &uid
	}
	return sc, actor, true
}

// orgError maps service errors onto responses: a stable machine code in
// "error" to branch on, and a sentence in "message" to show — the shape the
// admin console's apiErrorCode/apiErrorMessage read. Validation errors name
// the problem, because the caller is configuring its own application; lookups
// that could probe another application's data answer a plain 404.
func (h *OrganizationHandler) orgError(c echo.Context, err error) error {
	var unmet *auth.OrganizationsModeUnmetError
	switch {
	case errors.Is(err, auth.ErrOrganizationsDisabled):
		return fail(c, http.StatusNotFound, "not_found")
	case errors.Is(err, auth.ErrOrganizationNotFound):
		return orgFail(c, http.StatusNotFound, "organization_not_found", "Organization not found.")
	case errors.Is(err, auth.ErrOrganizationMemberNotFound):
		return orgFail(c, http.StatusNotFound, "member_not_found", "That user is not a member of this organization.")
	case errors.Is(err, auth.ErrUserNotInApplication):
		return orgFail(c, http.StatusNotFound, "user_not_found", "User not found in this application.")
	case errors.Is(err, auth.ErrOrganizationSlugTaken):
		return orgFail(c, http.StatusConflict, "organization_slug_taken", "An organization with this slug already exists in this application.")
	case errors.Is(err, auth.ErrOrganizationInvitationAccountExists):
		return orgFail(c, http.StatusConflict, "account_exists", err.Error())
	case errors.Is(err, auth.ErrOrganizationLimitReached),
		errors.Is(err, auth.ErrOrganizationMemberLimitReached),
		errors.Is(err, auth.ErrOrganizationRoleLimitReached):
		return orgFail(c, http.StatusConflict, "limit_reached", err.Error())
	case errors.As(err, &unmet):
		return c.JSON(http.StatusConflict, map[string]any{
			"error":                    "organizations_mode_unmet",
			"message":                  err.Error(),
			"users_without_membership": unmet.UsersWithoutMembership,
		})
	case errors.Is(err, auth.ErrInvalidOrganizationSlug),
		errors.Is(err, auth.ErrInvalidOrganizationName),
		errors.Is(err, auth.ErrInvalidOrganizationMetadata),
		errors.Is(err, auth.ErrInvalidOrganizationMemberStatus),
		errors.Is(err, auth.ErrInvalidOrganizationsMode),
		errors.Is(err, auth.ErrRoleNotInApplication),
		errors.Is(err, auth.ErrNoRolesRequested),
		errors.Is(err, auth.ErrInvalidInvitationEmail),
		errors.Is(err, auth.ErrInvalidInvitationURL),
		errors.Is(err, auth.ErrInvalidInvitationTTL),
		errors.Is(err, auth.ErrInvitationLinkRequired),
		errors.Is(err, auth.ErrWeakPassword):
		return orgFail(c, http.StatusBadRequest, "invalid_request", err.Error())
	case errors.Is(err, auth.ErrOrganizationInvitationInvalid):
		return orgFail(c, http.StatusBadRequest, "invalid_invitation", "This invitation is invalid or has expired.")
	default:
		// Never echo err: it may carry SQL detail.
		h.logger.Error().Err(err).Str("path", c.Path()).Msg("organizations: request failed")
		return orgFail(c, http.StatusInternalServerError, "internal_error", "Something went wrong. Please try again.")
	}
}

func orgFail(c echo.Context, status int, code, message string) error {
	return c.JSON(status, APIError{Error: code, Message: message})
}

// auditOrg records a management event. The organisation is attached by row id
// for queries and by public id in the metadata for people reading the log.
func (h *OrganizationHandler) auditOrg(c echo.Context, sc auth.OrganizationScope, actor orgActor, action, resourceType, resourceID string, org *auth.Organization, meta map[string]any) {
	if meta == nil {
		meta = map[string]any{}
	}
	tid, aid := sc.TenantID, sc.AppRowID
	ev := audit.Event{
		TenantID: &tid, ApplicationID: &aid, UserID: actor.userID, ActorEmail: actor.email,
		Action: action, ResourceType: resourceType, ResourceID: resourceID,
		IPAddress: c.RealIP(), UserAgent: c.Request().UserAgent(), Metadata: meta,
	}
	if org != nil {
		rid := org.RowID()
		ev.OrganizationID = &rid
		meta["organization_id"] = org.ID
		meta["organization_slug"] = org.Slug
	}
	if actor.clientID != "" {
		ev.AuthMethod = audit.AuthMethodClientCredentials
		meta["client_id"] = actor.clientID
	}
	logOrStage(c, h.audit, ev)
}

// parseUserParam parses :uid. A malformed id answers exactly like an unknown
// one, so it cannot distinguish "invalid" from "not yours".
func parseUserParam(c echo.Context) (int64, bool) {
	uid, err := strconv.ParseInt(c.Param("uid"), 10, 64)
	if err != nil || uid <= 0 {
		_ = orgFail(c, http.StatusNotFound, "user_not_found", "User not found in this application.")
		return 0, false
	}
	return uid, true
}

func pageParams(c echo.Context) auth.PageParams {
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	offset, _ := strconv.Atoi(c.QueryParam("offset"))
	return auth.PageParams{Search: c.QueryParam("search"), Limit: limit, Offset: offset}
}

// ---------------------------------------------------------------------------
// Organisations
// ---------------------------------------------------------------------------

// CreateOrganizationRequest is the body for creating an organisation.
type CreateOrganizationRequest struct {
	// Slug is the immutable handle: 1-63 lowercase letters, digits or hyphens.
	Slug        string         `json:"slug"`
	DisplayName string         `json:"display_name"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// UpdateOrganizationRequest changes an organisation. Omitted fields are kept.
type UpdateOrganizationRequest struct {
	DisplayName *string        `json:"display_name,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	// IsActive false suspends the organisation and signs everyone out of it.
	IsActive *bool `json:"is_active,omitempty"`
}

// CreateOrganization creates an organisation in the application.
//
// @Summary      Create an organization
// @Description  Creates a customer organization inside the application. Allowed while the application's organizations_mode is still "off", so organizations can be prepared before sign-in depends on them. Application backends authenticate with Authorization: Basic (client credentials); the admin console with a bearer token. 404 when ORGANIZATIONS_ENABLED is false.
// @Tags         organizations
// @Accept       json
// @Produce      json
// @Param        body  body      CreateOrganizationRequest  true  "Organization"
// @Success      201   {object}  auth.Organization
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      409   {object}  map[string]string  "Slug taken or limit reached"
// @Router       /api/v1/auth/apps/organizations [post]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/organizations [post]
func (h *OrganizationHandler) CreateOrganization(scope orgScopeFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sc, actor, ok := scope(c)
		if !ok {
			return nil
		}
		var req CreateOrganizationRequest
		if err := c.Bind(&req); err != nil {
			return orgFail(c, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		}
		org, err := h.orgs.CreateOrganization(c.Request().Context(), sc, auth.CreateOrganizationInput{
			Slug: req.Slug, DisplayName: req.DisplayName, Metadata: req.Metadata, CreatedBy: actor.userID,
		})
		if err != nil {
			return h.orgError(c, err)
		}
		h.auditOrg(c, sc, actor, audit.ActionOrganizationCreated, "organization", org.ID, org, nil)
		return c.JSON(http.StatusCreated, org)
	}
}

// ListOrganizations lists the application's organisations.
//
// @Summary      List organizations
// @Tags         organizations
// @Produce      json
// @Param        search  query     string  false  "Match slug or display name"
// @Param        limit   query     int     false  "Page size (default 25, max 100)"
// @Param        offset  query     int     false  "Offset"
// @Success      200     {object}  auth.OrganizationsPage
// @Router       /api/v1/auth/apps/organizations [get]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/organizations [get]
func (h *OrganizationHandler) ListOrganizations(scope orgScopeFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sc, _, ok := scope(c)
		if !ok {
			return nil
		}
		page, err := h.orgs.ListOrganizations(c.Request().Context(), sc, pageParams(c))
		if err != nil {
			return h.orgError(c, err)
		}
		return c.JSON(http.StatusOK, page)
	}
}

// GetOrganization returns one organisation by public id or slug.
//
// @Summary      Get an organization
// @Tags         organizations
// @Produce      json
// @Param        org  path      string  true  "Organization id (org_…) or slug"
// @Success      200  {object}  auth.Organization
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/auth/apps/organizations/{org} [get]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/organizations/{org} [get]
func (h *OrganizationHandler) GetOrganization(scope orgScopeFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sc, _, ok := scope(c)
		if !ok {
			return nil
		}
		org, err := h.orgs.GetOrganization(c.Request().Context(), sc, c.Param("org"))
		if err != nil {
			return h.orgError(c, err)
		}
		return c.JSON(http.StatusOK, org)
	}
}

// UpdateOrganization changes display name, metadata or active state.
//
// @Summary      Update an organization
// @Description  Changes display_name, metadata or is_active. The slug is immutable. Setting is_active=false signs every member out of the organization.
// @Tags         organizations
// @Accept       json
// @Produce      json
// @Param        org   path      string                     true  "Organization id or slug"
// @Param        body  body      UpdateOrganizationRequest  true  "Changes"
// @Success      200   {object}  auth.Organization
// @Router       /api/v1/auth/apps/organizations/{org} [patch]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/organizations/{org} [patch]
func (h *OrganizationHandler) UpdateOrganization(scope orgScopeFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sc, actor, ok := scope(c)
		if !ok {
			return nil
		}
		var req UpdateOrganizationRequest
		if err := c.Bind(&req); err != nil {
			return orgFail(c, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		}
		org, err := h.orgs.UpdateOrganization(c.Request().Context(), sc, c.Param("org"), auth.UpdateOrganizationInput{
			DisplayName: req.DisplayName, Metadata: req.Metadata, IsActive: req.IsActive,
		})
		if err != nil {
			return h.orgError(c, err)
		}
		meta := map[string]any{}
		if req.IsActive != nil {
			meta["is_active"] = *req.IsActive
		}
		h.auditOrg(c, sc, actor, audit.ActionOrganizationUpdated, "organization", org.ID, org, meta)
		return c.JSON(http.StatusOK, org)
	}
}

// DeleteOrganization soft-deletes an organisation.
//
// @Summary      Delete an organization
// @Description  Soft-deletes the organization: sign-in to it stops, every session in it is revoked and pending invitations are closed. Members and roles are kept for the audit trail.
// @Tags         organizations
// @Param        org  path  string  true  "Organization id or slug"
// @Success      204
// @Router       /api/v1/auth/apps/organizations/{org} [delete]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/organizations/{org} [delete]
func (h *OrganizationHandler) DeleteOrganization(scope orgScopeFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sc, actor, ok := scope(c)
		if !ok {
			return nil
		}
		org, err := h.orgs.DeleteOrganization(c.Request().Context(), sc, c.Param("org"))
		if err != nil {
			return h.orgError(c, err)
		}
		h.auditOrg(c, sc, actor, audit.ActionOrganizationDeleted, "organization", org.ID, org, nil)
		return c.NoContent(http.StatusNoContent)
	}
}

// ---------------------------------------------------------------------------
// Members and organisation roles
// ---------------------------------------------------------------------------

// AddOrganizationMemberRequest adds a member, optionally with roles.
type AddOrganizationMemberRequest struct {
	Roles []string `json:"roles,omitempty"`
}

// UpdateOrganizationMemberRequest suspends or reactivates a member.
type UpdateOrganizationMemberRequest struct {
	// Status is "active" or "suspended".
	Status string `json:"status"`
}

// OrganizationMemberRolesRequest grants organisation roles.
type OrganizationMemberRolesRequest struct {
	Roles []string `json:"roles"`
	// Mode is "add" (default) or "replace".
	Mode string `json:"mode,omitempty"`
}

// ListOrganizationMembers lists an organisation's members.
//
// @Summary      List organization members
// @Tags         organizations
// @Produce      json
// @Param        org     path      string  true   "Organization id or slug"
// @Param        search  query     string  false  "Match email or name"
// @Param        limit   query     int     false  "Page size (default 25, max 100)"
// @Param        offset  query     int     false  "Offset"
// @Success      200     {object}  auth.OrganizationMembersPage
// @Router       /api/v1/auth/apps/organizations/{org}/members [get]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/organizations/{org}/members [get]
func (h *OrganizationHandler) ListMembers(scope orgScopeFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sc, _, ok := scope(c)
		if !ok {
			return nil
		}
		page, err := h.orgs.ListMembers(c.Request().Context(), sc, c.Param("org"), pageParams(c))
		if err != nil {
			return h.orgError(c, err)
		}
		return c.JSON(http.StatusOK, page)
	}
}

// AddMember adds a user of the application to an organisation.
//
// @Summary      Add an organization member
// @Description  Adds one of the application's users to the organization, optionally with organization roles. Idempotent: an existing member answers 200 and gains any additional roles; a new member answers 201.
// @Tags         organizations
// @Accept       json
// @Produce      json
// @Param        org   path      string                        true   "Organization id or slug"
// @Param        uid   path      string                        true   "User id"
// @Param        body  body      AddOrganizationMemberRequest  false  "Roles"
// @Success      200   {object}  auth.OrganizationMember
// @Success      201   {object}  auth.OrganizationMember
// @Failure      404   {object}  map[string]string
// @Router       /api/v1/auth/apps/organizations/{org}/members/{uid} [put]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/organizations/{org}/members/{uid} [put]
func (h *OrganizationHandler) AddMember(scope orgScopeFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sc, actor, ok := scope(c)
		if !ok {
			return nil
		}
		uid, ok := parseUserParam(c)
		if !ok {
			return nil
		}
		var req AddOrganizationMemberRequest
		if c.Request().ContentLength != 0 {
			if err := c.Bind(&req); err != nil {
				return orgFail(c, http.StatusBadRequest, "invalid_request", "Invalid request body.")
			}
		}
		ctx := c.Request().Context()
		member, created, err := h.orgs.AddMember(ctx, sc, c.Param("org"), uid, req.Roles, actor.userID)
		if err != nil {
			return h.orgError(c, err)
		}
		org, _ := h.orgs.GetOrganization(ctx, sc, c.Param("org"))
		h.auditOrg(c, sc, actor, audit.ActionOrganizationMemberAdded, "user", member.UserID, org,
			map[string]any{"created": created, "roles": member.Roles})
		if created {
			return c.JSON(http.StatusCreated, member)
		}
		return c.JSON(http.StatusOK, member)
	}
}

// GetMember returns one member.
//
// @Summary      Get an organization member
// @Tags         organizations
// @Produce      json
// @Param        org  path      string  true  "Organization id or slug"
// @Param        uid  path      string  true  "User id"
// @Success      200  {object}  auth.OrganizationMember
// @Router       /api/v1/auth/apps/organizations/{org}/members/{uid} [get]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/organizations/{org}/members/{uid} [get]
func (h *OrganizationHandler) GetMember(scope orgScopeFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sc, _, ok := scope(c)
		if !ok {
			return nil
		}
		uid, ok := parseUserParam(c)
		if !ok {
			return nil
		}
		m, err := h.orgs.GetMember(c.Request().Context(), sc, c.Param("org"), uid)
		if err != nil {
			return h.orgError(c, err)
		}
		return c.JSON(http.StatusOK, m)
	}
}

// UpdateMember suspends or reactivates a member.
//
// @Summary      Suspend or reactivate an organization member
// @Description  status "suspended" keeps the membership and roles but refuses sign-in to the organization and revokes the member's sessions in it. "active" restores it from the next sign-in.
// @Tags         organizations
// @Accept       json
// @Produce      json
// @Param        org   path      string                           true  "Organization id or slug"
// @Param        uid   path      string                           true  "User id"
// @Param        body  body      UpdateOrganizationMemberRequest  true  "Status"
// @Success      200   {object}  auth.OrganizationMember
// @Router       /api/v1/auth/apps/organizations/{org}/members/{uid} [patch]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/organizations/{org}/members/{uid} [patch]
func (h *OrganizationHandler) UpdateMember(scope orgScopeFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sc, actor, ok := scope(c)
		if !ok {
			return nil
		}
		uid, ok := parseUserParam(c)
		if !ok {
			return nil
		}
		var req UpdateOrganizationMemberRequest
		if err := c.Bind(&req); err != nil {
			return orgFail(c, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		}
		ctx := c.Request().Context()
		m, err := h.orgs.SetMemberStatus(ctx, sc, c.Param("org"), uid, strings.TrimSpace(req.Status))
		if err != nil {
			return h.orgError(c, err)
		}
		org, _ := h.orgs.GetOrganization(ctx, sc, c.Param("org"))
		h.auditOrg(c, sc, actor, audit.ActionOrganizationMemberUpdated, "user", m.UserID, org,
			map[string]any{"status": m.Status})
		return c.JSON(http.StatusOK, m)
	}
}

// RemoveMember removes a member and their organisation roles.
//
// @Summary      Remove an organization member
// @Description  Deletes the membership and its organization roles and revokes the member's sessions in this organization. The user's account is untouched.
// @Tags         organizations
// @Param        org  path  string  true  "Organization id or slug"
// @Param        uid  path  string  true  "User id"
// @Success      204
// @Router       /api/v1/auth/apps/organizations/{org}/members/{uid} [delete]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/organizations/{org}/members/{uid} [delete]
func (h *OrganizationHandler) RemoveMember(scope orgScopeFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sc, actor, ok := scope(c)
		if !ok {
			return nil
		}
		uid, ok := parseUserParam(c)
		if !ok {
			return nil
		}
		ctx := c.Request().Context()
		org, err := h.orgs.GetOrganization(ctx, sc, c.Param("org"))
		if err != nil {
			return h.orgError(c, err)
		}
		if err := h.orgs.RemoveMember(ctx, sc, org.ID, uid); err != nil {
			return h.orgError(c, err)
		}
		h.auditOrg(c, sc, actor, audit.ActionOrganizationMemberRemoved, "user", strconv.FormatInt(uid, 10), org, nil)
		return c.NoContent(http.StatusNoContent)
	}
}

// AssignMemberRoles grants organisation roles.
//
// @Summary      Assign organization roles to a member
// @Description  Grants roles that apply only inside this organization. Roles are names of the application's own roles; unknown or system roles refuse the whole call. mode=add (default) keeps existing organization roles, mode=replace discards them. The member's access tokens are invalidated so the change applies at their next refresh.
// @Tags         organizations
// @Accept       json
// @Produce      json
// @Param        org   path      string                          true  "Organization id or slug"
// @Param        uid   path      string                          true  "User id"
// @Param        body  body      OrganizationMemberRolesRequest  true  "Roles"
// @Success      200   {object}  auth.MemberRolesResult
// @Router       /api/v1/auth/apps/organizations/{org}/members/{uid}/roles [post]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/organizations/{org}/members/{uid}/roles [post]
func (h *OrganizationHandler) AssignMemberRoles(scope orgScopeFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sc, actor, ok := scope(c)
		if !ok {
			return nil
		}
		uid, ok := parseUserParam(c)
		if !ok {
			return nil
		}
		var req OrganizationMemberRolesRequest
		if err := c.Bind(&req); err != nil {
			return orgFail(c, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		}
		var replace bool
		switch req.Mode {
		case "", "add":
		case "replace":
			replace = true
		default:
			return orgFail(c, http.StatusBadRequest, "invalid_request", `mode must be "add" or "replace".`)
		}
		ctx := c.Request().Context()
		res, err := h.orgs.AssignMemberRoles(ctx, sc, c.Param("org"), uid, req.Roles, replace, actor.userID)
		if err != nil {
			return h.orgError(c, err)
		}
		org, _ := h.orgs.GetOrganization(ctx, sc, c.Param("org"))
		h.auditOrg(c, sc, actor, audit.ActionOrganizationRolesAssigned, "user", res.UserID, org,
			map[string]any{"mode": map[bool]string{true: "replace", false: "add"}[replace],
				"assigned": res.Assigned, "removed": res.Removed, "roles": res.Roles})
		return c.JSON(http.StatusOK, res)
	}
}

// RemoveMemberRole removes one organisation role.
//
// @Summary      Remove an organization role from a member
// @Tags         organizations
// @Produce      json
// @Param        org   path      string  true  "Organization id or slug"
// @Param        uid   path      string  true  "User id"
// @Param        role  path      string  true  "Role name"
// @Success      200   {object}  auth.MemberRolesResult
// @Router       /api/v1/auth/apps/organizations/{org}/members/{uid}/roles/{role} [delete]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/organizations/{org}/members/{uid}/roles/{role} [delete]
func (h *OrganizationHandler) RemoveMemberRole(scope orgScopeFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sc, actor, ok := scope(c)
		if !ok {
			return nil
		}
		uid, ok := parseUserParam(c)
		if !ok {
			return nil
		}
		ctx := c.Request().Context()
		res, err := h.orgs.RemoveMemberRole(ctx, sc, c.Param("org"), uid, c.Param("role"))
		if err != nil {
			return h.orgError(c, err)
		}
		if len(res.Removed) > 0 {
			org, _ := h.orgs.GetOrganization(ctx, sc, c.Param("org"))
			h.auditOrg(c, sc, actor, audit.ActionOrganizationRoleRevoked, "user", res.UserID, org,
				map[string]any{"role": c.Param("role")})
		}
		return c.JSON(http.StatusOK, res)
	}
}

// ListUserOrganizations lists every organisation a user belongs to.
//
// @Summary      List a user's organizations
// @Tags         organizations
// @Produce      json
// @Param        uid  path      string  true  "User id"
// @Success      200  {array}   auth.OrganizationMembership
// @Router       /api/v1/auth/apps/users/{uid}/organizations [get]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/users/{uid}/organizations [get]
func (h *OrganizationHandler) ListUserOrganizations(scope orgScopeFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sc, _, ok := scope(c)
		if !ok {
			return nil
		}
		uid, ok := parseUserParam(c)
		if !ok {
			return nil
		}
		ms, err := h.orgs.ListUserMemberships(c.Request().Context(), sc, uid, false)
		if err != nil {
			return h.orgError(c, err)
		}
		return c.JSON(http.StatusOK, ms)
	}
}

// ---------------------------------------------------------------------------
// Invitations (management)
// ---------------------------------------------------------------------------

// CreateOrganizationInvitationRequest invites an email to an organisation.
type CreateOrganizationInvitationRequest struct {
	Email string   `json:"email"`
	Roles []string `json:"roles,omitempty"`
	// InvitationURL is the application's page that accepts invitations. Must be
	// on one of the application's registered redirect URI origins; the
	// invitation and organization query parameters are appended.
	InvitationURL string `json:"invitation_url,omitempty"`
	// SendEmail asks EMC to send the invitation using the application's branded
	// template. Requires invitation_url.
	SendEmail bool `json:"send_email,omitempty"`
	// ExpiresInHours defaults to 72; 1–720.
	ExpiresInHours int    `json:"expires_in_hours,omitempty"`
	InviterName    string `json:"inviter_name,omitempty"`
}

// CreateInvitation invites an email address to an organisation.
//
// @Summary      Invite to an organization
// @Description  Creates an invitation carrying the organization and roles. The raw token is returned once in the response and never stored. With send_email EMC delivers it; otherwise the application sends its own email using the token. A pending invitation for the same address is replaced.
// @Tags         organizations
// @Accept       json
// @Produce      json
// @Param        org   path      string                               true  "Organization id or slug"
// @Param        body  body      CreateOrganizationInvitationRequest  true  "Invitation"
// @Success      201   {object}  auth.CreatedOrganizationInvitation
// @Router       /api/v1/auth/apps/organizations/{org}/invitations [post]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/organizations/{org}/invitations [post]
func (h *OrganizationHandler) CreateInvitation(scope orgScopeFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sc, actor, ok := scope(c)
		if !ok {
			return nil
		}
		var req CreateOrganizationInvitationRequest
		if err := c.Bind(&req); err != nil {
			return orgFail(c, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		}
		if req.ExpiresInHours < 0 || req.ExpiresInHours > 720 {
			return h.orgError(c, auth.ErrInvalidInvitationTTL)
		}
		ctx := c.Request().Context()
		inv, err := h.orgs.CreateInvitation(ctx, sc, c.Param("org"), auth.CreateOrganizationInvitationInput{
			Email: req.Email, Roles: req.Roles, InvitedBy: actor.userID, InvitedByClient: actor.clientID,
			InviterName: req.InviterName, TTL: time.Duration(req.ExpiresInHours) * time.Hour,
			InvitationURL: req.InvitationURL, SendEmail: req.SendEmail,
		})
		if err != nil {
			return h.orgError(c, err)
		}
		org, _ := h.orgs.GetOrganization(ctx, sc, c.Param("org"))
		h.auditOrg(c, sc, actor, audit.ActionOrganizationInviteSent, "organization_invitation", inv.ID, org,
			map[string]any{"email": inv.Email, "roles": inv.Roles, "email_sent": inv.EmailSent})
		c.Response().Header().Set("Cache-Control", "no-store")
		return c.JSON(http.StatusCreated, inv)
	}
}

// ListInvitations lists an organisation's invitations.
//
// @Summary      List organization invitations
// @Tags         organizations
// @Produce      json
// @Param        org             path      string  true   "Organization id or slug"
// @Param        include_closed  query     bool    false  "Include accepted, revoked and expired"
// @Success      200             {array}   auth.OrganizationInvitation
// @Router       /api/v1/auth/apps/organizations/{org}/invitations [get]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/organizations/{org}/invitations [get]
func (h *OrganizationHandler) ListInvitations(scope orgScopeFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sc, _, ok := scope(c)
		if !ok {
			return nil
		}
		invs, err := h.orgs.ListInvitations(c.Request().Context(), sc, c.Param("org"), c.QueryParam("include_closed") == "true")
		if err != nil {
			return h.orgError(c, err)
		}
		return c.JSON(http.StatusOK, invs)
	}
}

// RevokeInvitation revokes a pending invitation.
//
// @Summary      Revoke an organization invitation
// @Tags         organizations
// @Param        org  path  string  true  "Organization id or slug"
// @Param        inv  path  string  true  "Invitation id (inv_…)"
// @Success      204
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/auth/apps/organizations/{org}/invitations/{inv} [delete]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/organizations/{org}/invitations/{inv} [delete]
func (h *OrganizationHandler) RevokeInvitation(scope orgScopeFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sc, actor, ok := scope(c)
		if !ok {
			return nil
		}
		ctx := c.Request().Context()
		if err := h.orgs.RevokeInvitation(ctx, sc, c.Param("org"), c.Param("inv")); err != nil {
			if errors.Is(err, auth.ErrOrganizationInvitationInvalid) {
				return orgFail(c, http.StatusNotFound, "invitation_not_found", "Invitation not found or already closed.")
			}
			return h.orgError(c, err)
		}
		org, _ := h.orgs.GetOrganization(ctx, sc, c.Param("org"))
		h.auditOrg(c, sc, actor, audit.ActionOrganizationInviteRevoked, "organization_invitation", c.Param("inv"), org, nil)
		return c.NoContent(http.StatusNoContent)
	}
}

// ---------------------------------------------------------------------------
// Application settings (admin console only)
// ---------------------------------------------------------------------------

// OrganizationSettings is an application's organisation configuration.
type OrganizationSettings struct {
	// Mode is "off", "optional" or "required".
	Mode string `json:"organizations_mode"`
	// Enabled reports the deployment switch, so the console can explain why
	// a mode has no effect.
	Enabled bool `json:"organizations_enabled"`
}

// UpdateOrganizationSettingsRequest changes the mode.
type UpdateOrganizationSettingsRequest struct {
	Mode string `json:"organizations_mode"`
	// Force allows "required" while some users belong to no organization.
	// They will be unable to sign in until they are added to one.
	Force bool `json:"force,omitempty"`
}

// GetSettings returns the application's organisation mode.
//
// @Summary      Get an application's organization settings
// @Tags         organizations
// @Produce      json
// @Security     BearerAuth
// @Param        tid    path      string  true  "Tenant id"
// @Param        appID  path      string  true  "Application id"
// @Success      200    {object}  OrganizationSettings
// @Router       /api/v1/tenants/{tid}/applications/{appID}/organization-settings [get]
func (h *OrganizationHandler) GetSettings(c echo.Context) error {
	// The one organisation route that answers while the deployment switch is
	// off: the console needs to tell an operator WHY the section is inert,
	// rather than render a 404 as an error. It reveals nothing but a flag, and
	// the route guards (apps:read on this application) have already run.
	if !h.orgs.Enabled() {
		return c.JSON(http.StatusOK, OrganizationSettings{Mode: auth.OrganizationsModeOff, Enabled: false})
	}
	sc, _, ok := h.AdminScope(c)
	if !ok {
		return nil
	}
	mode, err := h.orgs.ApplicationMode(c.Request().Context(), sc.AppRowID)
	if err != nil {
		return h.orgError(c, err)
	}
	return c.JSON(http.StatusOK, OrganizationSettings{Mode: mode, Enabled: h.orgs.Enabled()})
}

// UpdateSettings changes the application's organisation mode.
//
// @Summary      Change an application's organization mode
// @Description  off (default): tokens are unchanged and organization parameters are ignored. optional: a session may be inside one organization or none. required: every end-user session is inside exactly one organization. Moving to "required" is refused (409) while active users belong to no organization unless force=true, and revokes organization-less sessions. Moving to "off" revokes organization sessions so users sign in again with a plain token.
// @Tags         organizations
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        tid    path      string                             true  "Tenant id"
// @Param        appID  path      string                             true  "Application id"
// @Param        body   body      UpdateOrganizationSettingsRequest  true  "Mode"
// @Success      200    {object}  OrganizationSettings
// @Failure      409    {object}  map[string]any  "Users without an organization"
// @Router       /api/v1/tenants/{tid}/applications/{appID}/organization-settings [put]
func (h *OrganizationHandler) UpdateSettings(c echo.Context) error {
	sc, actor, ok := h.AdminScope(c)
	if !ok {
		return nil
	}
	var req UpdateOrganizationSettingsRequest
	if err := c.Bind(&req); err != nil {
		return orgFail(c, http.StatusBadRequest, "invalid_request", "Invalid request body.")
	}
	mode := strings.TrimSpace(req.Mode)
	previous, err := h.orgs.SetApplicationMode(c.Request().Context(), sc, mode, req.Force)
	if err != nil {
		return h.orgError(c, err)
	}
	h.auditOrg(c, sc, actor, audit.ActionOrganizationModeChanged, "application",
		strconv.FormatInt(sc.AppRowID, 10), nil,
		map[string]any{"previous": previous, "mode": mode, "force": req.Force})
	return c.JSON(http.StatusOK, OrganizationSettings{Mode: mode, Enabled: h.orgs.Enabled()})
}

// ---------------------------------------------------------------------------
// End-user flows
// ---------------------------------------------------------------------------

// organizationSignInError writes the response for an organisation outcome of a
// sign-in, and reports whether err was one. Shared by every login handler so
// the three outcomes look identical whichever way the user signed in.
//
// These are reached only AFTER the credentials (and any second factor)
// succeeded, so none of them is a credential failure and none should count
// against the caller's captcha or lockout budget.
func organizationSignInError(c echo.Context, err error) (bool, error) {
	var sel *auth.OrganizationSelectionRequiredError
	switch {
	case errors.As(err, &sel):
		c.Response().Header().Set("Cache-Control", "no-store")
		return true, c.JSON(http.StatusConflict, map[string]any{
			"error":           "organization_selection_required",
			"message":         userMessage("organization_selection_required"),
			"selection_token": sel.SelectionToken,
			"organizations":   sel.Organizations,
			"expires_in":      sel.ExpiresIn,
		})
	case errors.Is(err, auth.ErrOrganizationAccessDenied):
		return true, fail(c, http.StatusForbidden, "organization_access_denied")
	case errors.Is(err, auth.ErrOrganizationUnavailable):
		return true, fail(c, http.StatusServiceUnavailable, "organization_unavailable")
	}
	return false, nil
}

// organizationOutcome answers an organisation outcome of an AuthHandler sign-in
// and audits a refusal. Called first in each login handler's error branch, so
// a correct password refused only for organisation reasons is never recorded
// as a credential failure or charged to the captcha budget.
func (h *AuthHandler) organizationOutcome(c echo.Context, err error, authMethod, clientID, email string) (bool, error) {
	handled, resp := organizationSignInError(c, err)
	if !handled {
		return false, nil
	}
	var sel *auth.OrganizationSelectionRequiredError
	if !errors.As(err, &sel) {
		ev := audit.Event{
			Action: audit.ActionOrganizationLoginDenied, Status: audit.StatusFailure,
			AuthMethod: authMethod, ResourceType: "user", ActorEmail: email,
			IPAddress: c.RealIP(), UserAgent: c.Request().UserAgent(),
		}
		if clientID != "" {
			attachAppContext(c.Request().Context(), &ev, h.appSvc, clientID)
		}
		h.auditEvent(c, ev)
	}
	return true, resp
}

// SelectOrganizationRequest completes a sign-in that stopped at a choice.
type SelectOrganizationRequest struct {
	SelectionToken string `json:"selection_token"`
	// Organization is the chosen id (org_…) or slug, from the 409 response.
	Organization string `json:"organization"`
}

// SelectOrganization completes a sign-in with the chosen organisation.
//
// @Summary      Choose an organization to finish signing in
// @Description  Completes a sign-in that answered 409 organization_selection_required. The selection_token is single-use and valid for 5 minutes; the organization must be one of those offered.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        body  body      SelectOrganizationRequest  true  "Selection"
// @Success      200   {object}  auth.AuthResult
// @Failure      400   {object}  APIError  "organization_selection_invalid"
// @Failure      403   {object}  APIError  "organization_access_denied"
// @Router       /api/v1/auth/apps/login/organization [post]
func (h *OrganizationHandler) SelectOrganization(c echo.Context) error {
	if !h.orgs.Enabled() {
		return fail(c, http.StatusNotFound, "not_found")
	}
	var req SelectOrganizationRequest
	if err := c.Bind(&req); err != nil {
		return orgFail(c, http.StatusBadRequest, "invalid_request", "Invalid request body.")
	}
	tokens, err := h.authSvc.CompleteOrganizationSelection(c.Request().Context(), req.SelectionToken, req.Organization)
	if err != nil {
		if errors.Is(err, auth.ErrOrganizationSelectionInvalid) {
			return fail(c, http.StatusBadRequest, "organization_selection_invalid")
		}
		if handled, resp := organizationSignInError(c, err); handled {
			h.auditSignIn(c, "", audit.ActionOrganizationLoginDenied, false)
			return resp
		}
		h.logger.Error().Err(err).Msg("organization selection failed")
		return fail(c, http.StatusInternalServerError, "login_failed")
	}
	h.auditSignIn(c, tokens.AccessToken, audit.ActionOrganizationSelected, true)
	setAuthCookies(c, tokens.AccessToken, tokens.RefreshToken, h.cookieCfg)
	return c.JSON(http.StatusOK, tokens)
}

// SwitchOrganizationRequest moves a session to another organisation.
type SwitchOrganizationRequest struct {
	// RefreshToken of the current session. Required, in the body.
	RefreshToken string `json:"refresh_token"`
	// Organization is the target id (org_…) or slug.
	Organization string `json:"organization,omitempty"`
	// Personal asks for a session with no organisation. Refused when the
	// application requires one.
	Personal bool `json:"personal,omitempty"`
}

// SwitchOrganization moves the user to another organisation without a password.
//
// @Summary      Switch organization
// @Description  Creates a new session in another organization from the current one, without asking for a password again. The new session keeps the original authentication time and methods, so it can never outlive the session it came from. The current session is left as it is. Set personal=true (and no organization) to leave organizations, when the application allows it.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        body  body      SwitchOrganizationRequest  true  "Target"
// @Success      200   {object}  auth.AuthResult
// @Failure      401   {object}  APIError
// @Failure      403   {object}  APIError  "organization_access_denied"
// @Router       /api/v1/auth/apps/switch-organization [post]
func (h *OrganizationHandler) SwitchOrganization(c echo.Context) error {
	if !h.orgs.Enabled() {
		return fail(c, http.StatusNotFound, "not_found")
	}
	var req SwitchOrganizationRequest
	if err := c.Bind(&req); err != nil {
		return orgFail(c, http.StatusBadRequest, "invalid_request", "Invalid request body.")
	}
	// The refresh token is accepted from the body ONLY. Falling back to the
	// refresh cookie would let a cross-site form post switch a signed-in
	// victim's organisation with their own cookies — a CSRF this endpoint has
	// no token to defend against.
	req.Organization = strings.TrimSpace(req.Organization)
	if (req.Organization == "") == !req.Personal {
		return orgFail(c, http.StatusBadRequest, "invalid_request", "Set exactly one of organization or personal.")
	}
	tokens, err := h.authSvc.SwitchOrganization(c.Request().Context(), auth.SwitchOrganizationInput{
		RefreshToken: req.RefreshToken, Organization: req.Organization, Personal: req.Personal,
	})
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidRefreshToken):
			return fail(c, http.StatusUnauthorized, "session_terminated")
		case errors.Is(err, auth.ErrOrganizationsNotApplicable):
			return fail(c, http.StatusBadRequest, "organizations_not_enabled")
		}
		if handled, resp := organizationSignInError(c, err); handled {
			h.auditSignIn(c, "", audit.ActionOrganizationLoginDenied, false)
			return resp
		}
		h.logger.Error().Err(err).Msg("organization switch failed")
		return fail(c, http.StatusInternalServerError, "login_failed")
	}
	h.auditSignIn(c, tokens.AccessToken, audit.ActionOrganizationSwitched, true)
	setAuthCookies(c, tokens.AccessToken, tokens.RefreshToken, h.cookieCfg)
	return c.JSON(http.StatusOK, tokens)
}

// auditSignIn records a selection or switch from the claims of the token it
// produced. A denial has no token and is recorded without a subject.
func (h *OrganizationHandler) auditSignIn(c echo.Context, accessToken, action string, success bool) {
	ev := audit.Event{
		Action: action, ResourceType: "session", AuthMethod: audit.AuthMethodPassword,
		IPAddress: c.RealIP(), UserAgent: c.Request().UserAgent(),
	}
	if !success {
		ev.Status = audit.StatusFailure
	}
	if accessToken != "" {
		tid, uid, appID := claimsFromToken(accessToken)
		ev.TenantID, ev.UserID, ev.ApplicationID = tid, uid, appID
	}
	logOrStage(c, h.audit, ev)
}

// MyOrganizationsResponse lists the caller's organisations.
type MyOrganizationsResponse struct {
	// Current is the organisation this token is signed in to, empty for none.
	Current       string                        `json:"current,omitempty"`
	Organizations []auth.OrganizationMembership `json:"organizations"`
}

// MyOrganizations lists the organisations the signed-in user may switch to.
//
// @Summary      List my organizations
// @Description  The organizations the signed-in user can sign in to in this application, and which one the presented token is for.
// @Tags         AUTH
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  MyOrganizationsResponse
// @Router       /api/v1/auth/apps/me/organizations [get]
func (h *OrganizationHandler) MyOrganizations(c echo.Context) error {
	if !h.orgs.Enabled() {
		return fail(c, http.StatusNotFound, "not_found")
	}
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil || claims.AppID == "" || claims.Email == "" {
		return fail(c, http.StatusForbidden, "organizations_not_enabled")
	}
	tid, err1 := strconv.ParseInt(claims.TenantID, 10, 64)
	aid, err2 := strconv.ParseInt(claims.AppID, 10, 64)
	uid, err3 := strconv.ParseInt(claims.UserID, 10, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return fail(c, http.StatusForbidden, "organizations_not_enabled")
	}
	ms, err := h.orgs.ListUserMemberships(c.Request().Context(),
		auth.OrganizationScope{TenantID: tid, AppRowID: aid}, uid, true)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotInApplication) {
			// A tenant-level user signing in through the application:
			// organisations do not apply to them.
			return c.JSON(http.StatusOK, MyOrganizationsResponse{Organizations: []auth.OrganizationMembership{}})
		}
		return h.orgError(c, err)
	}
	return c.JSON(http.StatusOK, MyOrganizationsResponse{Current: claims.OrgID, Organizations: ms})
}

// PreviewInvitation describes an invitation to the holder of its token.
//
// @Summary      Preview an organization invitation
// @Tags         AUTH
// @Produce      json
// @Param        token  query     string  true  "Invitation token"
// @Success      200    {object}  auth.OrganizationInvitationPreview
// @Failure      400    {object}  map[string]string
// @Router       /api/v1/auth/apps/organizations/invitations/preview [get]
func (h *OrganizationHandler) PreviewInvitation(c echo.Context) error {
	if !h.orgs.Enabled() {
		return fail(c, http.StatusNotFound, "not_found")
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Referrer-Policy", "no-referrer")
	p, err := h.orgs.PreviewInvitation(c.Request().Context(), c.QueryParam("token"))
	if err != nil {
		return h.orgError(c, err)
	}
	return c.JSON(http.StatusOK, p)
}

// AcceptOrganizationInvitationRequest accepts an invitation.
type AcceptOrganizationInvitationRequest struct {
	Token string `json:"token"`
	// Password, FirstName and LastName create the account when the invitee has
	// none. Ignored when the request carries the invitee's own access token.
	Password  string `json:"password,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

// AcceptInvitation accepts an organisation invitation.
//
// @Summary      Accept an organization invitation
// @Description  Two modes. With the invitee's own access token in Authorization: Bearer, the signed-in account joins the organization — it must be the invited email in the same application. Without one, a new verified account is created with the given password. Either way the membership and its roles are created atomically. Sign in with organization=<id> afterwards.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        body  body      AcceptOrganizationInvitationRequest  true  "Acceptance"
// @Success      200   {object}  auth.AcceptedOrganizationInvitation
// @Failure      400   {object}  map[string]string  "Invalid or expired invitation, or weak password"
// @Failure      409   {object}  map[string]string  "Account exists - sign in and accept with the access token"
// @Router       /api/v1/auth/apps/organizations/invitations/accept [post]
func (h *OrganizationHandler) AcceptInvitation(c echo.Context) error {
	if !h.orgs.Enabled() {
		return fail(c, http.StatusNotFound, "not_found")
	}
	var req AcceptOrganizationInvitationRequest
	if err := c.Bind(&req); err != nil {
		return orgFail(c, http.StatusBadRequest, "invalid_request", "Invalid request body.")
	}
	ctx := c.Request().Context()
	in := auth.AcceptOrganizationInvitationInput{
		Token: req.Token, Password: req.Password, FirstName: req.FirstName, LastName: req.LastName,
	}

	// Signed-in mode. The identity comes ONLY from a verified, non-revoked
	// end-user access token; a body field naming a user would let anyone who
	// holds a token join as somebody else.
	if raw := bearerFromHeader(c); raw != "" {
		claims, err := h.jwtSvc.VerifyForAudience(ctx, raw, auth.HumanGrants...)
		if err != nil || claims.AppID == "" ||
			h.authSvc.SessionDenied(ctx, claims.SessionID, claims.UserID, claims.TenantID, issuedAtUnix(claims)) {
			return fail(c, http.StatusUnauthorized, "session_terminated")
		}
		uid, err1 := strconv.ParseInt(claims.UserID, 10, 64)
		aid, err2 := strconv.ParseInt(claims.AppID, 10, 64)
		if err1 != nil || err2 != nil {
			return fail(c, http.StatusUnauthorized, "session_terminated")
		}
		in.ExistingUserID, in.AppRowID = &uid, aid
	}

	res, err := h.orgs.AcceptInvitation(ctx, in)
	if err != nil {
		return h.orgError(c, err)
	}
	sc, orgRowID, invID := res.Scope()
	tid, aid := sc.TenantID, sc.AppRowID
	uid, _ := strconv.ParseInt(res.UserID, 10, 64)
	logOrStage(c, h.audit, audit.Event{
		TenantID: &tid, ApplicationID: &aid, UserID: &uid, OrganizationID: &orgRowID,
		Action: audit.ActionOrganizationInviteAccepted, ResourceType: "organization_invitation",
		ResourceID: invID, IPAddress: c.RealIP(), UserAgent: c.Request().UserAgent(),
		Metadata: map[string]any{
			"organization_id": res.Organization.ID, "account_created": res.AccountCreated, "roles": res.Roles,
		},
	})
	return c.JSON(http.StatusOK, res)
}

// bearerFromHeader returns the bearer token from the Authorization header, or "".
func bearerFromHeader(c echo.Context) string {
	h := c.Request().Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func issuedAtUnix(claims *auth.Claims) int64 {
	if claims.IssuedAt == nil {
		return 0
	}
	return claims.IssuedAt.Unix()
}
