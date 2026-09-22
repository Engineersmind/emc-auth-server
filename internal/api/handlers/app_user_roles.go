package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// AssignAppUserRolesRequest is the body of POST /api/v1/auth/apps/users/roles.
//
// Carries NO client_id or client_secret: application credentials arrive in the
// Authorization: Basic header, the only channel /auth/apps/register and
// /auth/apps/login accept. Keeping one credential channel matters beyond
// consistency — a secret in a JSON body lands in request logs, error reports and
// proxy traces that redact Authorization headers by default.
type AssignAppUserRolesRequest struct {
	// UserID is the application's own user, as returned by /auth/apps/register.
	UserID string `json:"user_id"`
	// Roles are role names defined in this application.
	Roles []string `json:"roles"`
	// Mode is "add" (default) or "replace". Add is the safe default: a retried
	// request is then harmless, whereas a defaulted replace would silently strip
	// roles from a caller who simply omitted the field.
	Mode string `json:"mode"`
}

// AssignAppUserRoles handles POST /api/v1/auth/users/roles.
//
// Lets an application's backend attach roles to its own users after
// registration, authenticating with its client credentials rather than an
// administrator's bearer token. Registration assigns the application's default
// role, or none when no default is configured; this is how a user acquires
// anything beyond it, and the roles reach the token at their next login.
//
// SERVER-SIDE ONLY. The client_secret grants authority over every user of the
// application, so this endpoint is for a backend the operator controls. In a SPA
// or a mobile binary the secret is extractable, and any user could then grant
// themselves every role the application defines. There is deliberately no
// end-user-token equivalent of this call.
//
// @Summary      Assign roles to an application user
// @Description  Attaches roles to one of the calling application's own users. Application credentials via Authorization: Basic header only. Roles are given by name and must already exist in this application; unknown, system, or other applications' roles are refused and nothing is written. mode=add (the default) keeps the roles the user already holds, mode=replace discards them. Every active session for the user is signed out so the change takes effect on their next request. SERVER-SIDE USE ONLY — the client secret must never be shipped in a browser or mobile client.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        Authorization  header  string                     true  "Basic base64(client_id:client_secret)"
// @Param        body           body    AssignAppUserRolesRequest  true  "User and role names"
// @Success      200   {object}  auth.AssignAppUserRolesResult
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string  "Invalid application credentials"
// @Failure      404   {object}  map[string]string  "User not found in this application"
// @Router       /api/v1/auth/apps/users/roles [post]
func (h *AuthHandler) AssignAppUserRoles(c echo.Context) error {
	var req AssignAppUserRolesRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	clientID, clientSecret, errResp := appCredentialsFromRequest(c)
	if errResp != nil {
		return c.JSON(http.StatusBadRequest, errResp)
	}
	if req.UserID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "user_id is required"})
	}
	userID, err := strconv.ParseInt(req.UserID, 10, 64)
	if err != nil {
		// Indistinguishable from a well-formed id that does not exist, so a
		// malformed value cannot be used to tell "invalid" from "not yours".
		return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found in this application"})
	}

	var replace bool
	switch req.Mode {
	case "", "add":
		replace = false
	case "replace":
		replace = true
	default:
		return c.JSON(http.StatusBadRequest, map[string]string{"error": `mode must be "add" or "replace"`})
	}

	result, err := h.svc.AssignAppUserRoles(c.Request().Context(), auth.AssignAppUserRolesInput{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		UserID:       userID,
		Roles:        req.Roles,
		Replace:      replace,
	})
	if err != nil {
		return h.appUserRolesError(c, clientID, err)
	}

	// Attributed to the client_id, not to a user: the actor is a machine and
	// users.id has nobody to point at. An investigation asking "which human
	// granted this" must be able to see at once that the answer is "none".
	h.auditEvent(c, audit.Event{
		UserID:       &result.UserID,
		Action:       audit.ActionAppUserRolesAssigned,
		AuthMethod:   audit.AuthMethodClientCredentials,
		ResourceType: "user",
		ResourceID:   strconv.FormatInt(result.UserID, 10),
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
		Metadata: map[string]any{
			"client_id": clientID,
			"mode":      map[bool]string{true: "replace", false: "add"}[replace],
			"assigned":  result.Assigned,
			"roles":     result.Roles,
		},
	})
	return c.JSON(http.StatusOK, result)
}

// appUserRolesError maps the service's refusals onto responses.
//
// Credential failures are logged WITHOUT the secret and answered generically, so
// the endpoint cannot be used to tell a registered client_id from an unregistered
// one. Role failures do name the offending roles: the caller has already
// authenticated as the application that owns them, so it is being told about its
// own configuration — and a typo in a deployment script is the likely cause.
func (h *AuthHandler) appUserRolesError(c echo.Context, clientID string, err error) error {
	switch {
	case errors.Is(err, auth.ErrInvalidClient):
		h.logger.Warn().Str("client_id", clientID).Str("ip", c.RealIP()).
			Msg("app role assignment: invalid client credentials")
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid client credentials"})

	case errors.Is(err, auth.ErrUserNotInApplication):
		// Same answer for "no such user" and "somebody else's user", so one
		// application cannot enumerate a sibling application's user ids.
		return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found in this application"})

	case errors.Is(err, auth.ErrRoleNotInApplication):
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})

	default:
		// Never echo err: it may carry SQL detail, and the caller is a machine
		// that cannot act on it anyway.
		h.logger.Error().Err(err).Str("client_id", clientID).
			Msg("app role assignment failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to assign roles"})
	}
}
