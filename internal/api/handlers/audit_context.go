package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// attachAppContext ensures an application-scoped event carries the tenant and
// application it targeted — including on failures, where the token that would
// otherwise supply them was never issued. It records the public client_id in
// metadata and resolves the tenant/application row (cheap, no secret check) so
// the audit trail always shows the application name (via the query join).
// Unknown client_ids leave the row un-attributed (the client_id was invalid).
func attachAppContext(ctx context.Context, e *audit.Event, appSvc *auth.ApplicationService, clientID string) {
	if clientID == "" {
		return
	}
	if e.Metadata == nil {
		e.Metadata = map[string]any{}
	}
	if _, ok := e.Metadata["client_id"]; !ok {
		e.Metadata["client_id"] = clientID
	}
	if appSvc == nil {
		return
	}
	if tenantID, appID, ok := appSvc.ResolveClient(ctx, clientID); ok {
		if e.ApplicationID == nil {
			e.ApplicationID = &appID
		}
		if e.TenantID == nil {
			e.TenantID = &tenantID
		}
	}
}

// attachTokenOwner attributes a failed refresh/replay audit event to the account
// the presented refresh token belongs to, when it resolves to a real stored row
// (expired or replayed included). A token that never existed leaves the event
// anonymous — we never attribute a failure to a guessed identity. Forensics for
// "whose session was replayed" without trusting an invalid token's claims.
func attachTokenOwner(ctx context.Context, e *audit.Event, svc *auth.AuthService, rawToken string) {
	if svc == nil {
		return
	}
	if owner, ok := svc.ResolveTokenOwner(ctx, rawToken); ok {
		e.UserID = &owner.UserID
		e.TenantID = &owner.TenantID
		if e.ActorEmail == "" {
			e.ActorEmail = owner.Email
		}
	}
}

// authFailureReason classifies a login/MFA error into a short, stable code for
// the audit metadata `reason` field — enough to debug "why did this fail"
// without leaking the raw error text (which can vary or carry detail).
func authFailureReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, auth.ErrInvalidClient):
		return "invalid_client"
	case errors.Is(err, auth.ErrTooManyOTPAttempts):
		return "too_many_attempts"
	case containsMsg(err, "invalid credentials"):
		return "invalid_credentials"
	case containsMsg(err, "not verified"):
		return "email_not_verified"
	case containsMsg(err, "invalid or expired"), containsMsg(err, "invalid TOTP"):
		return "invalid_or_expired_code"
	case containsMsg(err, "not configured"):
		return "not_configured"
	default:
		return "error"
	}
}

// enrichAudit fills request-scoped context onto an audit event just before it
// is logged, so every event carries the same production-grade fields without
// each call site having to repeat them:
//
//   - RequestID   — from the X-Request-Id header set by the RequestID
//     middleware, tying the row to the request's structured logs.
//   - IPAddress   — the caller's real IP (respecting proxy headers).
//   - UserAgent   — the caller's User-Agent.
//   - Status      — derived from the action when the caller left it unset
//     (*_failed / replay / challenge_failed → failure).
//   - Metadata    — always includes the HTTP method and the matched ROUTE
//     template (never the raw URL, which can carry ids/tokens),
//     merged with any caller-supplied detail.
//
// It only fills blanks — an explicit Status or Metadata value from the caller
// always wins.
func enrichAudit(c echo.Context, e *audit.Event) {
	if e.RequestID == "" {
		e.RequestID = c.Response().Header().Get(echo.HeaderXRequestID)
		if e.RequestID == "" {
			e.RequestID = c.Request().Header.Get(echo.HeaderXRequestID)
		}
	}
	if e.IPAddress == "" {
		e.IPAddress = c.RealIP()
	}
	if e.UserAgent == "" {
		e.UserAgent = c.Request().UserAgent()
	}
	if e.Status == "" {
		e.Status = deriveStatus(e.Action)
	}
	// Best-effort backfill of the response code. When a call site did not set
	// HTTPStatus explicitly, use the already-written response status if there
	// is one (covers handlers that log after c.JSON / echo.NewHTTPError paths);
	// otherwise fall back to a sensible default derived from the outcome.
	if e.HTTPStatus == 0 {
		if written := c.Response().Status; written != 0 && c.Response().Committed {
			e.HTTPStatus = written
		} else {
			e.HTTPStatus = defaultStatusFor(e.Action, e.Status)
		}
	}

	if e.Metadata == nil {
		e.Metadata = map[string]any{}
	}
	if _, ok := e.Metadata["http_method"]; !ok {
		e.Metadata["http_method"] = c.Request().Method
	}
	// c.Path() is the route template ("/api/v1/tenants/:tid/applications/:id"),
	// not the concrete URL — safe to store, no ids or query secrets leak in.
	if _, ok := e.Metadata["http_route"]; !ok {
		if route := c.Path(); route != "" {
			e.Metadata["http_route"] = route
		}
	}
	// hostname — which host/domain served the request (white-label / multi-domain).
	// Auth0's `hostname`. Host header only, never the full URL.
	if _, ok := e.Metadata["hostname"]; !ok {
		if host := c.Request().Host; host != "" {
			e.Metadata["hostname"] = host
		}
	}
}

// defaultStatusFor returns the HTTP status to record when a call site logs an
// event before the response is written (the common case — audit is emitted at
// the decision point). Success paths map to 200 (201 for registration);
// failures fall back to 400 unless a more specific code is known at the site.
func defaultStatusFor(action, status string) int {
	if status == audit.StatusFailure {
		return 0 // unknown; let a call-site value or auditFailure set the real code
	}
	if action == audit.ActionAuthRegister {
		return 201
	}
	return 200
}

// statusForError maps a classified auth failure to the HTTP status the handler
// serves for it, so a failure audit row records the same code the caller saw.
func statusForError(err error) int {
	switch authFailureReason(err) {
	case "invalid_credentials", "invalid_client", "email_not_verified", "invalid_or_expired_code":
		return http.StatusUnauthorized
	case "too_many_attempts":
		return http.StatusTooManyRequests
	case "not_configured":
		return http.StatusBadRequest
	default:
		return http.StatusBadRequest
	}
}

// safeErrorMessage returns a short, non-sensitive description of a failure for
// the audit `error_message` field. It maps the classified reason to a stable
// phrase rather than echoing raw err.Error(), which can carry variable detail.
func safeErrorMessage(err error) string {
	switch authFailureReason(err) {
	case "invalid_credentials":
		return "email or password is incorrect"
	case "invalid_client":
		return "invalid client credentials"
	case "email_not_verified":
		return "account email is not verified"
	case "invalid_or_expired_code":
		return "code is invalid or expired"
	case "too_many_attempts":
		return "too many attempts — temporarily locked"
	case "not_configured":
		return "feature not configured"
	case "":
		return ""
	default:
		return "authentication failed"
	}
}

// deriveStatus infers the outcome from the action name. Our action taxonomy
// already encodes failure in the verb, so the status column stays correct even
// when a call site does not set it explicitly.
func deriveStatus(action string) string {
	if action == audit.ActionAuthReplayDetected ||
		strings.HasSuffix(action, "_failed") ||
		strings.Contains(action, "challenge_failed") {
		return audit.StatusFailure
	}
	return audit.StatusSuccess
}

// applyFailure fills failure detail derived from err onto the event before it
// is enriched: outcome, the HTTP status served, and metadata error_code /
// error_message / reason. Only fills blanks, so an explicit call-site value
// (e.g. a specific status) always wins.
func applyFailure(e *audit.Event, err error) {
	e.Status = audit.StatusFailure
	if e.HTTPStatus == 0 {
		e.HTTPStatus = statusForError(err)
	}
	if e.Metadata == nil {
		e.Metadata = map[string]any{}
	}
	code := authFailureReason(err)
	if _, ok := e.Metadata["reason"]; !ok {
		e.Metadata["reason"] = code
	}
	if _, ok := e.Metadata["error_code"]; !ok {
		e.Metadata["error_code"] = code
	}
	if _, ok := e.Metadata["error_message"]; !ok {
		if msg := safeErrorMessage(err); msg != "" {
			e.Metadata["error_message"] = msg
		}
	}
}

// logOrStage enriches an event, then either stages it for response-body capture
// (when the AuditCapture middleware is active on this request) or logs it
// immediately (the fallback — e.g. tests without the middleware). Staged events
// are logged by the middleware once the real status + response body are known.
func logOrStage(c echo.Context, auditLog *audit.Logger, e audit.Event) {
	enrichAudit(c, &e)
	if !mw.StageAuditEvent(c, e) {
		auditLog.Log(c.Request().Context(), e)
	}
}

// auditEvent enriches and logs an event for the auth handler.
func (h *AuthHandler) auditEvent(c echo.Context, e audit.Event) {
	logOrStage(c, h.audit, e)
}

// auditFailure records a failed operation, distilling err into the status
// code, error_code, and a safe error_message before logging.
func (h *AuthHandler) auditFailure(c echo.Context, e audit.Event, err error) {
	applyFailure(&e, err)
	h.auditEvent(c, e)
}

// auditFailure records a failed operation for the admin handler.
func (h *AdminHandler) auditFailure(c echo.Context, e audit.Event, err error) {
	applyFailure(&e, err)
	h.auditEvent(c, e)
}

// auditFailure records a failed operation for the OAuth handler.
func (h *OAuthHandler) auditFailure(c echo.Context, e audit.Event, err error) {
	applyFailure(&e, err)
	h.auditEvent(c, e)
}

// auditEvent enriches and logs an event for the admin handler.
func (h *AdminHandler) auditEvent(c echo.Context, e audit.Event) {
	logOrStage(c, h.audit, e)
}

// auditEvent enriches and logs an event for the OAuth handler.
func (h *OAuthHandler) auditEvent(c echo.Context, e audit.Event) {
	logOrStage(c, h.audit, e)
}
