package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// OIDCHandler serves the OpenID Connect endpoints that sit on top of the token
// layer: UserInfo (issue #7a, below) and the per-tenant discovery document
// (issue #7b, oidc_discovery.go).
//
// Discovery waited for issue #6 rather than shipping with UserInfo, because a
// discovery response must carry authorization_endpoint and token_endpoint, and
// publishing one that names routes returning 404 is worse than publishing none
// — a relying party that reads it configures itself against endpoints that do
// not exist and fails later, further from the cause. Both now exist.
type OIDCHandler struct {
	pool *pgxpool.Pool

	// issuers supplies the public origin every URL in the discovery document is
	// built from, and is the same resolver that stamps "iss" at mint time — so
	// the document's issuer and the tokens' issuer cannot be derived from two
	// different values. UserInfo does not use it.
	issuers *auth.TenantIssuerResolver

	logger zerolog.Logger
}

// NewOIDCHandler builds the handler.
func NewOIDCHandler(pool *pgxpool.Pool, issuers *auth.TenantIssuerResolver, logger zerolog.Logger) *OIDCHandler {
	return &OIDCHandler{pool: pool, issuers: issuers, logger: logger}
}

// UserInfoResponse is the OIDC UserInfo claim set (OIDC Core 1.0 §5.3).
//
// Field names are the standard claim names, not our internal ones — the point of
// this endpoint is that an off-the-shelf OIDC client can read it without
// per-vendor mapping. `omitempty` throughout because the spec says a claim with
// no value should be omitted rather than returned empty; a client that sees
// "name": "" would treat the empty string as the user's actual name.
type UserInfoResponse struct {
	// Subject is the stable, permanent identifier for the user.
	//
	// This is the raw user id, deliberately, and it must stay consistent with the
	// "sub" already carried in every access token (JWTService.Sign sets
	// Subject: c.UserID). OIDC Core requires the token's sub and UserInfo's sub to
	// match; returning a pairwise (per-client) subject here while tokens carry the
	// raw id would violate that and give the same person two identities.
	//
	// Pairwise subjects are the privacy-preserving alternative, keeping two
	// applications from correlating the same user. Adding them later means
	// changing BOTH this and the token claim, and is only safe for a client that
	// has never received a subject in the current format — a relying party stores
	// sub as its primary key for the user, so changing it orphans every linked
	// account. The natural place is a per-client setting introduced with the
	// client registry in issue #6/#8, applied from that client's first token.
	Subject string `json:"sub"`

	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`

	// UpdatedAt is seconds since the Unix epoch, per OIDC Core — not RFC 3339,
	// which is what the rest of this API returns for timestamps.
	UpdatedAt int64 `json:"updated_at,omitempty"`
}

// UserInfo handles GET and POST /oauth/userinfo.
//
// Both verbs because OIDC Core §5.3 requires a UserInfo endpoint to support GET
// and POST; a client library may use either, and refusing one would fail
// conformance for no benefit.
//
// The endpoint is authenticated by the access token alone and takes no tenant in
// the path: the tenant comes from the verified token, never from the request.
// That is the tenant-isolation rule stated in CLAUDE.md, and it is why this route
// needs no /tenants/{slug} prefix even though its issuer has one.
//
// Only AudienceAPI tokens reach here — enforced by the route's middleware, not by
// this handler. Machine (M2M), management, and agent tokens are refused because
// they represent no user, so there is no "info" to return; letting one through
// would mean answering a question about a user for a caller that never
// authenticated as one (issue #84).
//
// @Summary     OIDC UserInfo
// @Description Standard OpenID Connect UserInfo endpoint. Returns claims about the user behind the presented access token. Requires a user access token (aud=emc-auth-api); machine, management, and agent tokens are rejected.
// @Tags        oidc
// @Produce     json
// @Security    BearerAuth
// @Success     200  {object}  UserInfoResponse
// @Failure     401  {object}  map[string]string
// @Failure     500  {object}  map[string]string
// @Router      /oauth/userinfo [get]
func (h *OIDCHandler) UserInfo(c echo.Context) error {
	// UserInfo responses carry personal data and are per-token, so they must not
	// be stored by any intermediary. OIDC Core requires this.
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Pragma", "no-cache")

	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return h.unauthorized(c, "unauthorized")
	}

	userID, err := strconv.ParseInt(claims.UserID, 10, 64)
	if err != nil {
		// A verified token whose user_id is not an integer did not come from any
		// current mint path. Refuse rather than query with it.
		h.logger.Warn().Str("user_id", claims.UserID).Msg("userinfo: non-numeric user_id in a verified token")
		return h.unauthorized(c, "invalid subject")
	}
	tenantID, err := strconv.ParseInt(claims.TenantID, 10, 64)
	if err != nil {
		h.logger.Warn().Str("tenant_id", claims.TenantID).Msg("userinfo: non-numeric tenant_id in a verified token")
		return h.unauthorized(c, "invalid subject")
	}

	var (
		email     string
		firstName string
		lastName  string
		verified  bool
		updatedAt time.Time
		isActive  bool
		deletedAt *time.Time
	)
	// Scoped by tenant_id as well as id. The token is verified so its tenant claim
	// is trustworthy, but scoping the query means a mismatch cannot return another
	// tenant's row even if a user id were somehow reused across tenants.
	//
	// Soft deletion is deleted_at, not the is_deleted boolean that migration 00002
	// created — 00021 migrated the data across and dropped the column. Both names
	// appear in the migration history, so the wrong one reads plausibly and fails
	// only at runtime.
	err = h.pool.QueryRow(c.Request().Context(), `
		SELECT email, first_name, last_name, email_verified, updated_at, is_active, deleted_at
		FROM users
		WHERE id = $1 AND tenant_id = $2
	`, userID, tenantID).Scan(&email, &firstName, &lastName, &verified, &updatedAt, &isActive, &deletedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return h.unauthorized(c, "user not found")
	}
	if err != nil {
		h.logger.Error().Err(err).Int64("user_id", userID).Msg("userinfo: user lookup failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}

	// The user is re-checked on every call rather than trusted from the token.
	// An access token lives 15 minutes, so a user deactivated or soft-deleted a
	// moment ago still holds a valid one; without this, UserInfo would keep
	// answering for them until it expired. Soft-deleted users are never
	// hard-deleted (CLAUDE.md non-negotiable 5), so the row still exists and only
	// this flag distinguishes them.
	if !isActive || deletedAt != nil {
		return h.unauthorized(c, "user is not active")
	}

	// Scope filtering (OIDC Core §5.4), deferred to issue #6 by #7a's decision
	// log because no flow could grant a scope until the authorization code flow
	// existed — filtering then would have filtered on a field nothing set.
	//
	// Branch on PRESENCE of the claim, not its content. A token with no scope
	// claim is a first-party session (password login, refresh, MFA, magic link,
	// social, SAML) that predates or bypasses scopes entirely; it gets the full
	// claim set exactly as before. A token carrying a scope claim came through
	// /oauth/authorize, where the client asked for specific scopes and received
	// only what it was granted — releasing more than that here would hand a
	// client data it never requested and, once consent exists, was never
	// approved for. See Claims.Scope for why empty cannot mean "grants nothing".
	granted := claims.ScopeList()
	scoped := granted != nil

	resp := UserInfoResponse{Subject: claims.UserID}
	if !scoped || auth.HasScope(granted, auth.ScopeEmail) {
		resp.Email = email
		resp.EmailVerified = verified
	}
	if !scoped || auth.HasScope(granted, auth.ScopeProfile) {
		resp.GivenName = firstName
		resp.FamilyName = lastName
		resp.UpdatedAt = updatedAt.Unix()
		// "name" is the full display name. Built from the parts rather than
		// stored, and omitted entirely when both are empty so a client does not
		// receive a blank string as though it were a real name.
		if full := strings.TrimSpace(firstName + " " + lastName); full != "" {
			resp.Name = full
		}
	}

	return c.JSON(http.StatusOK, resp)
}

// unauthorized returns a 401 carrying the WWW-Authenticate challenge RFC 6750
// requires of an OAuth 2.0 protected resource.
//
// The rest of this API returns a bare JSON error, which is right for first-party
// callers. UserInfo is different: it is consumed by standard OIDC client
// libraries, and several treat a 401 without a challenge as a transport fault to
// retry rather than an invalid token to refresh.
func (h *OIDCHandler) unauthorized(c echo.Context, reason string) error {
	c.Response().Header().Set("WWW-Authenticate",
		`Bearer error="invalid_token", error_description="`+reason+`"`)
	return c.JSON(http.StatusUnauthorized, map[string]string{"error": reason})
}
