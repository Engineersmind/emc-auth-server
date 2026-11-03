package auth

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// IntrospectionResult is an RFC 7662 introspection response.
//
// For any token that is not active the response is {"active": false} and
// nothing else: RFC 7662 §2.2 forbids revealing why, and a reason would turn
// the endpoint into an oracle for which tokens once existed.
type IntrospectionResult struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Username  string   `json:"username,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	Exp       int64    `json:"exp,omitempty"`
	Iat       int64    `json:"iat,omitempty"`
	Sub       string   `json:"sub,omitempty"`
	Aud       []string `json:"aud,omitempty"`
	Iss       string   `json:"iss,omitempty"`

	// EMC extensions — the same names the access token carries.
	Gty            string   `json:"gty,omitempty"`
	SessionID      string   `json:"sid,omitempty"`
	TenantID       string   `json:"tenant_id,omitempty"`
	AppID          string   `json:"app_id,omitempty"`
	Roles          []string `json:"roles,omitempty"`
	Permissions    []string `json:"permissions,omitempty"`
	OrgID          string   `json:"org_id,omitempty"`
	OrgName        string   `json:"org_name,omitempty"`
	OrgRoles       []string `json:"org_roles,omitempty"`
	OrgPermissions []string `json:"org_permissions,omitempty"`
}

var inactiveToken = &IntrospectionResult{Active: false}

// IntrospectionClient is the authenticated client asking.
type IntrospectionClient struct {
	ClientID string
	TenantID int64
	AppRowID int64
}

// Introspect answers whether a token is active RIGHT NOW, for the application
// it was issued to (RFC 7662).
//
// A JWT is self-contained and a relying party verifying it locally cannot see
// a revocation until the token expires. This is the live check for the moments
// that cannot wait — approving, revealing, sending: it consults the session
// denylist, the user's current status and, for an organisation token, the
// membership itself.
//
// A client may introspect only tokens issued to its own application. Another
// application's token answers inactive, exactly like a forged one, so one
// client cannot use the endpoint to learn about a sibling's users.
func (s *AuthService) Introspect(ctx context.Context, client IntrospectionClient, token, hint string) *IntrospectionResult {
	if token == "" {
		return inactiveToken
	}
	// token_type_hint only orders the lookups. RFC 7662 §2.1: if the hinted
	// type misses, the server MUST extend its search to the other types it
	// supports, so a wrong hint can never make a live token read inactive.
	if hint == "refresh_token" {
		if r := s.introspectRefreshToken(ctx, client, token); r.Active {
			return r
		}
		r, _ := s.introspectAccessToken(ctx, client, token)
		return r
	}
	if r, ok := s.introspectAccessToken(ctx, client, token); ok {
		return r
	}
	return s.introspectRefreshToken(ctx, client, token)
}

// introspectAccessToken returns ok=false when the token is not a verifiable
// JWT at all, so the caller can try it as a refresh token.
func (s *AuthService) introspectAccessToken(ctx context.Context, client IntrospectionClient, token string) (*IntrospectionResult, bool) {
	allowed := make([]string, 0, len(HumanGrants)+len(MachineGrants))
	allowed = append(append(allowed, HumanGrants...), MachineGrants...)
	claims, err := s.jwtSvc.VerifyForAudience(ctx, token, allowed...)
	if err != nil {
		// An expired or wrongly signed JWT is still recognisably a JWT; it is
		// inactive, not a candidate refresh token.
		return inactiveToken, looksLikeJWT(token)
	}
	if claims.AppID != strconv.FormatInt(client.AppRowID, 10) ||
		claims.TenantID != strconv.FormatInt(client.TenantID, 10) {
		return inactiveToken, true
	}

	var iat int64
	if claims.IssuedAt != nil {
		iat = claims.IssuedAt.Unix()
	}
	if s.SessionDenied(ctx, claims.SessionID, claims.UserID, claims.TenantID, iat) {
		return inactiveToken, true
	}

	if claims.Gty != GrantClientCredentials {
		uid, err := strconv.ParseInt(claims.UserID, 10, 64)
		if err != nil {
			return inactiveToken, true
		}
		// The session is checked here as well as through SessionDenied above,
		// because that denylist fails OPEN: with Redis down, or an entry lost, a
		// revoked session's unexpired token would still read active. PostgreSQL
		// is the durable record of the revocation; the denylist stays for the
		// account-wide cases (revoke-all, block, role change) that leave the
		// session row alone. A lookup failure answers inactive.
		var sessionID *int64
		if claims.SessionID != "" {
			sid, err := strconv.ParseInt(claims.SessionID, 10, 64)
			if err != nil {
				return inactiveToken, true
			}
			sessionID = &sid
		}
		var live bool
		if err := s.pool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM users
			               WHERE id = $1 AND tenant_id = $2 AND is_active = true AND deleted_at IS NULL)
			   AND ($3::BIGINT IS NULL OR EXISTS (
			            SELECT 1 FROM user_sessions s
			            WHERE s.id = $3 AND s.user_id = $1 AND s.tenant_id = $2
			              AND `+LiveSessionWhere("s.")+`))
		`, uid, client.TenantID, sessionID).Scan(&live); err != nil || !live {
			return inactiveToken, true
		}
		if claims.OrgID != "" && !s.orgSvc.memberActiveByPublicID(ctx, client.AppRowID, uid, claims.OrgID) {
			return inactiveToken, true
		}
	}

	r := &IntrospectionResult{
		Active: true, Scope: claims.Scope, ClientID: client.ClientID, Username: claims.Email,
		TokenType: "access_token", Iat: iat, Sub: claims.Subject, Aud: claims.Audience, Iss: claims.Issuer,
		Gty: claims.Gty, SessionID: claims.SessionID, TenantID: claims.TenantID, AppID: claims.AppID,
		Roles: claims.Roles, Permissions: claims.Permissions,
		OrgID: claims.OrgID, OrgName: claims.OrgName, OrgRoles: claims.OrgRoles, OrgPermissions: claims.OrgPermissions,
	}
	if claims.ExpiresAt != nil {
		r.Exp = claims.ExpiresAt.Unix()
	}
	if r.Sub == "" {
		r.Sub = claims.UserID
	}
	return r, true
}

func (s *AuthService) introspectRefreshToken(ctx context.Context, client IntrospectionClient, token string) *IntrospectionResult {
	var (
		userID, sessionID int64
		expiresAt         time.Time
		email             string
		orgID             *int64
	)
	err := s.pool.QueryRow(ctx, `
		SELECT s.user_id, s.id, rt.expires_at, u.email, s.organization_id
		FROM refresh_tokens rt
		JOIN user_sessions s ON s.id = rt.session_id
		JOIN users u ON u.id = s.user_id AND u.is_active = true AND u.deleted_at IS NULL
		WHERE rt.token_hash = $1
		  AND s.tenant_id = $2 AND s.application_id = $3
		  AND `+LiveTokenWhere("rt.")+`
		  AND `+LiveSessionWhere("s."),
		HashToken(token), client.TenantID, client.AppRowID).Scan(&userID, &sessionID, &expiresAt, &email, &orgID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.logger.Warn().Err(err).Msg("introspection: refresh token lookup failed")
		}
		return inactiveToken
	}
	r := &IntrospectionResult{
		Active: true, ClientID: client.ClientID, Username: email, TokenType: "refresh_token",
		Exp: expiresAt.Unix(), Sub: strconv.FormatInt(userID, 10), SessionID: strconv.FormatInt(sessionID, 10),
		TenantID: strconv.FormatInt(client.TenantID, 10), AppID: strconv.FormatInt(client.AppRowID, 10),
	}
	if orgID != nil {
		m, err := s.orgSvc.loadMintOrganization(ctx, *orgID, userID, client.AppRowID)
		if !s.orgSvc.Enabled() || err != nil {
			return inactiveToken
		}
		r.OrgID, r.OrgName = m.publicID, m.slug
	}
	return r
}

func looksLikeJWT(token string) bool {
	dots := 0
	for _, c := range token {
		if c == '.' {
			dots++
		}
	}
	return dots == 2
}

// memberActiveByPublicID reports whether the user is, right now, an active
// member of the active organisation with this public id in the application.
// False on any doubt, including the feature being switched off.
func (s *OrganizationService) memberActiveByPublicID(ctx context.Context, appRowID, userID int64, publicID string) bool {
	if !s.Enabled() {
		return false
	}
	var ok bool
	if err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM organizations o
			JOIN organization_members m ON m.organization_id = o.id
			WHERE o.public_id = $1 AND o.application_id = $2
			  AND o.deleted_at IS NULL AND o.is_active = true
			  AND m.user_id = $3 AND m.status = 'active')
	`, publicID, appRowID, userID).Scan(&ok); err != nil {
		s.logger.Warn().Err(err).Msg("introspection: membership check failed; answering inactive")
		return false
	}
	return ok
}
