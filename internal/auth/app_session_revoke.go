package auth

import (
	"context"
	"fmt"
)

// ---------------------------------------------------------------------------
// Admin action: revoke every session of one application (#196, #189 backlog)
//
// A change to an application's MFA policy applies at each user's NEXT login.
// Sessions minted while MFA was off would otherwise keep refreshing for up to
// JWT_REFRESH_TTL. This is the manual lever an administrator pulls after
// tightening the policy to force every user through it now. Deliberately
// manual: a policy change never revokes sessions by itself.
// ---------------------------------------------------------------------------

// RevokeReasonAdminAppRevokeAll — an administrator ended every live session of
// one application at once (#196), typically right after tightening its MFA
// policy.
const RevokeReasonAdminAppRevokeAll = "admin_app_revoke_all"

// AppSessionRevokeResult reports what RevokeApplicationSessions did.
type AppSessionRevokeResult struct {
	// Revoked is the number of sessions actually ended.
	Revoked int `json:"revoked"`
	// Failed is the number of sessions whose revocation errored. Each is logged;
	// such a session still ends at its next refresh only if some other control
	// stops it, so a non-zero value is worth retrying the action for.
	Failed int `json:"failed"`
}

// RevokeApplicationSessions ends every live session of the application appRowID
// inside tenantID: application users and tenant-level users who signed in
// through it alike, since both hold a session bound to the application
// (user_sessions.application_id). Each session goes through revokeSession, so
// its refresh tokens are revoked and its outstanding access tokens denied in
// Redis after the commit.
//
// The caller must have verified that appRowID belongs to tenantID (handlers
// use applicationOwnedByTenant); tenant_id is still pinned in the query so the
// action can never reach another tenant's sessions. A listing error is
// returned rather than read as "nothing to revoke".
func (s *AuthService) RevokeApplicationSessions(ctx context.Context, tenantID, appRowID int64) (AppSessionRevokeResult, error) {
	rows, err := s.listSessionRows(ctx, `
		SELECT id, user_id, tenant_id FROM user_sessions
		WHERE application_id = $1 AND tenant_id = $2
		  AND `+LiveSessionWhere(""),
		appRowID, tenantID)
	if err != nil {
		return AppSessionRevokeResult{}, fmt.Errorf("list application sessions: %w", err)
	}
	revoked, failed := s.revokeSessionRowsReason(ctx, rows, RevokeReasonAdminAppRevokeAll)
	return AppSessionRevokeResult{Revoked: revoked, Failed: failed}, nil
}
