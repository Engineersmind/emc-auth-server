package admin

import (
	"context"
	"errors"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ErrSessionRevokeUnavailable is returned by RevokeApplicationSessions when the
// auth service is not wired. Unlike the single-session revoke there is no
// direct-write fallback: a bulk revoke that cannot deny the sessions' access
// tokens would report a sign-out that takes up to fifteen minutes to happen,
// which is exactly what an administrator pulling this lever is trying to avoid.
var ErrSessionRevokeUnavailable = errors.New("session revocation is not available on this server")

// RevokeApplicationSessions ends every live session of one application in the
// tenant (#196). See auth.AuthService.RevokeApplicationSessions. The caller must
// have verified that appRowID belongs to tenantID.
func (s *Service) RevokeApplicationSessions(ctx context.Context, tenantID, appRowID int64) (auth.AppSessionRevokeResult, error) {
	if s.authSvc == nil {
		return auth.AppSessionRevokeResult{}, ErrSessionRevokeUnavailable
	}
	return s.authSvc.RevokeApplicationSessions(ctx, tenantID, appRowID)
}
