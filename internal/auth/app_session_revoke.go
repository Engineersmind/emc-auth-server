package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/engineersmind/emc-auth-server/internal/metrics"
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

// MaxAppSessionRevokePerCall bounds how many sessions one call of
// RevokeApplicationSessions ends. The revocations run serially inside the
// request, one short transaction each, so without a bound an application with
// tens of thousands of live sessions could outlast an HTTP or proxy timeout
// partway through. A call that hits the bound reports Remaining > 0 and the
// administrator repeats it until Remaining is 0. Deliberately a constant: the
// bound is about request duration, not policy.
const MaxAppSessionRevokePerCall = 1000

// appSessionDenyTTLMargin pads the re-denial TTL computed from the database
// clock, so a small skew between the database and the servers that check
// access-token expiry cannot let a token outlive its denylist entry.
const appSessionDenyTTLMargin = 30 * time.Second

// ErrSessionDenylistUnavailable refuses the bulk application revoke on a
// deployment without Redis. Revoking the rows would stop every refresh, but
// the sessions' outstanding access tokens would stay valid for up to
// AccessTokenTTL — and a later retry could not repair that, because the rows
// would no longer be live. Reporting that as a completed sign-out is exactly
// what an administrator pulling this lever must not be told.
var ErrSessionDenylistUnavailable = errors.New("revoking every session of an application needs the session denylist (Redis), which this server does not have")

// AppSessionRevokeResult reports what RevokeApplicationSessions did.
type AppSessionRevokeResult struct {
	// Revoked is the number of sessions this call ended.
	Revoked int `json:"revoked"`
	// Failed is the number of sessions whose revocation errored. Each is logged
	// and stays live, so it is counted in Remaining and retried by the next call.
	Failed int `json:"failed"`
	// DenyFailed is the number of sessions revoked by this action within the
	// last AccessTokenTTL whose access-token denial could not be written. Their
	// refresh is already stopped, but an access token they hold stays valid
	// until it expires. The next call re-denies them.
	DenyFailed int `json:"deny_failed"`
	// Remaining is the number of the application's sessions still live after
	// this call: those beyond MaxAppSessionRevokePerCall and those that failed.
	Remaining int `json:"remaining"`
	// Complete is true only when every session is signed out: nothing remains
	// live and every denial landed. Anything else is worth repeating the call.
	Complete bool `json:"complete"`
}

// RevokeApplicationSessions ends up to MaxAppSessionRevokePerCall live sessions
// of the application appRowID inside tenantID: application users and
// tenant-level users who signed in through it alike, since both hold a session
// bound to the application (user_sessions.application_id).
//
// Three steps:
//  1. revoke each session's row and refresh tokens (revokeSessionDB);
//  2. deny the outstanding access tokens in Redis of EVERY session this action
//     revoked within the last AccessTokenTTL — not only this call's. That is
//     the retry path for a denial write that failed on an earlier call, or that
//     never ran because the earlier request was cut off between steps 1 and 2:
//     those sessions are no longer live, so step 1 would never see them again;
//  3. count what is still live.
//
// Refused up front with ErrSessionDenylistUnavailable when this deployment has
// no Redis: step 2 could not run at all.
//
// The caller must have verified that appRowID belongs to tenantID (handlers
// use applicationOwnedByTenant); tenant_id is still pinned in every query so
// the action can never reach another tenant's sessions. A listing error is
// returned rather than read as "nothing to revoke".
func (s *AuthService) RevokeApplicationSessions(ctx context.Context, tenantID, appRowID int64) (AppSessionRevokeResult, error) {
	var res AppSessionRevokeResult
	if s.redisCli == nil {
		return res, ErrSessionDenylistUnavailable
	}

	rows, err := s.listSessionRows(ctx, `
		SELECT id, user_id, tenant_id FROM user_sessions
		WHERE application_id = $1 AND tenant_id = $2
		  AND `+LiveSessionWhere("")+`
		ORDER BY id
		LIMIT $3`,
		appRowID, tenantID, MaxAppSessionRevokePerCall)
	if err != nil {
		return res, fmt.Errorf("list application sessions: %w", err)
	}
	for _, r := range rows {
		n, rErr := s.revokeSessionDB(ctx, r.userID, r.tenantID, r.id, RevokeReasonAdminAppRevokeAll)
		if rErr != nil {
			res.Failed++
			s.logger.Error().Err(rErr).Int64("session_id", r.id).Int64("application_id", appRowID).
				Msg("app session revoke: session revocation failed; it stays live and is retried by the next call")
			continue
		}
		res.Revoked += int(n)
	}

	if res.DenyFailed, err = s.denyRecentAppRevocations(ctx, tenantID, appRowID); err != nil {
		return res, err
	}

	if err = s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM user_sessions
		WHERE application_id = $1 AND tenant_id = $2 AND `+LiveSessionWhere(""),
		appRowID, tenantID).Scan(&res.Remaining); err != nil {
		return res, fmt.Errorf("count remaining application sessions: %w", err)
	}
	res.Complete = res.Remaining == 0 && res.Failed == 0 && res.DenyFailed == 0
	return res, nil
}

// denyRecentAppRevocations writes the access-token denylist entry of every
// session the bulk action revoked for this application within the last
// AccessTokenTTL — the only window in which such a session can still hold a
// usable access token — with the TTL that token has left. Rewriting an entry
// that already exists is harmless, so the pass is idempotent and needs no
// record of which earlier writes failed. Returns how many writes failed.
func (s *AuthService) denyRecentAppRevocations(ctx context.Context, tenantID, appRowID int64) (int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, EXTRACT(EPOCH FROM (NOW() - revoked_at))::FLOAT8
		FROM user_sessions
		WHERE application_id = $1 AND tenant_id = $2 AND revoked_reason = $3
		  AND revoked_at > NOW() - make_interval(secs => $4)
	`, appRowID, tenantID, RevokeReasonAdminAppRevokeAll, AccessTokenTTL.Seconds())
	if err != nil {
		return 0, fmt.Errorf("list recently revoked application sessions: %w", err)
	}
	type pending struct {
		id  int64
		ttl time.Duration
	}
	var toDeny []pending
	for rows.Next() {
		var id int64
		var ageSecs float64
		if err := rows.Scan(&id, &ageSecs); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan recently revoked application session: %w", err)
		}
		ttl := AccessTokenTTL - time.Duration(ageSecs*float64(time.Second)) + appSessionDenyTTLMargin
		if ttl > 0 {
			toDeny = append(toDeny, pending{id: id, ttl: ttl})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate recently revoked application sessions: %w", err)
	}
	if len(toDeny) == 0 {
		return 0, nil
	}

	// One round trip per chunk rather than per session.
	const chunk = 500
	failed := 0
	for start := 0; start < len(toDeny); start += chunk {
		end := min(start+chunk, len(toDeny))
		pipe := s.redisCli.Pipeline()
		cmds := make([]*redis.StatusCmd, 0, end-start)
		for _, p := range toDeny[start:end] {
			cmds = append(cmds, pipe.Set(ctx, sessionDenyKey(p.id), "1", p.ttl))
		}
		// Exec reports the first failure; each command carries its own, which is
		// what is counted.
		if _, execErr := pipe.Exec(ctx); execErr != nil {
			s.logger.Warn().Err(execErr).Int64("application_id", appRowID).
				Msg("app session revoke: denylist write failed; the next call retries it")
		}
		for _, cmd := range cmds {
			if cmd.Err() != nil {
				failed++
				metrics.SessionDenylistErrors.WithLabelValues("write").Inc()
			}
		}
	}
	return failed, nil
}
