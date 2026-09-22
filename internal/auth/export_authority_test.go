package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// Test seam for the tenant-authority rules.
//
// The authority tests live in package auth_test and previously executed a
// verbatim COPY of the production SQL, which meant a change to service.go alone
// left them green — the copied constant was untouched, so the "mutation test"
// only ever proved the copy was self-consistent. Raised in review on #143.
//
// These wrappers let those tests drive the real implementations. The SQL copies
// are kept alongside as a second signal: they catch a semantic drift between
// the two rules that a behavioural test would not notice, while these catch the
// case the copies cannot.
//
// In an _test.go file, so nothing here is compiled into the binary.

// ExportedLoadPermissions calls the production loadPermissions.
func ExportedLoadPermissions(pool *pgxpool.Pool, logger zerolog.Logger, ctx context.Context, userID, tenantID int64) ([]string, error) {
	return NewAuthService(pool, nil, logger).loadPermissions(ctx, userID, tenantID)
}

// ExportedPermissionsForRefresh calls the production permissionsForRefresh —
// the branch that keeps a rotation from silently changing what a session can
// do.
func ExportedPermissionsForRefresh(pool *pgxpool.Pool, logger zerolog.Logger, ctx context.Context, userID, tenantID int64) ([]string, error) {
	return NewAuthService(pool, nil, logger).permissionsForRefresh(ctx, userID, tenantID)
}

// ExportedCheckGraceWindow calls the production checkGraceWindow.
//
// Exported so a test can assert what the CALL SITE resolves rather than what
// permissionsForRefresh resolves in isolation. That distinction is the whole
// point: permissionsForRefresh was already correct and already covered, while
// this path and Refresh still called loadPermissions, so every existing test
// passed with the bug in place (raised in review on #143).
//
// This one matters most of the three — GraceResult.Permissions is applied to
// the in-flight request directly through graceToAuthClaims, with no token
// minting or signature verification in between.
func ExportedCheckGraceWindow(pool *pgxpool.Pool, logger zerolog.Logger, ctx context.Context, userID, tenantID, sessionID int64) ([]string, error) {
	res, err := NewAuthService(pool, nil, logger).checkGraceWindow(ctx, userID, tenantID, sessionID)
	if err != nil {
		return nil, err
	}
	return res.Permissions, nil
}

// ExportedRefreshUserLoad runs the refresh path's user load — the WHERE clause
// that decides whether a rotation may proceed at all — and reports whether the
// user was found for this tenant.
//
// Calls the production helper rather than a copy, so changing the predicate in
// service.go changes what this returns.
func ExportedRefreshUserLoad(pool *pgxpool.Pool, logger zerolog.Logger, ctx context.Context, userID, tenantID int64) (bool, error) {
	s := NewAuthService(pool, nil, logger)
	found, err := s.refreshUserHasAuthority(ctx, userID, tenantID)
	return found, err
}
