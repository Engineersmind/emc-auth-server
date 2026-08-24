package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// LoadAdminScopeFromGrantsForTest exposes the admin_grants resolver to the
// external auth_test package.
//
// The resolver itself stays unexported: it is one half of a flagged pair (see
// resolveAdminScope) and callers outside this package must not be able to pick a
// model, or the flag stops being the single point of control. Tests need it
// directly because they assert on the NEW model's answer specifically, which is
// exactly what resolveAdminScope hides while ADMIN_GRANTS_ENABLED is off.
func LoadAdminScopeFromGrantsForTest(ctx context.Context, pool *pgxpool.Pool, userID, tenantID int64) (string, []string, error) {
	return loadAdminScopeFromGrants(ctx, pool, userID, tenantID)
}

// LoadAdminScopeLegacyForTest exposes the 00062 resolver, so a test can assert
// the two models agree — the same property the shadow comparison checks in
// production.
func LoadAdminScopeLegacyForTest(ctx context.Context, pool *pgxpool.Pool, userID, tenantID int64) (string, []string, error) {
	return loadAdminScope(ctx, pool, userID, tenantID)
}

// AdminScopeDiffForTest exposes the comparison used by the shadow pass.
func AdminScopeDiffForTest(legacyScope string, legacyApps []string, newScope string, newApps []string) string {
	return adminScopeDiff(legacyScope, legacyApps, newScope, newApps)
}
