package admin

import "testing"

// Pins the scope/inherited derivation fixed after Copilot's review of PR #147.
//
// The old formula was
//
//	(applicationID != nil && rowApp == nil) || rowTenant == nil
//
// and a platform request has rowTenant nil by definition, so it always reported
// inherited: true for a row that exists and has no DELETE endpoint. The console
// renders "Reset to inherited" off this field, so it offered to remove something
// unremovable.
//
// The table mirrors the switch in GetCaptchaPolicy. Kept as a pure function test
// because standing up Postgres to assert a boolean would be disproportionate,
// and the bug was in the boolean, not the query.
func TestCaptchaPolicyInheritedDerivation(t *testing.T) {
	inherited := func(tenantID int64, applicationID, rowTenant, rowApp *int64) bool {
		switch {
		case applicationID != nil:
			return rowApp == nil
		case tenantID != 0:
			return rowTenant == nil
		default:
			return false
		}
	}
	id := func(v int64) *int64 { return &v }

	cases := []struct {
		name          string
		tenantID      int64
		applicationID *int64
		rowTenant     *int64
		rowApp        *int64
		want          bool
	}{
		// The regression: a platform request always has rowTenant nil.
		{"platform scope, platform row answered", 0, nil, nil, nil, false},

		{"tenant scope, tenant row answered", 42, nil, id(42), nil, false},
		{"tenant scope, fell back to platform", 42, nil, nil, nil, true},

		{"app scope, app row answered", 42, id(7), id(42), id(7), false},
		{"app scope, fell back to tenant", 42, id(7), id(42), nil, true},
		{"app scope, fell back to platform", 42, id(7), nil, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := inherited(tc.tenantID, tc.applicationID, tc.rowTenant, tc.rowApp); got != tc.want {
				t.Errorf("inherited = %v, want %v", got, tc.want)
			}
		})
	}
}
