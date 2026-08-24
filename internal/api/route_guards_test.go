package api_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Every per-application admin route must be guarded per application.
//
// The bug this pins: a route naming :appID acts on ONE application, but nine of
// them were guarded with the tenant-wide helpers (RequireTenantSelfOrAny via
// tidAppsRead/tidAppsWrite/tidUsersRead/tidUsersWrite). Those pass
// allowAppScoped=false, so an application-scoped administrator — a co-owner,
// whose entire purpose is administering specific applications — was refused with
// "tenant-wide administration; this account administers specific applications
// only" on applications they legitimately administer. The Advanced (rate limit)
// and Connections (identity providers) tabs 403'd for every co-owner.
//
// Asserted against the source rather than by booting the router because the
// mistake is a guard CHOICE, not a runtime behaviour: RequireAppScope is already
// covered by its own tests, and what went wrong was reaching for the wrong helper
// while adding a route. This catches the next one at compile-time-ish speed, with
// no database.
// ---------------------------------------------------------------------------

// appScopedGuards are the helpers that check :appID against the caller's granted
// applications (all wrap mw.RequireAppScope).
var appScopedGuards = []string{
	"appAppsRead", "appAppsWrite",
	"appUsersRead", "appUsersWrite",
	"appRolesRead", "appRolesWrite",
	"appPermsRead", "appPermsWrite",
	"appIDAppsRead", "appIDAppsWrite",
	"RequireAppScope",
}

// routeLine matches a registered route and captures its path and the rest of the
// registration (handler plus middleware).
var routeLine = regexp.MustCompile(`\.(GET|POST|PUT|DELETE|PATCH)\("([^"]*)",(.*)$`)

func TestTenantScopedAppRoutesUseAppScopeGuard(t *testing.T) {
	src, err := os.ReadFile("routes.go")
	if err != nil {
		t.Fatalf("read routes.go: %v", err)
	}

	var offenders []string
	for i, line := range strings.Split(string(src), "\n") {
		m := routeLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		path, rest := m[2], m[3]

		// Only the canonical tenant-scoped family. The flat /applications/:appID
		// aliases resolve the tenant from the caller's own claims and are a
		// separate question — they are deliberately tenant-wide today, and the
		// frontend is being moved off them (see lib/api/rate-limits.ts).
		if !strings.HasPrefix(path, "/tenants/:tid/applications/:appID") {
			continue
		}

		guarded := false
		for _, g := range appScopedGuards {
			if strings.Contains(rest, g) {
				guarded = true
				break
			}
		}
		if !guarded {
			offenders = append(offenders, "routes.go:"+itoa(i+1)+"  "+strings.TrimSpace(line))
		}
	}

	if len(offenders) > 0 {
		t.Errorf("%d per-application route(s) are not guarded per application.\n"+
			"A route naming :appID must use an app-scope guard (appAppsRead, appUsersWrite, …),\n"+
			"not a tenant-wide one (tidAppsRead, tidUsersWrite, …), or every co-owner is\n"+
			"refused on an application they administer:\n\n%s",
			len(offenders), strings.Join(offenders, "\n"))
	}
}

// TestAppScopeGuardsExist guards the guard list above: if one of these helpers is
// renamed, the test would silently stop matching and pass regardless.
func TestAppScopeGuardsExist(t *testing.T) {
	src, err := os.ReadFile("routes.go")
	if err != nil {
		t.Fatalf("read routes.go: %v", err)
	}
	text := string(src)

	for _, g := range appScopedGuards {
		if g == "RequireAppScope" {
			continue // the middleware itself, not a local alias
		}
		if !strings.Contains(text, g+" :=") {
			t.Errorf("guard %q is in appScopedGuards but no longer defined in routes.go; "+
				"the audit above would silently stop covering routes that use it", g)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
