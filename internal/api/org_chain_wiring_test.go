package api_test

import (
	"os"
	"strings"
	"testing"
)

// The organisation routes must be wired through the shared chain builders, which
// the middleware tests exercise. Read from the source, like route_guards_test.go,
// so a route rewired inline (and so no longer covered) fails here.
func TestOrgRoutesUseTheSharedChainBuilders(t *testing.T) {
	src, err := os.ReadFile("routes.go")
	if err != nil {
		t.Fatalf("read routes.go: %v", err)
	}
	s := string(src)
	for _, want := range []string{
		"mw.OrgFlowChain(s2s,",
		`authGroup.Group("/apps/organizations", mw.AppOrgManagementChain(s2s,`,
		`"/apps/users/:uid/organizations", orgHandler.ListUserOrganizations(appOrgScope),` + "\n\t\tmw.AppOrgManagementChain(s2s,",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("routes.go no longer contains %q", want)
		}
	}
	// The end-user org-flow routes each go through orgFlowChain.
	for _, route := range []string{"/apps/login/organization", "/apps/switch-organization",
		"/apps/organizations/invitations/preview", "/apps/organizations/invitations/accept"} {
		i := strings.Index(s, `"`+route+`"`)
		if i < 0 {
			t.Errorf("route %s not found", route)
			continue
		}
		end := i + 300
		if end > len(s) {
			end = len(s)
		}
		if !strings.Contains(s[i:end], "orgFlowChain(") {
			t.Errorf("route %s is not wired through orgFlowChain", route)
		}
	}
}
