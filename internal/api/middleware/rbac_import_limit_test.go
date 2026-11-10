package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
)

// The RBAC bulk routes have their own bucket. They used to share the audit
// compliance bucket, so a few validate calls used up the tenant's audit-export,
// user-import and GDPR-erase allowance and then answered "too many audit
// compliance requests".
func TestRBACImportRateLimiter_OwnBucketAndNeutralMessage(t *testing.T) {
	mw.ResetStoresForTest()
	t.Cleanup(mw.ResetStoresForTest)

	e := echo.New()
	ok := func(c echo.Context) error { return c.NoContent(http.StatusNoContent) }
	rbac := mw.RBACImportRateLimiter(2)
	audit := mw.AuditMaintenanceRateLimiter(2)

	call := func(h echo.MiddlewareFunc, appID string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("appID")
		c.SetParamValues(appID)
		_ = h(ok)(c)
		return rec
	}

	for i := 0; i < 2; i++ {
		if rec := call(rbac, "7"); rec.Code != http.StatusNoContent {
			t.Fatalf("request %d = %d, want 204", i+1, rec.Code)
		}
	}
	rec := call(rbac, "7")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third request = %d, want 429", rec.Code)
	}
	if strings.Contains(strings.ToLower(rec.Body.String()), "audit") {
		t.Errorf("429 body mentions audit: %s", rec.Body.String())
	}
	if rec.Header().Get("Retry-After") != "60" {
		t.Errorf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}

	// A different application has its own allowance.
	if rec := call(rbac, "8"); rec.Code != http.StatusNoContent {
		t.Errorf("other application = %d, want 204", rec.Code)
	}
	// And exhausting the RBAC bucket leaves the audit bucket untouched.
	if rec := call(audit, "7"); rec.Code != http.StatusNoContent {
		t.Errorf("audit bucket = %d, want 204 (separate from RBAC)", rec.Code)
	}
}
