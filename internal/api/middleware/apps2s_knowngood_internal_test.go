package middleware

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

type oneSecret struct{ id, secret string }

func (o oneSecret) AuthenticateClient(_ context.Context, id, secret string) (int64, int64, error) {
	if id == o.id && secret == o.secret {
		return 7, 12, nil
	}
	return 0, 0, auth.ErrInvalidClient
}

func knownGoodLogin(t *testing.T, s *AppS2S, ip, id, secret string) int {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/apps/login", strings.NewReader(`{"email":"u@x.com"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(echo.HeaderAuthorization, "Basic "+base64.StdEncoding.EncodeToString([]byte(id+":"+secret)))
	req.RemoteAddr = ip + ":40000"
	rec := httptest.NewRecorder()
	_ = s.Resolve(SurfaceApp)(func(c echo.Context) error { return c.NoContent(http.StatusOK) })(e.NewContext(req, rec))
	return rec.Code
}

// Re-review B: a stranger who knows the public client_id exhausts its
// wrong-secret budget. The real backend, on an address where its secret
// verified recently but which is NOT a registered server IP, must still get
// through on an UNCACHED check — a cold instance, or the minute after the
// verified cache expired.
func TestKnownGoodAddressSurvivesStrangerLockout(t *testing.T) {
	ResetStoresForTest()
	s := NewAppS2S(AppS2SConfig{}, nil, oneSecret{"live-app", "real"}, zerolog.Nop())
	const backend = "203.0.113.10"

	if got := knownGoodLogin(t, s, backend, "live-app", "real"); got != http.StatusOK {
		t.Fatalf("first verification: %d", got)
	}
	for i := 0; i < DefaultBadCredentialsPerClientRate+5; i++ {
		knownGoodLogin(t, s, fmt.Sprintf("198.51.100.%d", 50+i), "live-app", "guess")
	}
	// Unknown addresses are now refused for this client_id…
	if got := knownGoodLogin(t, s, "198.51.100.250", "live-app", "real"); got != http.StatusTooManyRequests {
		t.Fatalf("right secret from an unknown address during the lockout: %d, want 429", got)
	}

	// …but the backend's own address is not. Force an uncached check.
	s.verified = newVerifiedClientCache(verifiedClientTTL, verifiedClientMax)
	if got := knownGoodLogin(t, s, backend, "live-app", "real"); got != http.StatusOK {
		t.Fatalf("real backend on its known-good address, uncached: %d, want 200", got)
	}
}
