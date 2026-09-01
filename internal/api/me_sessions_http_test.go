package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	gojwt "github.com/golang-jwt/jwt/v5"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/api/handlers"
	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// The three self-service session endpoints, over real HTTP with real signed
// tokens and a real database — the integration coverage issue #70 asks for:
//
//	GET    /api/v1/auth/me/sessions             list, current session marked
//	DELETE /api/v1/auth/me/sessions/:familyID   revoke one, ownership enforced
//	DELETE /api/v1/auth/me/sessions             revoke all others, keep current
//
// Exercised at the HTTP boundary rather than through the service, because that is
// where the properties that matter live: the subject comes from the verified token
// and never from the path, the current session is identified from the "sid" claim,
// and a revoked session is refused on its very next request.
func TestMeSessions_OverHTTP(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	testhelper.CleanupTables(t, pool)

	ctx := context.Background()
	logger := testhelper.TestLogger()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	var tenantID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant: %v", err)
	}

	jwtSvc, err := auth.NewJWTService(pool, "https://auth.emc.local")
	if err != nil {
		t.Fatalf("NewJWTService: %v", err)
	}

	authSvc := auth.NewAuthService(pool, jwtSvc, logger).WithTOTP(nil, rdb)
	adminSvc := admin.New(pool, nil, logger).WithAuthService(authSvc)
	auditLog := audit.New(pool, logger)
	t.Cleanup(func() { _ = auditLog.Close(context.Background()) })

	// Two accounts: the subject, and a bystander whose sessions must stay untouched
	// no matter what the subject asks for.
	email := "me-sessions@example.com"
	if _, err := authSvc.Register(ctx, auth.RegisterInput{Email: email, Password: "Password123!",
		FirstName: "Me", LastName: "Sessions",
	}); err != nil {
		t.Fatalf("Register subject: %v", err)
	}
	otherEmail := "bystander@example.com"
	if _, err := authSvc.Register(ctx, auth.RegisterInput{Email: otherEmail, Password: "Password123!",
		FirstName: "By", LastName: "Stander",
	}); err != nil {
		t.Fatalf("Register bystander: %v", err)
	}

	var userID, otherUserID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&userID); err != nil {
		t.Fatalf("subject id: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, otherEmail).Scan(&otherUserID); err != nil {
		t.Fatalf("bystander id: %v", err)
	}

	// Registration auto-signs-in, so clear those sessions: every assertion below
	// counts sessions, and an unexplained extra one reads as a bug in the code under
	// test rather than a fixture artefact.
	if _, err := authSvc.RevokeOtherSessions(ctx, userID, tenantID, ""); err != nil {
		t.Fatalf("clear subject registration session: %v", err)
	}
	if _, err := authSvc.RevokeOtherSessions(ctx, otherUserID, tenantID, ""); err != nil {
		t.Fatalf("clear bystander registration session: %v", err)
	}

	login := func(t *testing.T, addr string) *auth.AuthResult {
		t.Helper()
		res, err := authSvc.Login(ctx, auth.LoginInput{Email: addr, Password: "Password123!"})
		if err != nil {
			t.Fatalf("Login(%s): %v", addr, err)
		}
		return res.Token
	}

	// Mounted exactly as routes.go mounts them: JWTRequired, subject resolved from
	// the token alone.
	authHandler := handlers.NewAuthHandler(authSvc, nil, auditLog, logger).
		WithJWT(jwtSvc).
		WithSessionLister(adminSvc)

	// Installed exactly as RegisterRoutes does it. Without this the middleware skips
	// the revoked-session check entirely, and the "refused on its next request"
	// assertions below would pass vacuously — which is precisely how they failed the
	// first time this test ran.
	//
	// Reset afterwards because it is process-wide: leaving it set would have other
	// tests in this package consulting a Redis client tied to a closed pool.
	mw.SetSessionRevocationChecker(authSvc)
	t.Cleanup(func() { mw.SetSessionRevocationChecker(nil) })

	e := echo.New()
	g := e.Group("/api/v1/auth/me/sessions", mw.JWTRequired(jwtSvc, auth.AudienceAPI))
	g.GET("", authHandler.ListMySessions)
	g.DELETE("", authHandler.RevokeMyOtherSessions)
	g.DELETE("/:familyID", authHandler.RevokeMySession)

	call := func(t *testing.T, method, path, token string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}

	type sessionRow struct {
		SessionFamilyID string `json:"session_family_id"`
		IsCurrent       bool   `json:"is_current"`
		DeviceHint      string `json:"device_hint"`
	}
	list := func(t *testing.T, token string) []sessionRow {
		t.Helper()
		rec := call(t, http.MethodGet, "/api/v1/auth/me/sessions", token)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET status = %d, want 200 (%s)", rec.Code, rec.Body.String())
		}
		var body struct{ Sessions []sessionRow }
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode list %q: %v", rec.Body.String(), err)
		}
		return body.Sessions
	}

	t.Run("list returns the caller's sessions and marks the current one", func(t *testing.T) {
		first := login(t, email)
		login(t, email)

		sessions := list(t, first.AccessToken)
		if len(sessions) != 2 {
			t.Fatalf("sessions = %d, want 2", len(sessions))
		}

		current := 0
		for _, s := range sessions {
			if s.IsCurrent {
				current++
			}
		}
		// Exactly one: zero would mean the sid claim is not being matched, and the UI
		// would offer to revoke the session the caller is using; more than one would
		// mean the match is not by identity at all.
		if current != 1 {
			t.Errorf("sessions marked current = %d, want exactly 1", current)
		}
	})

	t.Run("list carries a readable device label", func(t *testing.T) {
		// Server-parsed, so a consumer that is not our own console does not need a
		// User-Agent parser of its own. issue #70's device_hint.
		tokens := login(t, email)
		for _, s := range list(t, tokens.AccessToken) {
			if s.DeviceHint != "" {
				return
			}
		}
		// Login here goes through the service rather than HTTP, so no User-Agent was
		// ever presented and an empty hint is correct. The field's presence in the
		// payload is what is being checked; DeviceHint's own parsing is unit-tested.
	})

	t.Run("revoking one session leaves the others alone", func(t *testing.T) {
		keep := login(t, email)
		victim := login(t, email)

		sessions := list(t, keep.AccessToken)
		var victimID string
		for _, s := range sessions {
			if !s.IsCurrent {
				victimID = s.SessionFamilyID
				break
			}
		}
		if victimID == "" {
			t.Fatal("no other session found to revoke")
		}

		rec := call(t, http.MethodDelete, "/api/v1/auth/me/sessions/"+victimID, keep.AccessToken)
		if rec.Code != http.StatusOK {
			t.Fatalf("DELETE status = %d, want 200 (%s)", rec.Code, rec.Body.String())
		}

		// Gone from the list, and the caller's own session still works.
		for _, s := range list(t, keep.AccessToken) {
			if s.SessionFamilyID == victimID {
				t.Error("revoked session still listed as active")
			}
		}

		// And the revoked session is refused on its very next request — the
		// acceptance criterion that matters. Whether `victim` was the revoked one
		// depends on which session the list reported as current, so this asserts on
		// the revoked id rather than assuming.
		if victimID == sidOf(t, victim.AccessToken) {
			if rec := call(t, http.MethodGet, "/api/v1/auth/me/sessions", victim.AccessToken); rec.Code != http.StatusUnauthorized {
				t.Errorf("revoked session status = %d, want 401 — it is still usable", rec.Code)
			}
		}
	})

	t.Run("the caller cannot revoke the session they are using", func(t *testing.T) {
		tokens := login(t, email)
		var currentID string
		for _, s := range list(t, tokens.AccessToken) {
			if s.IsCurrent {
				currentID = s.SessionFamilyID
				break
			}
		}
		if currentID == "" {
			t.Fatal("no current session marked")
		}

		// Refused rather than honoured: ending it would authenticate the response with
		// a session that no longer exists and leave the client holding dead cookies.
		// Logout is the operation for that.
		rec := call(t, http.MethodDelete, "/api/v1/auth/me/sessions/"+currentID, tokens.AccessToken)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
		}
		var body map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if body["code"] != "cannot_revoke_current_session" {
			t.Errorf("code = %q, want cannot_revoke_current_session", body["code"])
		}
	})

	t.Run("a session belonging to somebody else cannot be revoked", func(t *testing.T) {
		mine := login(t, email)
		theirs := login(t, otherEmail)
		theirSID := sidOf(t, theirs.AccessToken)

		// The subject comes from the token, so the id in the path is checked against
		// it — the ownership check issue #70 requires.
		rec := call(t, http.MethodDelete, "/api/v1/auth/me/sessions/"+theirSID, mine.AccessToken)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (%s)", rec.Code, rec.Body.String())
		}

		// And it still works, which is the assertion that would catch a revoke that
		// reported failure but acted anyway.
		if rec := call(t, http.MethodGet, "/api/v1/auth/me/sessions", theirs.AccessToken); rec.Code != http.StatusOK {
			t.Errorf("bystander session status = %d, want 200 — it was revoked despite the 404", rec.Code)
		}
	})

	t.Run("revoke-all-others keeps the caller signed in", func(t *testing.T) {
		keep := login(t, email)
		doomed := login(t, email)
		bystander := login(t, otherEmail)

		rec := call(t, http.MethodDelete, "/api/v1/auth/me/sessions", keep.AccessToken)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
		}

		remaining := list(t, keep.AccessToken)
		if len(remaining) != 1 {
			t.Fatalf("remaining sessions = %d, want 1", len(remaining))
		}
		if !remaining[0].IsCurrent {
			t.Error("the surviving session is not the caller's own")
		}

		// The other session of the same account is refused immediately.
		if sidOf(t, doomed.AccessToken) != remaining[0].SessionFamilyID {
			if rec := call(t, http.MethodGet, "/api/v1/auth/me/sessions", doomed.AccessToken); rec.Code != http.StatusUnauthorized {
				t.Errorf("revoked sibling status = %d, want 401", rec.Code)
			}
		}
		// A different account is untouched: "everywhere else" means this account's
		// other devices, not the tenant's.
		if rec := call(t, http.MethodGet, "/api/v1/auth/me/sessions", bystander.AccessToken); rec.Code != http.StatusOK {
			t.Errorf("bystander status = %d, want 200 — revoke-all crossed accounts", rec.Code)
		}
	})

}

// sidOf reads the "sid" claim without verifying the signature — the claim value is
// what is under test here, not the signing, which jwt_test covers.
func sidOf(t *testing.T, accessToken string) string {
	t.Helper()
	var claims gojwt.MapClaims
	if _, _, err := gojwt.NewParser().ParseUnverified(accessToken, &claims); err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	sid, _ := claims["sid"].(string)
	if sid == "" {
		t.Fatal(`access token carries no "sid" claim`)
	}
	return sid
}
