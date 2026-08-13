package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Issue #7: GET/POST /oauth/userinfo — the OIDC UserInfo endpoint.
//
// Audience enforcement lives in the route's JWTRequired middleware and is covered
// in middleware/jwt_test.go, so these tests set claims directly via
// c.Set("user", …) — exactly what that middleware does on success — and exercise
// what the handler itself decides: subject format, claim shape, and whether the
// user behind an already-valid token is still entitled to an answer.
//
// The last one is the part that is easy to get wrong. An access token lives 15
// minutes, so a user deactivated a moment ago still holds a valid one.
// ---------------------------------------------------------------------------

type userInfoFixture struct {
	handler  *OIDCHandler
	pool     *pgxpool.Pool
	ctx      context.Context
	tenantID int64
	userID   int64
	email    string
}

func newUserInfoFixture(t *testing.T) *userInfoFixture {
	t.Helper()

	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)

	ctx := context.Background()
	logger := testhelper.TestLogger()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	f := &userInfoFixture{
		handler: NewOIDCHandler(pool, nil, logger),
		pool:    pool,
		ctx:     ctx,
		email:   "admin@emc.local",
	}
	if err := pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`,
	).Scan(&f.tenantID); err != nil {
		t.Fatalf("fetch seed tenant: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT id FROM users WHERE email = $1 AND deleted_at IS NULL`, f.email,
	).Scan(&f.userID); err != nil {
		t.Fatalf("fetch seed user: %v", err)
	}
	return f
}

// claims builds the claim set JWTRequired would have placed in the context.
func (f *userInfoFixture) claims() *auth.Claims {
	return &auth.Claims{
		UserID:   strconv.FormatInt(f.userID, 10),
		TenantID: strconv.FormatInt(f.tenantID, 10),
		Email:    f.email,
		Role:     "super_admin",
	}
}

// call invokes the handler with the given claims (nil = unauthenticated context).
func (f *userInfoFixture) call(t *testing.T, method string, claims *auth.Claims) (*httptest.ResponseRecorder, UserInfoResponse) {
	t.Helper()

	e := echo.New()
	req := httptest.NewRequest(method, "/oauth/userinfo", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	if claims != nil {
		c.Set("user", claims)
	}

	if err := f.handler.UserInfo(c); err != nil {
		t.Fatalf("UserInfo returned a transport error: %v", err)
	}

	var out UserInfoResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode body %q: %v", rec.Body.String(), err)
		}
	}
	return rec, out
}

// TestUserInfo_ReturnsStandardClaims pins the response shape. The names are the
// OIDC standard claim names, which is the entire point — a stock client library
// reads them without per-vendor mapping, so renaming one is a breaking change to
// every integrator, not an internal refactor.
func TestUserInfo_ReturnsStandardClaims(t *testing.T) {
	f := newUserInfoFixture(t)

	rec, body := f.call(t, http.MethodGet, f.claims())

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if body.Subject != strconv.FormatInt(f.userID, 10) {
		t.Errorf("sub = %q, want the raw user id %d", body.Subject, f.userID)
	}
	if body.Email != f.email {
		t.Errorf("email = %q, want %q", body.Email, f.email)
	}
	if body.UpdatedAt <= 0 {
		t.Errorf("updated_at = %d, want a positive Unix timestamp", body.UpdatedAt)
	}

	// Raw JSON check: the struct would happily decode a payload using the wrong
	// key names, so assert on the wire format a client actually sees.
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	for _, key := range []string{"sub", "email", "email_verified"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("response is missing the required claim %q: %s", key, rec.Body.String())
		}
	}
}

// TestUserInfo_SubjectMatchesTokenSubject is the load-bearing assertion behind the
// "raw user id, not pairwise" decision.
//
// OIDC Core requires UserInfo's sub to equal the sub in the token that
// authenticated the call. JWTService.Sign already sets Subject: c.UserID, so
// returning anything else here — a pairwise hash, an email, a UUID — would give
// the same person two identities and break every compliant client.
func TestUserInfo_SubjectMatchesTokenSubject(t *testing.T) {
	f := newUserInfoFixture(t)

	claims := f.claims()
	_, body := f.call(t, http.MethodGet, claims)

	if body.Subject != claims.UserID {
		t.Errorf("userinfo sub = %q, token sub = %q — OIDC requires these to match",
			body.Subject, claims.UserID)
	}
}

// TestUserInfo_AcceptsPostAsWellAsGet — OIDC Core §5.3 requires both verbs, and a
// client library may use either.
func TestUserInfo_AcceptsPostAsWellAsGet(t *testing.T) {
	f := newUserInfoFixture(t)

	rec, body := f.call(t, http.MethodPost, f.claims())

	if rec.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if body.Subject == "" {
		t.Error("POST returned an empty sub")
	}
}

// TestUserInfo_NoClaims401 covers the defensive branch. The route sits behind
// JWTRequired so this should be unreachable, but a handler that dereferences a
// missing context value panics rather than refusing, and a panic on an
// unauthenticated path is a denial-of-service primitive.
func TestUserInfo_NoClaims401(t *testing.T) {
	f := newUserInfoFixture(t)

	rec, _ := f.call(t, http.MethodGet, nil)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// TestUserInfo_DeactivatedUser401 is the reason the handler re-reads the user
// instead of answering from the token.
//
// Deactivation has to take effect immediately. Without this check a user disabled
// seconds ago would keep getting their profile served for the remaining lifetime
// of an access token — up to 15 minutes of a revoked account still being answered
// for by a standards endpoint that other systems trust.
func TestUserInfo_DeactivatedUser401(t *testing.T) {
	f := newUserInfoFixture(t)

	if _, err := f.pool.Exec(f.ctx,
		`UPDATE users SET is_active = false WHERE id = $1`, f.userID); err != nil {
		t.Fatalf("deactivate user: %v", err)
	}

	rec, _ := f.call(t, http.MethodGet, f.claims())

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for a deactivated user", rec.Code)
	}
}

// TestUserInfo_SoftDeletedUser401 — users are soft-deleted, never removed
// (CLAUDE.md non-negotiable 5), so the row survives and only deleted_at
// distinguishes it. A lookup that forgot the column would find the row and answer
// normally for a deleted account.
//
// This test earned its keep immediately: it caught the handler querying
// is_deleted, the column migration 00002 created and 00021 dropped in favour of
// deleted_at. Both names appear in the migration history, so the wrong one reads
// perfectly plausibly and fails only when the query runs.
func TestUserInfo_SoftDeletedUser401(t *testing.T) {
	f := newUserInfoFixture(t)

	if _, err := f.pool.Exec(f.ctx,
		`UPDATE users SET deleted_at = NOW() WHERE id = $1`, f.userID); err != nil {
		t.Fatalf("soft-delete user: %v", err)
	}

	rec, _ := f.call(t, http.MethodGet, f.claims())

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for a soft-deleted user", rec.Code)
	}
}

// TestUserInfo_ForeignTenantClaim401 pins tenant isolation at the query level.
//
// The user lookup is scoped by tenant_id as well as id. A token whose tenant does
// not own the user must find nothing, rather than returning that user's profile
// on the strength of the id alone.
func TestUserInfo_ForeignTenantClaim401(t *testing.T) {
	f := newUserInfoFixture(t)

	claims := f.claims()
	claims.TenantID = strconv.FormatInt(f.tenantID+9999, 10)

	rec, _ := f.call(t, http.MethodGet, claims)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 when the tenant does not own the user", rec.Code)
	}
}

// TestUserInfo_NonNumericSubject401 guards the DB call. user_id reaches the query
// as an integer, so a claim that cannot parse must be refused before it gets
// there rather than being coerced to 0 and matching whatever row that finds.
func TestUserInfo_NonNumericSubject401(t *testing.T) {
	f := newUserInfoFixture(t)

	claims := f.claims()
	claims.UserID = "not-a-number"

	rec, _ := f.call(t, http.MethodGet, claims)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for a non-numeric sub", rec.Code)
	}
}

// TestUserInfo_SetsNoStoreAndChallenge covers two header contracts that are easy
// to drop in a refactor and invisible until an external client misbehaves:
// no-store (OIDC Core — the response carries personal data and must not be cached
// by intermediaries) and the RFC 6750 WWW-Authenticate challenge, which several
// OIDC libraries need in order to treat a 401 as "refresh the token" rather than
// "retry the request".
func TestUserInfo_SetsNoStoreAndChallenge(t *testing.T) {
	f := newUserInfoFixture(t)

	rec, _ := f.call(t, http.MethodGet, f.claims())
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	rec401, _ := f.call(t, http.MethodGet, nil)
	if got := rec401.Header().Get("WWW-Authenticate"); got == "" {
		t.Error("401 has no WWW-Authenticate challenge; RFC 6750 requires one")
	}
}
