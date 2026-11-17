package api_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/api"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// HTTP-level tests for the passwordless routes and for password closure, through
// the real router (issue #203).

type pwHTTP struct {
	t        *testing.T
	e        *echo.Echo
	rdb      *redis.Client
	policy   *auth.PasswordlessPolicyService
	tenantID int64
	stop     func()
}

func newPWHTTP(t *testing.T, enabled bool) *pwHTTP {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	logger := testhelper.TestLogger()
	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	if err := rdb.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flush redis: %v", err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE passwordless_policies, passwordless_policy_history`); err != nil {
		t.Fatalf("clear passwordless policies: %v", err)
	}
	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	e := echo.New()
	stop := api.RegisterRoutes(e, api.Deps{
		Logger: zerolog.New(os.Stderr).Level(zerolog.FatalLevel), Pool: pool, Redis: rdb,
		Config: api.RoutesConfig{
			JWTIssuer: "https://auth.test", Env: "test", AppBaseURL: "http://localhost:8080",
			OIDCIssuerBaseURL: "http://localhost:8080", PasswordlessEnabled: enabled,
		},
	})
	t.Cleanup(stop)
	return &pwHTTP{t: t, e: e, rdb: rdb, policy: auth.NewPasswordlessPolicyService(pool, logger), tenantID: tenantID, stop: stop}
}

func (h *pwHTTP) app(name string, enable bool, mut func(*auth.PasswordlessPolicyRow)) (*auth.AppResult, int64) {
	h.t.Helper()
	pool := testhelper.NewTestDB(h.t)
	appSvc := auth.NewApplicationService(pool, testhelper.TestLogger())
	app, err := appSvc.CreateApplication(context.Background(), h.tenantID, fmt.Sprintf("%s-%d", name, time.Now().UnixNano()), "web", nil)
	if err != nil {
		h.t.Fatalf("CreateApplication: %v", err)
	}
	id, _ := strconv.ParseInt(app.ID, 10, 64)
	// New applications start with their email templates disabled, so the sign-in
	// code is suppressed until an administrator enables it. The admin API refuses to
	// turn codes on while it is off; here the test enables it directly.
	if _, err := pool.Exec(context.Background(), `UPDATE email_templates SET is_active = true WHERE application_id = $1 AND template_type = 'passwordless_code'`, id); err != nil {
		h.t.Fatalf("enable template: %v", err)
	}
	if enable {
		row := auth.PasswordlessPolicyRow{EmailOTPEnabled: ref(true), SignupEnabled: ref(true)}
		if mut != nil {
			mut(&row)
		}
		sc := auth.PasswordlessScope{TenantID: &h.tenantID, ApplicationID: &id}
		if _, err := h.policy.Put(context.Background(), sc, auth.PasswordlessWriteInput{Row: row}); err != nil {
			h.t.Fatalf("Put policy: %v", err)
		}
	}
	return app, id
}

func ref[T any](v T) *T { return &v }

func (h *pwHTTP) post(app *auth.AppResult, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(echo.HeaderAuthorization, "Basic "+base64.StdEncoding.EncodeToString([]byte(app.ClientID+":"+app.ClientSecret)))
	req.RemoteAddr = "203.0.113.50:40000"
	rec := httptest.NewRecorder()
	h.e.ServeHTTP(rec, req)
	return rec
}

// setKnownCode replaces the stored code of a challenge with a known one. The MAC
// is computed under the development key the router falls back to outside
// production, so the test can complete a sign-in without reading mail.
func (h *pwHTTP) setKnownCode(challengeID, code string) {
	h.t.Helper()
	key, err := auth.PasswordlessKeyFromConfig("test", "")
	if err != nil {
		h.t.Fatal(err)
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(challengeID))
	m.Write([]byte{0})
	m.Write([]byte(code))
	if err := h.rdb.HSet(context.Background(), "pwless:ch:"+challengeID, "mac", hex.EncodeToString(m.Sum(nil))).Err(); err != nil {
		h.t.Fatal(err)
	}
}

func errCode(rec *httptest.ResponseRecorder) string {
	var b struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	return b.Error
}

// With the deployment switch off the routes do not exist as far as a client can
// tell: deploying the feature changes nothing until it is turned on.
func TestPasswordlessHTTP_RoutesAre404WhileTheSwitchIsOff(t *testing.T) {
	h := newPWHTTP(t, false)
	app, _ := h.app("pw-http-off", true, nil)
	for _, p := range []string{"start", "resend", "verify"} {
		rec := h.post(app, "/api/v1/auth/apps/passwordless/"+p, `{"email":"a@example.test","challenge_id":"x","code":"123456"}`)
		if rec.Code != http.StatusNotFound {
			t.Errorf("POST /apps/passwordless/%s with the switch off = %d, want 404", p, rec.Code)
		}
	}
}

func TestPasswordlessHTTP_StartVerifyFlow(t *testing.T) {
	h := newPWHTTP(t, true)

	// No policy for the application: refused, and it says why (per-app config).
	bare, _ := h.app("pw-http-bare", false, nil)
	if rec := h.post(bare, "/api/v1/auth/apps/passwordless/start", `{"email":"x@example.test"}`); rec.Code != http.StatusForbidden || errCode(rec) != "passwordless_disabled" {
		t.Errorf("start without a policy = %d %s, want 403 passwordless_disabled", rec.Code, rec.Body.String())
	}

	app, _ := h.app("pw-http-on", true, nil)
	email := fmt.Sprintf("http-%d@example.test", time.Now().UnixNano())

	// Bad input.
	if rec := h.post(app, "/api/v1/auth/apps/passwordless/start", `{"email":"not an email"}`); rec.Code != http.StatusBadRequest || errCode(rec) != "invalid_email" {
		t.Errorf("start with a bad address = %d %s, want 400 invalid_email", rec.Code, rec.Body.String())
	}
	// Wrong credentials never reach the flow.
	badApp := *app
	badApp.ClientSecret = "wrong"
	if rec := h.post(&badApp, "/api/v1/auth/apps/passwordless/start", fmt.Sprintf(`{"email":%q}`, email)); rec.Code != http.StatusUnauthorized {
		t.Errorf("start with a wrong secret = %d, want 401", rec.Code)
	}

	rec := h.post(app, "/api/v1/auth/apps/passwordless/start", fmt.Sprintf(`{"email":%q}`, email))
	if rec.Code != http.StatusOK {
		t.Fatalf("start = %d %s", rec.Code, rec.Body.String())
	}
	var start struct {
		ChallengeID string `json:"challenge_id"`
		ExpiresIn   int    `json:"expires_in"`
		ResendAfter int    `json:"resend_after"`
		CodeLength  int    `json:"code_length"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &start); err != nil || len(start.ChallengeID) != 64 || start.CodeLength != 6 || start.ExpiresIn != 300 {
		t.Fatalf("start body = %s", rec.Body.String())
	}

	// A wrong code: one uniform error, with prose for a person.
	rec = h.post(app, "/api/v1/auth/apps/passwordless/verify", fmt.Sprintf(`{"challenge_id":%q,"code":"000000"}`, start.ChallengeID))
	var apiErr struct{ Error, Message string }
	_ = json.Unmarshal(rec.Body.Bytes(), &apiErr)
	if rec.Code != http.StatusBadRequest || apiErr.Error != "invalid_or_expired_code" || apiErr.Message == "" {
		t.Errorf("wrong code = %d %s, want 400 invalid_or_expired_code with a message", rec.Code, rec.Body.String())
	}

	// The right code signs in (and signs up).
	h.setKnownCode(start.ChallengeID, "424242")
	rec = h.post(app, "/api/v1/auth/apps/passwordless/verify", fmt.Sprintf(`{"challenge_id":%q,"code":"424242"}`, start.ChallengeID))
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil || rec.Code != http.StatusOK || tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatalf("verify = %d %s", rec.Code, rec.Body.String())
	}
	// The code was single use.
	rec = h.post(app, "/api/v1/auth/apps/passwordless/verify", fmt.Sprintf(`{"challenge_id":%q,"code":"424242"}`, start.ChallengeID))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("second verify = %d, want 400", rec.Code)
	}

	// The account has no password, so password login gives the ordinary error.
	rec = h.post(app, "/api/v1/auth/apps/login", fmt.Sprintf(`{"email":%q,"password":"Some-Password-1!"}`, email))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("password login for a passwordless account = %d, want 401", rec.Code)
	}
}

func TestPasswordlessHTTP_ResendCooldown(t *testing.T) {
	h := newPWHTTP(t, true)
	app, _ := h.app("pw-http-resend", true, nil)
	rec := h.post(app, "/api/v1/auth/apps/passwordless/start", fmt.Sprintf(`{"email":"resend-%d@example.test"}`, time.Now().UnixNano()))
	var start struct {
		ChallengeID string `json:"challenge_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &start)

	rec = h.post(app, "/api/v1/auth/apps/passwordless/resend", fmt.Sprintf(`{"challenge_id":%q}`, start.ChallengeID))
	if rec.Code != http.StatusTooManyRequests || errCode(rec) != "resend_cooldown" || rec.Header().Get("Retry-After") == "" {
		t.Errorf("immediate resend = %d %s (Retry-After %q), want 429 resend_cooldown", rec.Code, rec.Body.String(), rec.Header().Get("Retry-After"))
	}
	if rec := h.post(app, "/api/v1/auth/apps/passwordless/resend", `{"challenge_id":"nope"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("resend for an unknown challenge = %d, want 400", rec.Code)
	}
}

// password_enabled=false closes the password endpoints with a clear, uniform
// answer, and leaves them alone for an application that did not opt in.
func TestPasswordlessHTTP_PasswordEndpointsClose(t *testing.T) {
	h := newPWHTTP(t, true)
	closed, _ := h.app("pw-http-closed", true, func(r *auth.PasswordlessPolicyRow) { r.PasswordEnabled = ref(false) })
	open, _ := h.app("pw-http-open", false, nil)

	for _, p := range []struct{ path, body string }{
		{"/api/v1/auth/apps/login", `{"email":"u@example.test","password":"Whatever-123!"}`},
		{"/api/v1/auth/apps/register", `{"email":"u@example.test","password":"Whatever-123!"}`},
		{"/api/v1/auth/forgot-password", `{"email":"u@example.test"}`},
	} {
		rec := h.post(closed, p.path, p.body)
		if rec.Code != http.StatusForbidden || errCode(rec) != "password_auth_disabled" {
			t.Errorf("%s on a closed application = %d %s, want 403 password_auth_disabled", p.path, rec.Code, rec.Body.String())
		}
	}
	// An application that did not opt in is untouched.
	if rec := h.post(open, "/api/v1/auth/apps/register", fmt.Sprintf(`{"email":"open-%d@example.test","password":"Whatever-123!"}`, time.Now().UnixNano())); rec.Code != http.StatusCreated {
		t.Errorf("register on an application that did not opt in = %d %s, want 201", rec.Code, rec.Body.String())
	}
}
