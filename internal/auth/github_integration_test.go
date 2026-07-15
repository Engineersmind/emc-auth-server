package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// stubGitHub is an httptest-backed fake of GitHub's OAuth + REST surface:
// the token endpoint plus GET /user and GET /user/emails. It reproduces
// GitHub's quirks the driver must survive — HTTP 200 with an error body on a
// bad code, and 403 on any request missing a User-Agent header.
type stubGitHub struct {
	server *httptest.Server

	mu         sync.Mutex
	tokenError string        // when set, /token returns 200 + {"error": ...}
	user       githubUser    // response for GET /user
	emails     []githubEmail // response for GET /user/emails
}

func newStubGitHub(t *testing.T) *stubGitHub {
	t.Helper()
	sg := &stubGitHub{}

	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		sg.mu.Lock()
		tokenError := sg.tokenError
		sg.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		// GitHub's real behaviour: failures are HTTP 200 with an error body,
		// never a 4xx status.
		if tokenError != "" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":             tokenError,
				"error_description": "stubbed failure",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "stub-github-access-token",
			"token_type":   "bearer",
			"scope":        "read:user,user:email",
		})
	})
	requireHeaders := func(w http.ResponseWriter, r *http.Request) bool {
		// GitHub rejects API requests without a User-Agent.
		if r.Header.Get("User-Agent") == "" {
			http.Error(w, "Request forbidden by administrative rules.", http.StatusForbidden)
			return false
		}
		if r.Header.Get("Authorization") != "Bearer stub-github-access-token" {
			http.Error(w, "Bad credentials", http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if !requireHeaders(w, r) {
			return
		}
		sg.mu.Lock()
		user := sg.user
		sg.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(user)
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		if !requireHeaders(w, r) {
			return
		}
		sg.mu.Lock()
		emails := sg.emails
		sg.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(emails)
	})

	sg.server = httptest.NewServer(mux)
	t.Cleanup(sg.server.Close)
	return sg
}

// setIdentity configures the identity the stub serves for the next login.
func (sg *stubGitHub) setIdentity(user githubUser, emails []githubEmail) {
	sg.mu.Lock()
	defer sg.mu.Unlock()
	sg.tokenError = ""
	sg.user = user
	sg.emails = emails
}

// setTokenError makes the next token exchange fail GitHub-style (200 + error body).
func (sg *stubGitHub) setTokenError(code string) {
	sg.mu.Lock()
	defer sg.mu.Unlock()
	sg.tokenError = code
}

// githubTestEnv provisions an isolated tenant + application + GitHub provider
// config, cleaning up only its own rows (same discipline as the Google env —
// the dev DB may hold real data).
type githubTestEnv struct {
	tenantID int64
	appRowID int64
	clientID string
	svc      *OAuthLoginService
	pool     *pgxpool.Pool
	redirect string
}

func newGitHubTestEnv(t *testing.T, sg *stubGitHub) *githubTestEnv {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	logger := testhelper.TestLogger()
	ctx := context.Background()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	var tenantID int64
	err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ($1, $2, 'integration-test-secret', true)
		RETURNING id
	`, "GitHub IT "+suffix, "github-it-"+suffix).Scan(&tenantID)
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	clientID := "app_ghit_" + suffix
	var appRowID int64
	err = pool.QueryRow(ctx, `
		INSERT INTO oauth_clients (tenant_id, name, app_type, client_id, scopes)
		VALUES ($1, 'GitHub IT App', 'web', $2, '{}')
		RETURNING id
	`, tenantID, clientID).Scan(&appRowID)
	if err != nil {
		t.Fatalf("seed application: %v", err)
	}

	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for _, q := range []string{
			`DELETE FROM audit_logs WHERE tenant_id = $1`,
			`DELETE FROM user_identities WHERE tenant_id = $1`,
			`DELETE FROM oauth_authorization_codes WHERE tenant_id = $1`,
			`DELETE FROM refresh_tokens WHERE tenant_id = $1`,
			`DELETE FROM user_credentials WHERE tenant_id = $1`,
			`DELETE FROM users WHERE tenant_id = $1`,
			`DELETE FROM identity_provider_configs WHERE tenant_id = $1`,
			`DELETE FROM roles WHERE tenant_id = $1`,
			`DELETE FROM oauth_clients WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			if _, err := pool.Exec(cctx, q, tenantID); err != nil {
				t.Logf("cleanup warning: %v", err)
			}
		}
	})

	box, err := NewSecretBox("", "development", "TEST_KEY", logger)
	if err != nil {
		t.Fatalf("secret box: %v", err)
	}
	idpSvc := NewIdentityProviderService(pool, box, logger)

	redirect := "https://demo.example/cb"
	_, err = idpSvc.UpsertConfig(ctx, tenantID, appRowID, UpsertProviderConfigInput{
		Provider:      ProviderGitHub,
		ClientID:      "stub-github-client-id",
		ClientSecret:  "stub-github-client-secret",
		Enabled:       true,
		RedirectAllow: []string{redirect},
	})
	if err != nil {
		t.Fatalf("seed provider config: %v", err)
	}

	jwtSvc := NewJWTService(pool, "https://it.test")
	authSvc := NewAuthService(pool, jwtSvc, logger)
	svc := NewOAuthLoginService(pool, rdb, idpSvc, authSvc, "http://localhost:9090", logger).
		WithGitHubEndpoints(sg.server.URL+"/login/oauth/authorize", sg.server.URL+"/login/oauth/access_token", sg.server.URL)

	return &githubTestEnv{
		tenantID: tenantID,
		appRowID: appRowID,
		clientID: clientID,
		svc:      svc,
		pool:     pool,
		redirect: redirect,
	}
}

// startLogin runs BuildAuthURL and extracts the state parameter.
func (env *githubTestEnv) startLogin(t *testing.T) string {
	t.Helper()
	authURL, err := env.svc.BuildAuthURL(context.Background(), ProviderGitHub, env.clientID, env.redirect)
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatal("authorization URL missing state")
	}
	return state
}

// callback consumes the state and runs HandleCallback with a stub code.
func (env *githubTestEnv) callback(t *testing.T, state string) (*CallbackResult, error) {
	t.Helper()
	st, err := env.svc.ConsumeState(context.Background(), ProviderGitHub, state)
	if err != nil {
		t.Fatalf("ConsumeState: %v", err)
	}
	return env.svc.HandleCallback(context.Background(), st, "stub-code")
}

func TestGitHubLoginFlowIntegration(t *testing.T) {
	sg := newStubGitHub(t)
	env := newGitHubTestEnv(t, sg)
	ctx := context.Background()

	t.Run("JIT provision with private email resolved via /user/emails", func(t *testing.T) {
		// Public profile email hidden (GitHub default for developers) — the
		// verified primary address only exists in /user/emails.
		sg.setIdentity(
			githubUser{ID: 583231, Login: "octocat", Name: "Mona Lisa Octocat"},
			[]githubEmail{
				{Email: "spare@example.com", Primary: false, Verified: true},
				{Email: "Mona.Octocat@Example.COM", Primary: true, Verified: true},
			},
		)
		result, err := env.callback(t, env.startLogin(t))
		if err != nil {
			t.Fatalf("HandleCallback: %v", err)
		}
		if result.Outcome != "provisioned" {
			t.Fatalf("outcome = %q, want provisioned", result.Outcome)
		}
		// Mixed-case provider email must be stored lowercased.
		if result.Email != "mona.octocat@example.com" {
			t.Fatalf("email = %q, want lowercased", result.Email)
		}

		var first, last, providerSub string
		err = env.pool.QueryRow(ctx, `
			SELECT u.first_name, u.last_name, ui.provider_sub
			FROM users u JOIN user_identities ui ON ui.user_id = u.id AND ui.provider = 'github'
			WHERE u.id = $1
		`, result.UserID).Scan(&first, &last, &providerSub)
		if err != nil {
			t.Fatalf("load provisioned user: %v", err)
		}
		if first != "Mona" || last != "Lisa Octocat" {
			t.Fatalf("name = %q %q, want Mona / Lisa Octocat", first, last)
		}
		// Numeric GitHub id, never the mutable login.
		if providerSub != "583231" {
			t.Fatalf("provider_sub = %q, want 583231", providerSub)
		}

		// Login-code exchange → standard EMC token pair.
		u, _ := url.Parse(result.RedirectURI)
		code := u.Query().Get("login_code")
		tokens, err := env.svc.ExchangeLoginCode(ctx, env.clientID, code)
		if err != nil {
			t.Fatalf("ExchangeLoginCode: %v", err)
		}
		if tokens.AccessToken == "" || tokens.RefreshToken == "" {
			t.Fatal("exchange returned empty token pair")
		}

		// Second login, same GitHub id but username and name changed —
		// resolves to the SAME user (identity is keyed on the numeric id).
		sg.setIdentity(
			githubUser{ID: 583231, Login: "renamed-octocat", Name: ""},
			[]githubEmail{{Email: "mona.octocat@example.com", Primary: true, Verified: true}},
		)
		result2, err := env.callback(t, env.startLogin(t))
		if err != nil {
			t.Fatalf("HandleCallback second login: %v", err)
		}
		if result2.Outcome != "login" || result2.UserID != result.UserID {
			t.Fatalf("second login outcome=%q user=%d, want login/%d", result2.Outcome, result2.UserID, result.UserID)
		}
	})

	t.Run("token endpoint 200 with error body is a failure", func(t *testing.T) {
		sg.setTokenError("bad_verification_code")
		if _, err := env.callback(t, env.startLogin(t)); err == nil {
			t.Fatal("HandleCallback succeeded on a 200+error-body token response")
		}
	})

	t.Run("no verified primary email rejected outright", func(t *testing.T) {
		sg.setIdentity(
			githubUser{ID: 77, Login: "unverified-user", Name: "No Verified Mail"},
			[]githubEmail{
				{Email: "primary.unverified@example.com", Primary: true, Verified: false},
				{Email: "verified.secondary@example.com", Primary: false, Verified: true},
			},
		)
		if _, err := env.callback(t, env.startLogin(t)); !errors.Is(err, ErrOAuthEmailNotVerified) {
			t.Fatalf("err = %v, want ErrOAuthEmailNotVerified", err)
		}
		var n int
		_ = env.pool.QueryRow(ctx, `SELECT COUNT(*) FROM user_identities WHERE tenant_id=$1 AND provider='github' AND provider_sub='77'`,
			env.tenantID).Scan(&n)
		if n != 0 {
			t.Fatalf("rejected login created %d identity rows", n)
		}
	})

	t.Run("mixed-case github email links to existing verified user", func(t *testing.T) {
		var localID int64
		err := env.pool.QueryRow(ctx, `
			INSERT INTO users (tenant_id, email, first_name, last_name, application_id, is_active, email_verified)
			VALUES ($1, 'case.link@example.com', '', '', $2, true, true) RETURNING id
		`, env.tenantID, env.appRowID).Scan(&localID)
		if err != nil {
			t.Fatalf("seed verified user: %v", err)
		}

		sg.setIdentity(
			githubUser{ID: 88, Login: "caselinker", Name: "Case Linker"},
			[]githubEmail{{Email: "Case.Link@Example.com", Primary: true, Verified: true}},
		)
		result, err := env.callback(t, env.startLogin(t))
		if err != nil {
			t.Fatalf("HandleCallback: %v", err)
		}
		if result.Outcome != "linked" || result.UserID != localID {
			t.Fatalf("outcome=%q user=%d, want linked/%d — mixed-case email must link, not duplicate", result.Outcome, result.UserID, localID)
		}
	})

	t.Run("unverified LOCAL account is a takeover gate", func(t *testing.T) {
		_, err := env.pool.Exec(ctx, `
			INSERT INTO users (tenant_id, email, first_name, last_name, application_id, is_active, email_verified)
			VALUES ($1, 'gh.squatter@example.com', '', '', $2, true, false)
		`, env.tenantID, env.appRowID)
		if err != nil {
			t.Fatalf("seed unverified user: %v", err)
		}
		sg.setIdentity(
			githubUser{ID: 99, Login: "squat-target", Name: ""},
			[]githubEmail{{Email: "gh.squatter@example.com", Primary: true, Verified: true}},
		)
		if _, err := env.callback(t, env.startLogin(t)); !errors.Is(err, ErrOAuthLinkConflict) {
			t.Fatalf("err = %v, want ErrOAuthLinkConflict (takeover gate)", err)
		}
	})
}
