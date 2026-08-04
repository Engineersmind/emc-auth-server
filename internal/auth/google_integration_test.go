package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// stubGoogle is an httptest-backed fake of Google's OIDC surface: discovery,
// JWKS, and the token endpoint. ID tokens are RS256-signed with a throwaway
// key so go-oidc performs REAL signature/issuer/audience/expiry verification
// against it — nothing in the flow is mocked out.
type stubGoogle struct {
	server *httptest.Server
	key    *rsa.PrivateKey

	mu     sync.Mutex
	claims jwt.MapClaims // claims for the next id_token issued by /token
}

func newStubGoogle(t *testing.T) *stubGoogle {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	sg := &stubGoogle{key: key}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                sg.server.URL,
			"authorization_endpoint":                sg.server.URL + "/auth",
			"token_endpoint":                        sg.server.URL + "/token",
			"jwks_uri":                              sg.server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := &sg.key.PublicKey
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "test-key",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		sg.mu.Lock()
		claims := sg.claims
		sg.mu.Unlock()

		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "test-key"
		idToken, err := tok.SignedString(sg.key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "stub-google-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	})

	sg.server = httptest.NewServer(mux)
	t.Cleanup(sg.server.Close)
	return sg
}

// setIDToken configures the claims of the next id_token the stub issues.
func (sg *stubGoogle) setIDToken(googleClientID, sub, email string, emailVerified bool) {
	sg.mu.Lock()
	defer sg.mu.Unlock()
	sg.claims = jwt.MapClaims{
		"iss":            sg.server.URL,
		"aud":            googleClientID,
		"sub":            sub,
		"email":          email,
		"email_verified": emailVerified,
		"given_name":     "Stub",
		"family_name":    "User",
		"iat":            time.Now().Unix(),
		"exp":            time.Now().Add(time.Hour).Unix(),
	}
}

// oauthTestEnv provisions an isolated tenant + application + provider config
// and cleans up ONLY its own rows (never truncates shared tables — the dev DB
// may hold real data).
type oauthTestEnv struct {
	tenantID int64
	appRowID int64
	clientID string
	svc      *OAuthLoginService
	pool     *pgxpool.Pool
	redirect string
}

func newOAuthTestEnv(t *testing.T, sg *stubGoogle) *oauthTestEnv {
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
	`, "OAuth IT "+suffix, "oauth-it-"+suffix).Scan(&tenantID)
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	clientID := "app_it_" + suffix
	var appRowID int64
	err = pool.QueryRow(ctx, `
		INSERT INTO oauth_clients (tenant_id, name, app_type, client_id, scopes)
		VALUES ($1, 'IT App', 'web', $2, '{}')
		RETURNING id
	`, tenantID, clientID).Scan(&appRowID)
	if err != nil {
		t.Fatalf("seed application: %v", err)
	}

	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		// Only this test's tenant subtree — explicit FK-safe order.
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
		Provider:      ProviderGoogle,
		ClientID:      "stub-google-client-id",
		ClientSecret:  "stub-google-client-secret",
		Enabled:       true,
		RedirectAllow: []string{redirect},
	})
	if err != nil {
		t.Fatalf("seed provider config: %v", err)
	}

	jwtSvc, err := NewJWTService(pool, "https://it.test")
	if err != nil {
		t.Fatalf("NewJWTService: %v", err)
	}
	authSvc := NewAuthService(pool, jwtSvc, logger)
	svc := NewOAuthLoginService(pool, rdb, idpSvc, authSvc, "http://localhost:9090", logger).
		WithIssuer(sg.server.URL)

	return &oauthTestEnv{
		tenantID: tenantID,
		appRowID: appRowID,
		clientID: clientID,
		svc:      svc,
		pool:     pool,
		redirect: redirect,
	}
}

// startLogin runs BuildAuthURL and extracts the state parameter from the
// returned authorization URL.
func (env *oauthTestEnv) startLogin(t *testing.T) string {
	t.Helper()
	authURL, err := env.svc.BuildAuthURL(context.Background(), ProviderGoogle, env.clientID, env.redirect)
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	if got := u.Query().Get("code_challenge_method"); got != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", got)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatal("authorization URL missing state")
	}
	return state
}

func TestGoogleLoginFlowIntegration(t *testing.T) {
	sg := newStubGoogle(t)
	env := newOAuthTestEnv(t, sg)
	ctx := context.Background()

	t.Run("JIT provision happy path", func(t *testing.T) {
		sg.setIDToken("stub-google-client-id", "google-sub-jit", "jit.user@example.com", true)
		state := env.startLogin(t)

		st, err := env.svc.ConsumeState(ctx, ProviderGoogle, state)
		if err != nil {
			t.Fatalf("ConsumeState: %v", err)
		}
		result, err := env.svc.HandleCallback(ctx, st, "stub-code")
		if err != nil {
			t.Fatalf("HandleCallback: %v", err)
		}
		if result.Outcome != "provisioned" {
			t.Fatalf("outcome = %q, want provisioned", result.Outcome)
		}

		// The provisioned user: app-scoped, email verified, NO credentials row.
		var emailVerified bool
		var appID *int64
		var hasCreds bool
		err = env.pool.QueryRow(ctx, `
			SELECT u.email_verified, u.application_id,
			       EXISTS (SELECT 1 FROM user_credentials WHERE user_id = u.id)
			FROM users u WHERE u.id = $1
		`, result.UserID).Scan(&emailVerified, &appID, &hasCreds)
		if err != nil {
			t.Fatalf("load provisioned user: %v", err)
		}
		if !emailVerified || appID == nil || *appID != env.appRowID || hasCreds {
			t.Fatalf("provisioned user wrong: verified=%v appID=%v hasCreds=%v", emailVerified, appID, hasCreds)
		}

		// Login-code exchange → real token pair via issueTokenPair.
		u, _ := url.Parse(result.RedirectURI)
		code := u.Query().Get("login_code")
		tokens, err := env.svc.ExchangeLoginCode(ctx, env.clientID, code)
		if err != nil {
			t.Fatalf("ExchangeLoginCode: %v", err)
		}
		if tokens.AccessToken == "" || tokens.RefreshToken == "" {
			t.Fatal("exchange returned empty token pair")
		}

		// Replay of the same login code must fail.
		if _, err := env.svc.ExchangeLoginCode(ctx, env.clientID, code); !errors.Is(err, ErrInvalidLoginCode) {
			t.Fatalf("login code replay: err = %v, want ErrInvalidLoginCode", err)
		}

		// Second login with the same Google sub resolves to the SAME user.
		sg.setIDToken("stub-google-client-id", "google-sub-jit", "jit.user@example.com", true)
		state2 := env.startLogin(t)
		st2, err := env.svc.ConsumeState(ctx, ProviderGoogle, state2)
		if err != nil {
			t.Fatalf("ConsumeState second login: %v", err)
		}
		result2, err := env.svc.HandleCallback(ctx, st2, "stub-code")
		if err != nil {
			t.Fatalf("HandleCallback second login: %v", err)
		}
		if result2.Outcome != "login" || result2.UserID != result.UserID {
			t.Fatalf("second login outcome=%q user=%d, want login/%d", result2.Outcome, result2.UserID, result.UserID)
		}
	})

	t.Run("state is single-use", func(t *testing.T) {
		state := env.startLogin(t)
		if _, err := env.svc.ConsumeState(ctx, ProviderGoogle, state); err != nil {
			t.Fatalf("first ConsumeState: %v", err)
		}
		if _, err := env.svc.ConsumeState(ctx, ProviderGoogle, state); !errors.Is(err, ErrOAuthStateInvalid) {
			t.Fatalf("state replay: err = %v, want ErrOAuthStateInvalid", err)
		}
	})

	t.Run("unverified google email rejected outright", func(t *testing.T) {
		sg.setIDToken("stub-google-client-id", "google-sub-unverified", "unverified@example.com", false)
		state := env.startLogin(t)
		st, err := env.svc.ConsumeState(ctx, ProviderGoogle, state)
		if err != nil {
			t.Fatalf("ConsumeState: %v", err)
		}
		if _, err := env.svc.HandleCallback(ctx, st, "stub-code"); !errors.Is(err, ErrOAuthEmailNotVerified) {
			t.Fatalf("err = %v, want ErrOAuthEmailNotVerified", err)
		}
		// No account may exist for the rejected email.
		var n int
		_ = env.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE tenant_id=$1 AND email=$2`,
			env.tenantID, "unverified@example.com").Scan(&n)
		if n != 0 {
			t.Fatalf("rejected login created %d user rows", n)
		}
	})

	t.Run("auto-link requires verified LOCAL account", func(t *testing.T) {
		// Verified local password user → linking allowed.
		var verifiedID int64
		err := env.pool.QueryRow(ctx, `
			INSERT INTO users (tenant_id, email, first_name, last_name, application_id, is_active, email_verified)
			VALUES ($1, 'linked.user@example.com', '', '', $2, true, true) RETURNING id
		`, env.tenantID, env.appRowID).Scan(&verifiedID)
		if err != nil {
			t.Fatalf("seed verified user: %v", err)
		}
		_, err = env.pool.Exec(ctx, `INSERT INTO user_credentials (user_id, tenant_id, password_hash) VALUES ($1, $2, 'x')`,
			verifiedID, env.tenantID)
		if err != nil {
			t.Fatalf("seed credentials: %v", err)
		}

		sg.setIDToken("stub-google-client-id", "google-sub-link", "linked.user@example.com", true)
		state := env.startLogin(t)
		st, _ := env.svc.ConsumeState(ctx, ProviderGoogle, state)
		result, err := env.svc.HandleCallback(ctx, st, "stub-code")
		if err != nil {
			t.Fatalf("HandleCallback: %v", err)
		}
		if result.Outcome != "linked" || result.UserID != verifiedID {
			t.Fatalf("outcome=%q user=%d, want linked/%d", result.Outcome, result.UserID, verifiedID)
		}

		// UNVERIFIED local user with the same provider email → takeover gate.
		_, err = env.pool.Exec(ctx, `
			INSERT INTO users (tenant_id, email, first_name, last_name, application_id, is_active, email_verified)
			VALUES ($1, 'squatter@example.com', '', '', $2, true, false)
		`, env.tenantID, env.appRowID)
		if err != nil {
			t.Fatalf("seed unverified user: %v", err)
		}
		sg.setIDToken("stub-google-client-id", "google-sub-squat", "squatter@example.com", true)
		state2 := env.startLogin(t)
		st2, _ := env.svc.ConsumeState(ctx, ProviderGoogle, state2)
		if _, err := env.svc.HandleCallback(ctx, st2, "stub-code"); !errors.Is(err, ErrOAuthLinkConflict) {
			t.Fatalf("err = %v, want ErrOAuthLinkConflict (takeover gate)", err)
		}
	})

	t.Run("unlink guard protects only login method", func(t *testing.T) {
		logger := testhelper.TestLogger()
		box, _ := NewSecretBox("", "development", "TEST_KEY", logger)
		idpSvc := NewIdentityProviderService(env.pool, box, logger)

		// The JIT user from the first subtest is Google-only → refuse unlink.
		var jitID int64
		err := env.pool.QueryRow(ctx, `SELECT id FROM users WHERE tenant_id=$1 AND email='jit.user@example.com'`,
			env.tenantID).Scan(&jitID)
		if err != nil {
			t.Fatalf("find JIT user: %v", err)
		}
		if err := idpSvc.UnlinkUserIdentity(ctx, env.tenantID, jitID, ProviderGoogle); !errors.Is(err, ErrLastLoginMethod) {
			t.Fatalf("err = %v, want ErrLastLoginMethod", err)
		}

		// The linked password user has credentials → unlink allowed.
		var linkedID int64
		err = env.pool.QueryRow(ctx, `SELECT id FROM users WHERE tenant_id=$1 AND email='linked.user@example.com'`,
			env.tenantID).Scan(&linkedID)
		if err != nil {
			t.Fatalf("find linked user: %v", err)
		}
		if err := idpSvc.UnlinkUserIdentity(ctx, env.tenantID, linkedID, ProviderGoogle); err != nil {
			t.Fatalf("unlink with password fallback: %v", err)
		}
	})
}
