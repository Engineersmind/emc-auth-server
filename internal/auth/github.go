package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// GitHub endpoint set (issue #66). GitHub does NOT implement OIDC for OAuth
// Apps — no discovery, no ID token. The flow is plain Authorization Code
// followed by REST identity fetch. Grouped as one block so GitHub Enterprise
// Server support later is a configuration change, not a refactor.
const (
	githubAuthorizeURL = "https://github.com/login/oauth/authorize"
	githubTokenURL     = "https://github.com/login/oauth/access_token"
	githubAPIBaseURL   = "https://api.github.com"
)

// githubHTTPTimeout bounds each REST call to the GitHub API.
const githubHTTPTimeout = 10 * time.Second

// githubDriver implements flowDriver for GitHub OAuth Apps.
//
// Security note: GitHub OAuth Apps silently IGNORE PKCE parameters. We still
// send them for code-path uniformity, but the actual protections on this
// flow are the single-use Redis state (CSRF) and the client secret at
// exchange — do not count PKCE as a control here (see SECURITY.md).
type githubDriver struct {
	// Endpoint overrides — production values by default; integration tests
	// point these at httptest stubs (same pattern as googleDriver.issuer).
	authorizeURL string
	tokenURL     string
	apiBaseURL   string

	httpClient *http.Client
}

func newGitHubDriver() *githubDriver {
	return &githubDriver{
		authorizeURL: githubAuthorizeURL,
		tokenURL:     githubTokenURL,
		apiBaseURL:   githubAPIBaseURL,
		httpClient:   &http.Client{Timeout: githubHTTPTimeout},
	}
}

// WithGitHubEndpoints overrides the GitHub endpoints. TEST HOOK ONLY — lets
// integration tests point the flow at httptest-stubbed servers instead of
// live GitHub. Production wiring never calls this.
func (s *OAuthLoginService) WithGitHubEndpoints(authorizeURL, tokenURL, apiBaseURL string) *OAuthLoginService {
	if g, ok := s.drivers[ProviderGitHub].(*githubDriver); ok {
		g.authorizeURL = authorizeURL
		g.tokenURL = tokenURL
		g.apiBaseURL = apiBaseURL
	}
	return s
}

// oauth2Config assembles the golang.org/x/oauth2 config for one application's
// GitHub credentials. read:user + user:email are required — without
// user:email, users whose email is private (the common case for developers)
// could not be attested via /user/emails.
func (d *githubDriver) oauth2Config(cfg *flowConfig, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  d.authorizeURL,
			TokenURL: d.tokenURL,
		},
		RedirectURL: redirectURL,
		Scopes:      []string{"read:user", "user:email"},
	}
}

// authCodeURL builds the GitHub authorization URL. The PKCE challenge is
// included but inert (see githubDriver security note).
func (d *githubDriver) authCodeURL(_ context.Context, cfg *flowConfig, redirectURL, state, verifier string) (string, error) {
	conf := d.oauth2Config(cfg, redirectURL)
	return conf.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), nil
}

// githubUser is the subset of GET /user the flow consumes. Email is
// deliberately NOT read from here — the public profile email is not
// guaranteed verified; the attested address comes from /user/emails.
type githubUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Name  string `json:"name"`
}

// githubEmail is one entry of GET /user/emails.
type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// fetchIdentity exchanges the code, then resolves the identity via REST:
// GET /user for the stable numeric ID and display name, GET /user/emails for
// the verified primary address. No verified primary email → the login is
// rejected (ErrOAuthEmailNotVerified) — no account is created or linked.
//
// GitHub's access token lives only in local variables inside this call — it
// is never persisted or logged (same non-negotiable as Google, issue #64).
func (d *githubDriver) fetchIdentity(ctx context.Context, cfg *flowConfig, redirectURL, code, verifier string) (*providerIdentity, error) {
	conf := d.oauth2Config(cfg, redirectURL)

	// GitHub's token endpoint returns HTTP 200 even on failure (e.g.
	// bad_verification_code) with an error body. x/oauth2 surfaces that as an
	// error or an empty access token depending on the shape — treat both as
	// failure and never trust the status code alone.
	token, err := conf.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("exchange authorization code: %w", err)
	}
	if token.AccessToken == "" {
		return nil, fmt.Errorf("github token response missing access_token")
	}

	var user githubUser
	if err := d.apiGET(ctx, token.AccessToken, "/user", &user); err != nil {
		return nil, err
	}
	if user.ID == 0 {
		return nil, fmt.Errorf("github /user response missing id")
	}

	var emails []githubEmail
	if err := d.apiGET(ctx, token.AccessToken, "/user/emails", &emails); err != nil {
		return nil, err
	}
	email := ""
	for _, e := range emails {
		if e.Primary && e.Verified {
			email = e.Email
			break
		}
	}
	// Email-verification gate — same posture as Google: rejected outright,
	// no fallback path that creates or links an account anyway.
	if email == "" {
		return nil, ErrOAuthEmailNotVerified
	}

	firstName, lastName := splitDisplayName(user.Name, user.Login)

	return &providerIdentity{
		// Numeric ID, never login — usernames are mutable, the ID is stable.
		Sub: strconv.FormatInt(user.ID, 10),
		// GitHub preserves user casing on emails; the auto-link lookup in
		// resolveUser is an exact match, so normalise here or mixed-case
		// addresses would JIT-provision duplicates instead of linking.
		Email:     strings.ToLower(email),
		FirstName: firstName,
		LastName:  lastName,
	}, nil
}

// apiGET performs one authenticated GitHub REST call and decodes the JSON
// response into out. GitHub rejects requests without a User-Agent (403).
func (d *githubDriver) apiGET(ctx context.Context, accessToken, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.apiBaseURL+path, nil)
	if err != nil {
		return fmt.Errorf("build github request %s: %w", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "emc-auth-server")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	// G107 false positive: apiBaseURL is the githubAPIBaseURL constant in
	// production and path is a caller-supplied literal ("/user",
	// "/user/emails") — no request-derived data reaches the URL. Only the
	// WithGitHubEndpoints test hook overrides the base (httptest servers).
	resp, err := d.httpClient.Do(req) //nolint:gosec // G107: apiBaseURL is a compile-time constant
	if err != nil {
		return fmt.Errorf("github %s: %w", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// Bounded read — the identity payloads are small; never stream an
	// unbounded provider response into memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read github %s response: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		// Body is deliberately not included — provider error bodies are not
		// trusted content for logs.
		return fmt.Errorf("github %s returned status %d", path, resp.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode github %s response: %w", path, err)
	}
	return nil
}

// splitDisplayName maps GitHub's single nullable display name onto the
// first/last columns: first space splits the name; a missing name falls back
// to the login so JIT-provisioned users are never blank.
func splitDisplayName(name, login string) (first, last string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return login, ""
	}
	parts := strings.SplitN(name, " ", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], strings.TrimSpace(parts[1])
}
