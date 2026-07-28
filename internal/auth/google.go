package auth

import (
	"context"
	"fmt"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// googleIssuer is Google's OIDC issuer; discovery resolves the endpoints and
// JWKS from here — nothing is hand-rolled (issue #64).
const googleIssuer = "https://accounts.google.com"

// googleDriver implements flowDriver via OIDC: discovery against the Google
// issuer, Authorization Code + PKCE exchange, and ID-token verification
// against Google's JWKS.
type googleDriver struct {
	// issuer is the OIDC issuer URL for discovery. Always googleIssuer in
	// production; overridden only by tests via WithIssuer to point at an
	// httptest-stubbed provider.
	issuer string

	// mu guards the lazily-initialised OIDC provider (one discovery + JWKS
	// fetch per process, then cached and auto-refreshed by go-oidc).
	mu       sync.Mutex
	provider *oidc.Provider
}

func newGoogleDriver() *googleDriver {
	return &googleDriver{issuer: googleIssuer}
}

// WithIssuer overrides the Google OIDC issuer for discovery. TEST HOOK ONLY —
// lets integration tests point the flow at an httptest-stubbed provider
// instead of the live Google endpoints. Production wiring never calls this.
func (s *OAuthLoginService) WithIssuer(issuer string) *OAuthLoginService {
	if g, ok := s.drivers[ProviderGoogle].(*googleDriver); ok {
		g.issuer = issuer
	}
	return s
}

// oidcProvider returns the cached Google OIDC provider, performing discovery
// on first use.
func (d *googleDriver) oidcProvider(ctx context.Context) (*oidc.Provider, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.provider != nil {
		return d.provider, nil
	}
	p, err := oidc.NewProvider(ctx, d.issuer)
	if err != nil {
		return nil, fmt.Errorf("google oidc discovery: %w", err)
	}
	d.provider = p
	return p, nil
}

// oauth2Config assembles the golang.org/x/oauth2 config for one application's
// Google credentials.
func (d *googleDriver) oauth2Config(provider *oidc.Provider, cfg *flowConfig, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
}

// authCodeURL performs discovery (first use) and builds the Google
// authorization URL with a PKCE S256 challenge.
func (d *googleDriver) authCodeURL(ctx context.Context, cfg *flowConfig, redirectURL, state, verifier string) (string, error) {
	provider, err := d.oidcProvider(ctx)
	if err != nil {
		return "", err
	}
	conf := d.oauth2Config(provider, cfg, redirectURL)
	return conf.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), nil
}

// googleIDClaims is the subset of Google ID token claims the flow consumes.
type googleIDClaims struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
}

// fetchIdentity exchanges the code with PKCE, verifies the ID token against
// Google's JWKS, and applies the email-verification gate.
//
// Google's tokens live only in local variables inside this call — they are
// never persisted or logged (issue #64 non-negotiable).
func (d *googleDriver) fetchIdentity(ctx context.Context, cfg *flowConfig, redirectURL, code, verifier string) (*providerIdentity, error) {
	provider, err := d.oidcProvider(ctx)
	if err != nil {
		return nil, err
	}

	conf := d.oauth2Config(provider, cfg, redirectURL)
	token, err := conf.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("exchange authorization code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("provider token response missing id_token")
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", err)
	}

	var claims googleIDClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode id_token claims: %w", err)
	}
	if claims.Sub == "" || claims.Email == "" {
		return nil, fmt.Errorf("id_token missing sub or email claim")
	}
	// Email-verification gate — rejected outright, no fallback path that
	// creates or links an account anyway.
	if !claims.EmailVerified {
		return nil, ErrOAuthEmailNotVerified
	}

	return &providerIdentity{
		Sub:       claims.Sub,
		Email:     claims.Email,
		FirstName: claims.GivenName,
		LastName:  claims.FamilyName,
	}, nil
}
