package auth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
)

// Issue #177: optional client state pass-through and PKCE on the login_code.

const testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // 43 chars, RFC 7636 appendix B

func TestLoginBindingValidate(t *testing.T) {
	good := pkceS256(testVerifier)
	tests := []struct {
		name    string
		b       LoginBinding
		wantErr bool
	}{
		{"empty is fine", LoginBinding{}, false},
		{"state only", LoginBinding{State: "abc 123/_-"}, false},
		{"state at cap", LoginBinding{State: strings.Repeat("a", maxClientStateLen)}, false},
		{"state over cap", LoginBinding{State: strings.Repeat("a", maxClientStateLen+1)}, true},
		{"state with newline", LoginBinding{State: "a\nb"}, true},
		{"state non-ascii", LoginBinding{State: "café"}, true},
		{"challenge S256 default method", LoginBinding{CodeChallenge: good}, false},
		{"challenge S256 explicit", LoginBinding{CodeChallenge: good, Method: "S256"}, false},
		{"challenge plain rejected", LoginBinding{CodeChallenge: good, Method: "plain"}, true},
		{"challenge too short", LoginBinding{CodeChallenge: "abc"}, true},
		{"challenge bad charset", LoginBinding{CodeChallenge: strings.Repeat("+", 43)}, true},
		{"method without challenge", LoginBinding{Method: "S256"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.b.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidLoginBinding) {
				t.Fatalf("err = %v, want ErrInvalidLoginBinding", err)
			}
		})
	}
}

func TestPKCES256_RFC7636Vector(t *testing.T) {
	if got, want := pkceS256(testVerifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"; got != want {
		t.Fatalf("pkceS256 = %q, want %q", got, want)
	}
}

func TestAppendState(t *testing.T) {
	if got := AppendState("https://app.acme.com/cb", ""); got != "https://app.acme.com/cb" {
		t.Fatalf("empty state must be a no-op, got %q", got)
	}
	got := AppendState("https://app.acme.com/cb?next=%2Fhome", "a b&c=d")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("state") != "a b&c=d" || u.Query().Get("next") != "/home" {
		t.Fatalf("state not echoed unchanged / query not preserved: %q", got)
	}
}

// loginCodeFor runs a full login through the stub provider with the given
// binding and returns the login_code and the redirect it arrived on.
func (env *oauthTestEnv) loginCodeFor(t *testing.T, sg *stubGoogle, sub string, b LoginBinding) (string, *url.URL) {
	t.Helper()
	ctx := context.Background()
	sg.setIDToken("stub-google-client-id", sub, sub+"@example.com", true)
	authURL, err := env.svc.BuildAuthURL(ctx, ProviderGoogle, env.clientID, env.redirect, b)
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	pu, _ := url.Parse(authURL)
	st, err := env.svc.ConsumeState(ctx, ProviderGoogle, pu.Query().Get("state"))
	if err != nil {
		t.Fatalf("ConsumeState: %v", err)
	}
	if st.ClientState != b.State {
		t.Fatalf("stored client state = %q, want %q", st.ClientState, b.State)
	}
	res, err := env.svc.HandleCallback(ctx, st, "stub-code")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	u, _ := url.Parse(res.RedirectURI)
	return u.Query().Get("login_code"), u
}

func TestLoginBindingFlowIntegration(t *testing.T) {
	sg := newStubGoogle(t)
	env := newOAuthTestEnv(t, sg)
	ctx := context.Background()

	t.Run("default path unchanged: no state, no challenge", func(t *testing.T) {
		code, u := env.loginCodeFor(t, sg, "bind-default", LoginBinding{})
		if u.Query().Has("state") {
			t.Fatal("state must not appear when the client sent none")
		}
		if _, err := env.svc.ExchangeLoginCode(ctx, env.clientID, code, ""); err != nil {
			t.Fatalf("legacy exchange failed: %v", err)
		}
	})

	t.Run("state echoed unchanged on the redirect", func(t *testing.T) {
		const state = "xyz &=?/ 123"
		_, u := env.loginCodeFor(t, sg, "bind-state", LoginBinding{State: state})
		if got := u.Query().Get("state"); got != state {
			t.Fatalf("state = %q, want %q", got, state)
		}
	})

	t.Run("PKCE: matching verifier exchanges", func(t *testing.T) {
		code, _ := env.loginCodeFor(t, sg, "bind-pkce-ok", LoginBinding{CodeChallenge: pkceS256(testVerifier)})
		if _, err := env.svc.ExchangeLoginCode(ctx, env.clientID, code, testVerifier); err != nil {
			t.Fatalf("exchange with matching verifier failed: %v", err)
		}
	})

	t.Run("PKCE: missing verifier rejected", func(t *testing.T) {
		code, _ := env.loginCodeFor(t, sg, "bind-pkce-missing", LoginBinding{CodeChallenge: pkceS256(testVerifier)})
		if _, err := env.svc.ExchangeLoginCode(ctx, env.clientID, code, ""); !errors.Is(err, ErrInvalidLoginCode) {
			t.Fatalf("err = %v, want ErrInvalidLoginCode", err)
		}
		// A failed attempt must not burn the code: the legitimate holder of the
		// verifier can still redeem it.
		if _, err := env.svc.ExchangeLoginCode(ctx, env.clientID, code, testVerifier); err != nil {
			t.Fatalf("code was burned by a rejected attempt: %v", err)
		}
	})

	t.Run("PKCE: wrong verifier rejected", func(t *testing.T) {
		code, _ := env.loginCodeFor(t, sg, "bind-pkce-wrong", LoginBinding{CodeChallenge: pkceS256(testVerifier)})
		wrong := strings.Repeat("A", 43)
		if _, err := env.svc.ExchangeLoginCode(ctx, env.clientID, code, wrong); !errors.Is(err, ErrInvalidLoginCode) {
			t.Fatalf("err = %v, want ErrInvalidLoginCode", err)
		}
	})

	t.Run("PKCE: verifier presented for a code without a challenge is rejected (no downgrade)", func(t *testing.T) {
		code, _ := env.loginCodeFor(t, sg, "bind-pkce-downgrade", LoginBinding{})
		if _, err := env.svc.ExchangeLoginCode(ctx, env.clientID, code, testVerifier); !errors.Is(err, ErrInvalidLoginCode) {
			t.Fatalf("err = %v, want ErrInvalidLoginCode", err)
		}
	})

	t.Run("malformed binding rejected at login start", func(t *testing.T) {
		for _, b := range []LoginBinding{
			{State: strings.Repeat("a", maxClientStateLen+1)},
			{CodeChallenge: "short"},
			{CodeChallenge: pkceS256(testVerifier), Method: "plain"},
		} {
			if _, err := env.svc.BuildAuthURL(ctx, ProviderGoogle, env.clientID, env.redirect, b); !errors.Is(err, ErrInvalidLoginBinding) {
				t.Fatalf("binding %+v: err = %v, want ErrInvalidLoginBinding", b, err)
			}
		}
	})
}
