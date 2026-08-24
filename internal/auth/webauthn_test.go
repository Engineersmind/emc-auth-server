package auth_test

import (
	"io"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// testLogger discards output: these tests assert on returned values, and a
// service that logs during construction should not spray the test output.
func testLogger() zerolog.Logger { return zerolog.New(io.Discard) }

// TestWebAuthnConfigRequiresOrigins proves a half-configured relying party is a
// startup failure rather than a running server that accepts ceremonies from
// anywhere. An RP ID with no origin allow-list is the dangerous shape: the
// library would have nothing to match the ceremony's origin against.
func TestWebAuthnConfigRequiresOrigins(t *testing.T) {
	_, err := auth.NewWebAuthnService(nil, nil, auth.WebAuthnConfig{
		RPID:          "localhost",
		RPDisplayName: "Test",
		Origins:       nil,
	}, testLogger())
	if err == nil {
		t.Fatal("RP ID with no origins was accepted, want error — a relying party with no origin allow-list must not start")
	}
}

// TestWebAuthnDisabledWithoutRPID proves the feature is opt-in: no RP ID means a
// nil service, which is how routes.go decides not to register the endpoints at
// all. A deployment that has not configured passkeys must not serve them.
func TestWebAuthnDisabledWithoutRPID(t *testing.T) {
	svc, err := auth.NewWebAuthnService(nil, nil, auth.WebAuthnConfig{}, testLogger())
	if err != nil {
		t.Fatalf("empty config should disable the feature, not error: %v", err)
	}
	if svc != nil {
		t.Fatal("expected a nil service when WEBAUTHN_RP_ID is unset")
	}
}

// TestWebAuthnRegistrationRequestsDiscoverableAndUV pins the two options the
// target UX depends on, straight off the wire format the browser receives.
//
// Both are load-bearing and both fail silently if wrong:
//   - residentKey "required" is what makes the credential discoverable, which is
//     what makes it appear in autofill. A non-discoverable credential registers
//     perfectly and then never shows up, with no error anywhere.
//   - userVerification "required" is what makes one gesture count as two
//     factors. Without it, a passkey on an unlocked laptop signs in with a click.
//
// Asserted against protocol constants rather than string literals so a library
// rename cannot make this test pass while the behaviour changes.
func TestWebAuthnRegistrationRequestsDiscoverableAndUV(t *testing.T) {
	svc, err := auth.NewWebAuthnService(nil, nil, auth.WebAuthnConfig{
		RPID:                    "localhost",
		RPDisplayName:           "Test",
		Origins:                 []string{"http://localhost:8080"},
		RequireUserVerification: true,
	}, testLogger())
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	if svc == nil {
		t.Fatal("expected a service for a valid config")
	}
	if got := svc.RPID(); got != "localhost" {
		t.Errorf("RPID() = %q, want %q", got, "localhost")
	}

	sel := svc.AuthenticatorSelectionForTest()
	if sel.ResidentKey != protocol.ResidentKeyRequirementRequired {
		t.Errorf("ResidentKey = %q, want %q — a non-discoverable credential never appears in autofill",
			sel.ResidentKey, protocol.ResidentKeyRequirementRequired)
	}
	if sel.UserVerification != protocol.VerificationRequired {
		t.Errorf("UserVerification = %q, want %q — without UV a passkey is a single factor",
			sel.UserVerification, protocol.VerificationRequired)
	}
}

// TestWebAuthnUVCanBeRelaxed proves the escape hatch works: an application still
// using a password as the first factor may accept authenticators that cannot do
// user verification. The default is 'required' (see the config comment); this
// only confirms the opt-out is wired, not that it is advisable.
func TestWebAuthnUVCanBeRelaxed(t *testing.T) {
	svc, err := auth.NewWebAuthnService(nil, nil, auth.WebAuthnConfig{
		RPID:                    "localhost",
		RPDisplayName:           "Test",
		Origins:                 []string{"http://localhost:8080"},
		RequireUserVerification: false,
	}, testLogger())
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	if got := svc.AuthenticatorSelectionForTest().UserVerification; got != protocol.VerificationPreferred {
		t.Errorf("UserVerification = %q, want %q", got, protocol.VerificationPreferred)
	}
}
