package auth_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Passkey integration tests — issue #112.
//
// Real PostgreSQL, real Redis, and a real WebAuthn verification path driven by
// the virtual authenticator in passkey_authenticator_test.go. Nothing about the
// ceremony is stubbed, so a passing test here means an actual ECDSA signature
// over an actual challenge was verified against an actual stored COSE key.
// ---------------------------------------------------------------------------

const (
	testRPID   = "localhost"
	testOrigin = "https://localhost:8443"
)

type passkeyFixture struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	rdb      *redis.Client
	svc      *auth.WebAuthnService
	authSvc  *auth.AuthService
	tenantID int64
	userID   int64
	email    string
}

func newPasskeyFixture(t *testing.T) *passkeyFixture {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	logger := testhelper.TestLogger()
	testhelper.CleanupTables(t, pool)

	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	var tenantID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant: %v", err)
	}

	svc, err := auth.NewWebAuthnService(pool, rdb, auth.WebAuthnConfig{
		RPID:          testRPID,
		RPDisplayName: "EMC Test",
		Origins:       []string{testOrigin},
		// Left false so a policy row can decide. The server-level flag is a
		// FLOOR (see PasskeyPolicyService.merge), so setting it here would make
		// every "UV not required" test unreachable.
		RequireUserVerification: false,
	}, logger)
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}

	jwtSvc := newTestJWTService(t, pool, "https://auth.emc.local")
	authSvc := auth.NewAuthService(pool, jwtSvc, logger).WithWebAuthn(svc)

	f := &passkeyFixture{
		ctx: ctx, pool: pool, rdb: rdb, svc: svc, authSvc: authSvc,
		tenantID: tenantID, email: "passkey-user@emc.local",
	}
	f.userID = f.createUser(t, f.email, true)
	return f
}

// createUser inserts a user, with or without a password row. withPassword=false
// models a social-login or invite-created account — the state that makes the
// last-factor guard reachable rather than hypothetical.
func (f *passkeyFixture) createUser(t *testing.T, email string, withPassword bool) int64 {
	t.Helper()
	var userID int64
	if err := f.pool.QueryRow(f.ctx, `
		INSERT INTO users (tenant_id, email, is_active, email_verified)
		VALUES ($1, $2, true, true) RETURNING id
	`, f.tenantID, email).Scan(&userID); err != nil {
		t.Fatalf("insert user %s: %v", email, err)
	}
	if withPassword {
		if _, err := f.pool.Exec(f.ctx, `
			INSERT INTO user_credentials (user_id, tenant_id, password_hash)
			VALUES ($1, $2, '$2a$12$notarealhashbutlongenoughxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')
		`, userID, f.tenantID); err != nil {
			t.Fatalf("insert password for %s: %v", email, err)
		}
	}
	return userID
}

// allowPasskeys writes a tenant policy row. Every test that expects a ceremony
// to succeed has to call this, which is itself the point: the platform default is
// off, so a test that forgets it fails closed rather than passing by accident.
func (f *passkeyFixture) allowPasskeys(t *testing.T, requireUV bool) {
	t.Helper()
	yes := true
	if _, err := f.svc.Policy().SetPolicy(f.ctx, &f.tenantID, nil, auth.PasskeyPolicyUpdate{
		AllowPasskeys:           &yes,
		AllowPasswordless:       &yes,
		RequireUserVerification: &requireUV,
	}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
}

// register runs a full registration ceremony and returns the stored credential.
func (f *passkeyFixture) register(t *testing.T, dev *virtualAuthenticator, label string) *auth.StoredCredential {
	t.Helper()
	creation, token, err := f.svc.RegisterBegin(f.ctx, f.userID, f.tenantID, f.email, "", testOrigin)
	if err != nil {
		t.Fatalf("RegisterBegin: %v", err)
	}
	req := dev.AttestationRequest(t, testRPID, testOrigin, creation.Response.Challenge.String())
	cred, err := f.svc.RegisterComplete(f.ctx, f.userID, f.tenantID, f.email, token, label, req)
	if err != nil {
		t.Fatalf("RegisterComplete: %v", err)
	}
	return cred
}

// userHandle reads the account's opaque WebAuthn handle, which a discoverable
// assertion must echo back.
func (f *passkeyFixture) userHandle(t *testing.T) []byte {
	t.Helper()
	var handle []byte
	if err := f.pool.QueryRow(f.ctx,
		`SELECT handle FROM webauthn_user_handles WHERE user_id = $1`, f.userID).Scan(&handle); err != nil {
		t.Fatalf("read user handle: %v", err)
	}
	return handle
}

// ---------------------------------------------------------------------------
// Policy gating
// ---------------------------------------------------------------------------

// TestPasskeyDisabledByDefault is the acceptance criterion that matters most for
// a feature that bypasses the MFA gate: nobody gets passkeys because the code
// shipped. A tenant has to say yes first.
func TestPasskeyDisabledByDefault(t *testing.T) {
	f := newPasskeyFixture(t)

	_, _, err := f.svc.RegisterBegin(f.ctx, f.userID, f.tenantID, f.email, "", testOrigin)
	if !errors.Is(err, auth.ErrPasskeysNotAllowed) {
		t.Fatalf("RegisterBegin with no policy row = %v, want ErrPasskeysNotAllowed", err)
	}

	if _, _, err := f.svc.LoginBegin(f.ctx, testOrigin); !errors.Is(err, auth.ErrPasskeysNotAllowed) {
		t.Fatalf("LoginBegin with no policy row = %v, want ErrPasskeysNotAllowed", err)
	}
}

// TestPasskeyPolicyDisableBlocksLoginAfterRegistration proves the switch is a
// live gate and not just an enrolment check. A tenant turning passkeys off must
// stop existing credentials working, or "off" means nothing for the users who
// already enrolled.
func TestPasskeyPolicyDisableBlocksLoginAfterRegistration(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)
	dev := newVirtualAuthenticator(t)
	f.register(t, dev, "Test device")

	no := false
	if _, err := f.svc.Policy().SetPolicy(f.ctx, &f.tenantID, nil,
		auth.PasskeyPolicyUpdate{AllowPasskeys: &no}); err != nil {
		t.Fatalf("SetPolicy(disable): %v", err)
	}

	if _, _, err := f.svc.LoginBegin(f.ctx, testOrigin); !errors.Is(err, auth.ErrPasskeysNotAllowed) {
		t.Fatalf("LoginBegin after disable = %v, want ErrPasskeysNotAllowed", err)
	}
}

// TestPasskeyPasswordlessCanBeDisabledSeparately proves the two switches are
// independent: a tenant may collect passkeys as a second factor while still
// requiring a password first.
func TestPasskeyPasswordlessCanBeDisabledSeparately(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)

	yes, no := true, false
	if _, err := f.svc.Policy().SetPolicy(f.ctx, &f.tenantID, nil, auth.PasskeyPolicyUpdate{
		AllowPasskeys: &yes, AllowPasswordless: &no,
	}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	// Registration still works — that is the whole distinction.
	if _, _, err := f.svc.RegisterBegin(f.ctx, f.userID, f.tenantID, f.email, "", testOrigin); err != nil {
		t.Fatalf("RegisterBegin with passwordless off = %v, want success", err)
	}
	if _, _, err := f.svc.LoginBegin(f.ctx, testOrigin); !errors.Is(err, auth.ErrPasswordlessNotAllowed) {
		t.Fatalf("LoginBegin with passwordless off = %v, want ErrPasswordlessNotAllowed", err)
	}
}

// TestPasskeyOriginMustBeAllowListed proves an unlisted origin cannot start a
// ceremony. Caught before the challenge is minted, so a page on the wrong domain
// never gets as far as creating a credential the browser would then refuse to
// offer.
func TestPasskeyOriginMustBeAllowListed(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)

	_, _, err := f.svc.RegisterBegin(f.ctx, f.userID, f.tenantID, f.email, "", "https://evil.example.com")
	if !errors.Is(err, auth.ErrOriginNotAllowed) {
		t.Fatalf("RegisterBegin from unlisted origin = %v, want ErrOriginNotAllowed", err)
	}
	if _, _, err := f.svc.LoginBegin(f.ctx, "https://evil.example.com"); !errors.Is(err, auth.ErrOriginNotAllowed) {
		t.Fatalf("LoginBegin from unlisted origin = %v, want ErrOriginNotAllowed", err)
	}
	// An empty Origin header is not a pass. A caller that sends nothing is
	// refused, not defaulted to the server's relying party.
	if _, _, err := f.svc.LoginBegin(f.ctx, ""); !errors.Is(err, auth.ErrOriginNotAllowed) {
		t.Fatalf("LoginBegin with no origin = %v, want ErrOriginNotAllowed", err)
	}
}

// TestPasskeyPolicyMostSpecificWins proves an application row overrides its
// tenant's, which is what lets one tenant run different relying parties on
// different application domains.
func TestPasskeyPolicyMostSpecificWins(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)

	appID := f.createOAuthClient(t, "app-with-own-rp")
	yes := true
	rpID := "insurance.acme.test"
	origins := []string{"https://insurance.acme.test"}
	if _, err := f.svc.Policy().SetPolicy(f.ctx, &f.tenantID, &appID, auth.PasskeyPolicyUpdate{
		AllowPasskeys: &yes, RPID: &rpID, Origins: &origins,
	}); err != nil {
		t.Fatalf("SetPolicy(app): %v", err)
	}

	appPolicy, err := f.svc.Policy().Resolve(f.ctx, f.tenantID, &appID)
	if err != nil {
		t.Fatalf("Resolve(app): %v", err)
	}
	if appPolicy.RPID != rpID {
		t.Errorf("application RP ID = %q, want %q", appPolicy.RPID, rpID)
	}
	if appPolicy.Source != "application" {
		t.Errorf("policy source = %q, want %q", appPolicy.Source, "application")
	}

	// The tenant scope is untouched by the application override.
	tenantPolicy, err := f.svc.Policy().Resolve(f.ctx, f.tenantID, nil)
	if err != nil {
		t.Fatalf("Resolve(tenant): %v", err)
	}
	if tenantPolicy.RPID != testRPID {
		t.Errorf("tenant RP ID = %q, want the inherited %q", tenantPolicy.RPID, testRPID)
	}
}

// TestPasskeyPolicyClearRPIDClearsOrigins covers the documented
// clear-to-inherit operation on a row that has custom origins.
//
// rp_id and origins are one setting as far as the schema is concerned —
// constraint passkey_policies_origins_need_rp_id forbids origins without an
// rp_id, because an allow-list means nothing without the relying party it is an
// allow-list FOR. So {"rp_id": ""} has to take the origins with it; leaving them
// behind turned the contract's own example into a constraint violation for every
// tenant that had configured its own domain.
func TestPasskeyPolicyClearRPIDClearsOrigins(t *testing.T) {
	f := newPasskeyFixture(t)

	yes := true
	rpID := "acme.test"
	origins := []string{"https://acme.test"}
	if _, err := f.svc.Policy().SetPolicy(f.ctx, &f.tenantID, nil, auth.PasskeyPolicyUpdate{
		AllowPasskeys: &yes, RPID: &rpID, Origins: &origins,
	}); err != nil {
		t.Fatalf("SetPolicy(custom rp): %v", err)
	}

	// The contract's exact call: clear rp_id, say nothing about origins.
	blank := ""
	rec, err := f.svc.Policy().SetPolicy(f.ctx, &f.tenantID, nil, auth.PasskeyPolicyUpdate{RPID: &blank})
	if err != nil {
		t.Fatalf(`SetPolicy({"rp_id": ""}) on a row with custom origins: %v`, err)
	}
	if rec.RPID != "" {
		t.Errorf("row rp_id = %q after clearing, want empty", rec.RPID)
	}
	if len(rec.Origins) != 0 {
		t.Errorf("row origins = %v after clearing rp_id, want none — origins cannot outlive the relying party they belong to", rec.Origins)
	}
	// And the scope now inherits the server's relying party.
	if rec.Effective.RPID != testRPID {
		t.Errorf("effective rp_id = %q, want the inherited %q", rec.Effective.RPID, testRPID)
	}

	// Setting origins while clearing rp_id in one call is the caller's own
	// contradiction and is refused rather than silently resolved.
	if _, err := f.svc.Policy().SetPolicy(f.ctx, &f.tenantID, nil, auth.PasskeyPolicyUpdate{
		RPID: &blank, Origins: &origins,
	}); !errors.Is(err, auth.ErrInvalidPasskeyPolicy) {
		t.Errorf(`SetPolicy(rp_id="", origins=[...]) = %v, want ErrInvalidPasskeyPolicy`, err)
	}
}

// TestPasskeyPolicyServerUVIsAFloor proves a tenant cannot relax a deployment
// that demanded user verification. Policy may only ever be as strict or stricter.
func TestPasskeyPolicyServerUVIsAFloor(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	logger := testhelper.TestLogger()

	svc, err := auth.NewWebAuthnService(pool, rdb, auth.WebAuthnConfig{
		RPID: testRPID, RPDisplayName: "EMC", Origins: []string{testOrigin},
		RequireUserVerification: true,
	}, logger)
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}

	var tenantID int64
	if err := pool.QueryRow(context.Background(),
		`SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Skip("seed tenant not present — run with the seeded fixture")
	}

	yes, no := true, false
	if _, err := svc.Policy().SetPolicy(context.Background(), &tenantID, nil, auth.PasskeyPolicyUpdate{
		AllowPasskeys: &yes, RequireUserVerification: &no,
	}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	policy, err := svc.Policy().Resolve(context.Background(), tenantID, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !policy.RequireUserVerification {
		t.Error("tenant row relaxed a server-level UV requirement — the server value must be a floor")
	}
}

// ---------------------------------------------------------------------------
// The ceremony itself
// ---------------------------------------------------------------------------

// TestPasskeyRegisterAndLogin is the happy path, end to end, with real
// signatures: register a credential, then sign in with it and nothing else.
func TestPasskeyRegisterAndLogin(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)
	dev := newVirtualAuthenticator(t)

	cred := f.register(t, dev, "My laptop")
	if cred.Name != "My laptop" {
		t.Errorf("stored name = %q, want %q", cred.Name, "My laptop")
	}
	if cred.RPID != testRPID {
		t.Errorf("stored rp_id = %q, want %q", cred.RPID, testRPID)
	}
	if !cred.Synced {
		t.Error("backup_state was not recorded — the virtual device reported a synced credential")
	}
	// Proves the embedded FIDO registry is wired, not just present.
	if cred.AuthenticatorName != "Windows Hello" {
		t.Errorf("authenticator_name = %q, want %q from the AAGUID registry", cred.AuthenticatorName, "Windows Hello")
	}

	assertion, token, err := f.svc.LoginBegin(f.ctx, testOrigin)
	if err != nil {
		t.Fatalf("LoginBegin: %v", err)
	}
	// A discoverable ceremony must not name credentials: doing so would turn the
	// endpoint into an account oracle.
	if len(assertion.Response.AllowedCredentials) != 0 {
		t.Errorf("allowCredentials had %d entries, want 0 for a discoverable login",
			len(assertion.Response.AllowedCredentials))
	}

	req := dev.AssertionRequest(t, testRPID, testOrigin, assertion.Response.Challenge.String(), f.userHandle(t))
	id, err := f.svc.LoginComplete(f.ctx, token, req)
	if err != nil {
		t.Fatalf("LoginComplete: %v", err)
	}
	if id.UserID != f.userID {
		t.Errorf("resolved user = %d, want %d", id.UserID, f.userID)
	}
	if !id.UserVerified {
		t.Error("UserVerified = false, want true — the device reported a UV gesture")
	}
	if id.CredentialLabel != "My laptop" {
		t.Errorf("credential label = %q, want %q — the audit row needs to name the device", id.CredentialLabel, "My laptop")
	}
}

// TestPasskeyChallengeIsSingleUse is the ticket's explicit acceptance criterion:
// a second complete call with the same challenge is rejected. GETDEL consumes the
// challenge before verification, so even a replay of a VALID response fails.
func TestPasskeyChallengeIsSingleUse(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)
	dev := newVirtualAuthenticator(t)
	f.register(t, dev, "Device")

	assertion, token, err := f.svc.LoginBegin(f.ctx, testOrigin)
	if err != nil {
		t.Fatalf("LoginBegin: %v", err)
	}
	challenge := assertion.Response.Challenge.String()
	handle := f.userHandle(t)

	if _, err := f.svc.LoginComplete(f.ctx, token, dev.AssertionRequest(t, testRPID, testOrigin, challenge, handle)); err != nil {
		t.Fatalf("first LoginComplete: %v", err)
	}
	// Same token, same challenge, a freshly and correctly signed assertion. It
	// must still fail — the nonce is spent.
	_, err = f.svc.LoginComplete(f.ctx, token, dev.AssertionRequest(t, testRPID, testOrigin, challenge, handle))
	if !errors.Is(err, auth.ErrChallengeExpired) {
		t.Fatalf("replayed challenge = %v, want ErrChallengeExpired", err)
	}
}

// TestPasskeyChallengeExpiredSurvivesTheAuthServiceWrapper pins ErrChallengeExpired
// across the layer the handler actually calls.
//
// TestPasskeyChallengeIsSingleUse covers the same rejection at the bare service.
// This one goes through AuthService.LoginWebAuthn, because the concern raised in
// review was not whether the sentinel is returned but whether it SURVIVES: the
// handler tells challenge_expired apart from every other failure so a stale tab
// can silently re-arm instead of showing the user an error, and one fmt.Errorf
// with %w on this path would collapse it into the opaque webauthn_failed with
// nothing failing loudly.
//
// Both shapes that produce it are covered. A spent ceremony is byte-for-byte the
// state a naturally expired one leaves behind — takeCeremony uses GETDEL, so
// "consumed" and "timed out" are the same absent key — which is why an
// artificially shortened TTL would assert nothing this does not.
func TestPasskeyChallengeExpiredSurvivesTheAuthServiceWrapper(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, false)
	dev := newVirtualAuthenticator(t)
	f.register(t, dev, "Device")

	// A token that was never issued: no ceremony state behind it at all.
	if _, _, err := f.authSvc.LoginWebAuthn(f.ctx, "never-issued-ceremony-token",
		dev.AssertionRequest(t, testRPID, testOrigin, "unused", f.userHandle(t))); !errors.Is(err, auth.ErrChallengeExpired) {
		t.Errorf("unknown ceremony token = %v, want ErrChallengeExpired", err)
	}

	// A token consumed by a successful sign-in, which is the same absent key an
	// expiry leaves behind.
	assertion, token, err := f.svc.LoginBegin(f.ctx, testOrigin)
	if err != nil {
		t.Fatalf("LoginBegin: %v", err)
	}
	challenge := assertion.Response.Challenge.String()
	handle := f.userHandle(t)
	if _, _, err := f.authSvc.LoginWebAuthn(f.ctx, token,
		dev.AssertionRequest(t, testRPID, testOrigin, challenge, handle)); err != nil {
		t.Fatalf("first LoginWebAuthn: %v", err)
	}
	_, _, err = f.authSvc.LoginWebAuthn(f.ctx, token,
		dev.AssertionRequest(t, testRPID, testOrigin, challenge, handle))
	if !errors.Is(err, auth.ErrChallengeExpired) {
		t.Fatalf("spent ceremony through LoginWebAuthn = %v, want ErrChallengeExpired", err)
	}
}

// TestPasskeyRejectsForeignOriginSignature proves the origin inside the SIGNED
// clientDataJSON is checked, not merely the header. This is the property that
// makes passkeys phishing-resistant, and it is the library's job — asserted here
// so a library swap cannot quietly drop it.
func TestPasskeyRejectsForeignOriginSignature(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)
	dev := newVirtualAuthenticator(t)
	f.register(t, dev, "Device")

	assertion, token, err := f.svc.LoginBegin(f.ctx, testOrigin)
	if err != nil {
		t.Fatalf("LoginBegin: %v", err)
	}
	// A perfectly valid signature over client data claiming a different origin —
	// exactly what a phishing site would be able to produce if the user's
	// authenticator could be tricked into signing for it.
	req := dev.AssertionRequest(t, testRPID, "https://phishing.example.com",
		assertion.Response.Challenge.String(), f.userHandle(t))
	if _, err := f.svc.LoginComplete(f.ctx, token, req); !errors.Is(err, auth.ErrWebAuthnVerification) {
		t.Fatalf("assertion signed for a foreign origin = %v, want ErrWebAuthnVerification", err)
	}
}

// TestPasskeyRejectsWrongRPIDHash proves a credential minted for one relying
// party cannot assert against another.
func TestPasskeyRejectsWrongRPIDHash(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)
	dev := newVirtualAuthenticator(t)
	f.register(t, dev, "Device")

	assertion, token, err := f.svc.LoginBegin(f.ctx, testOrigin)
	if err != nil {
		t.Fatalf("LoginBegin: %v", err)
	}
	req := dev.AssertionRequest(t, "someone-else.example.com", testOrigin,
		assertion.Response.Challenge.String(), f.userHandle(t))
	if _, err := f.svc.LoginComplete(f.ctx, token, req); !errors.Is(err, auth.ErrWebAuthnVerification) {
		t.Fatalf("assertion with a foreign rpIdHash = %v, want ErrWebAuthnVerification", err)
	}
}

// TestPasskeyRejectsNonDiscoverableCredential proves credProps=false is refused
// at registration rather than stored. A non-discoverable credential could never
// satisfy a passwordless login, so accepting it hands the user a passkey that
// silently never works.
func TestPasskeyRejectsNonDiscoverableCredential(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)
	dev := newVirtualAuthenticator(t)
	dev.discoverable = false

	creation, token, err := f.svc.RegisterBegin(f.ctx, f.userID, f.tenantID, f.email, "", testOrigin)
	if err != nil {
		t.Fatalf("RegisterBegin: %v", err)
	}
	req := dev.AttestationRequest(t, testRPID, testOrigin, creation.Response.Challenge.String())
	_, err = f.svc.RegisterComplete(f.ctx, f.userID, f.tenantID, f.email, token, "", req)
	if !errors.Is(err, auth.ErrCredentialNotDiscoverable) {
		t.Fatalf("non-discoverable registration = %v, want ErrCredentialNotDiscoverable", err)
	}
}

// TestPasskeyRequiresUVWhenPolicyDemandsIt proves a missing gesture is a hard
// rejection and never a downgraded token. With no password in the flow the
// gesture is the only evidence the right person is present.
func TestPasskeyRequiresUVWhenPolicyDemandsIt(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true) // requireUV = true
	dev := newVirtualAuthenticator(t)
	f.register(t, dev, "Device")

	dev.userVerified = false
	assertion, token, err := f.svc.LoginBegin(f.ctx, testOrigin)
	if err != nil {
		t.Fatalf("LoginBegin: %v", err)
	}
	req := dev.AssertionRequest(t, testRPID, testOrigin, assertion.Response.Challenge.String(), f.userHandle(t))
	// The specific sentinel, not merely "an error". Asserting err != nil would
	// keep passing if the assertion started being refused for an unrelated reason
	// — a wrong RP ID after a refactor, say — and the UV requirement itself could
	// silently stop being enforced with the test still green.
	_, err = f.svc.LoginComplete(f.ctx, token, req)
	if !errors.Is(err, auth.ErrUserVerificationRequired) {
		t.Fatalf("assertion with no UV flag under a require_uv policy = %v, want ErrUserVerificationRequired", err)
	}
}

// ---------------------------------------------------------------------------
// Clone detection
// ---------------------------------------------------------------------------

// TestPasskeyCloneDetectionOnSignCountRegression drives the counter backwards and
// asserts the whole containment response: the assertion is refused, the
// credential is deactivated, and every session the account had is revoked.
//
// The counter has to be walked UP first, because a stored count of zero cannot
// regress — which is exactly why this control is inert on Apple and Google
// authenticators that never increment.
func TestPasskeyCloneDetectionOnSignCountRegression(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)
	dev := newVirtualAuthenticator(t)
	dev.signCount = 5
	f.register(t, dev, "Device")

	// One honest sign-in at a higher counter, so the stored value is non-zero.
	dev.signCount = 10
	if _, err := f.login(t, dev); err != nil {
		t.Fatalf("baseline login: %v", err)
	}

	// Now the clone: a valid signature reporting a counter that went backwards.
	dev.signCount = 6
	_, err := f.login(t, dev)

	var cloned *auth.ClonedCredentialError
	if !errors.As(err, &cloned) {
		t.Fatalf("counter regression = %v, want a ClonedCredentialError", err)
	}
	if !errors.Is(err, auth.ErrCredentialCloned) {
		t.Error("ClonedCredentialError must satisfy errors.Is(err, ErrCredentialCloned)")
	}
	if cloned.Reason != "sign_count_regression" {
		t.Errorf("reason = %q, want %q", cloned.Reason, "sign_count_regression")
	}
	if cloned.UserID != f.userID {
		t.Errorf("cloned.UserID = %d, want %d — the audit event cannot name the account without it", cloned.UserID, f.userID)
	}

	// The credential must be out of service, not merely refused for this attempt.
	var active bool
	if err := f.pool.QueryRow(f.ctx,
		`SELECT is_active FROM webauthn_credentials WHERE id = $1`, cloned.CredentialRowID).Scan(&active); err != nil {
		t.Fatalf("read credential state: %v", err)
	}
	if active {
		t.Error("credential is still active after a clone detection")
	}
}

// TestPasskeyCloneDetectionOnBackupFlagChange covers the control that actually
// fires on real hardware. Backup eligibility is fixed for the life of a
// credential, so a change means the key exists somewhere it did not before.
func TestPasskeyCloneDetectionOnBackupFlagChange(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)
	dev := newVirtualAuthenticator(t)
	f.register(t, dev, "Device")

	// BOTH bits move. BE=0 with BS=1 is an invalid combination the spec forbids
	// and go-webauthn rejects outright, so a clone that reports itself as no
	// longer backup-eligible must also report itself as not backed up — which is
	// what a device-bound copy of a previously synced key would actually look
	// like. Setting only BE would test the library's malformed-input path instead
	// of our clone path.
	dev.backupEligible = false
	dev.backupState = false
	_, err := f.login(t, dev)

	var cloned *auth.ClonedCredentialError
	if !errors.As(err, &cloned) {
		t.Fatalf("backup-eligibility change = %v, want a ClonedCredentialError", err)
	}
	if cloned.Reason != "backup_eligibility_changed" {
		t.Errorf("reason = %q, want %q", cloned.Reason, "backup_eligibility_changed")
	}
}

// TestPasskeyCloneContainmentRequiresAValidSignature is the regression test for
// the review finding that mattered most: containment must never run on
// unverified input.
//
// A credential ID is an identifier, not a secret — it travels in every assertion
// and is not something the account owner can rotate. When the clone comparison
// ran BEFORE verification, anyone holding one could post a malformed assertion
// with a single flipped flag and have the credential deactivated, every session
// for the account revoked, token_version bumped and a Redis denylist entry
// written, all without proving possession of the private key. That is an
// unauthenticated account lockout, and it is repeatable.
//
// So: a flipped backup-eligibility flag with a signature that does NOT verify
// must be refused as an ordinary verification failure and change nothing.
func TestPasskeyCloneContainmentRequiresAValidSignature(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, false)
	dev := newVirtualAuthenticator(t)
	cred := f.register(t, dev, "Device")

	// A live session, so an escaped containment would have something to destroy.
	// Through AuthService, not the bare service: only the token-issuing path
	// writes a session row, and sessions are what the containment destroys.
	assertion, token, err := f.svc.LoginBegin(f.ctx, testOrigin)
	if err != nil {
		t.Fatalf("LoginBegin: %v", err)
	}
	if _, _, err := f.authSvc.LoginWebAuthn(f.ctx, token,
		dev.AssertionRequest(t, testRPID, testOrigin, assertion.Response.Challenge.String(), f.userHandle(t))); err != nil {
		t.Fatalf("baseline login: %v", err)
	}
	var sessionsBefore int
	if err := f.pool.QueryRow(f.ctx, `
		SELECT COUNT(*) FROM user_sessions WHERE user_id = $1 AND revoked_at IS NULL
	`, f.userID).Scan(&sessionsBefore); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessionsBefore == 0 {
		t.Fatal("no live session after a successful passkey login; the test cannot prove anything")
	}

	// The attacker's request: the victim's real credential ID, the clone signal,
	// and a signature from a key that is not the credential's.
	forged := newVirtualAuthenticator(t)
	forged.credID = dev.credID
	forged.backupEligible = !dev.backupEligible
	forged.backupState = forged.backupEligible

	assertion, token, err = f.svc.LoginBegin(f.ctx, testOrigin)
	if err != nil {
		t.Fatalf("LoginBegin: %v", err)
	}
	req := forged.AssertionRequest(t, testRPID, testOrigin, assertion.Response.Challenge.String(), f.userHandle(t))

	_, _, err = f.authSvc.LoginWebAuthn(f.ctx, token, req)
	if err == nil {
		t.Fatal("an assertion signed by the wrong key was accepted")
	}
	var cloned *auth.ClonedCredentialError
	if errors.As(err, &cloned) {
		t.Fatalf("unverified assertion triggered clone containment (%v); a credential id must not be enough to lock an account out", err)
	}
	if !errors.Is(err, auth.ErrWebAuthnVerification) {
		t.Errorf("forged assertion = %v, want ErrWebAuthnVerification", err)
	}

	// Nothing may have been contained.
	var active bool
	if err := f.pool.QueryRow(f.ctx,
		`SELECT is_active FROM webauthn_credentials WHERE id::TEXT = $1`, cred.ID).Scan(&active); err != nil {
		t.Fatalf("read credential state: %v", err)
	}
	if !active {
		t.Error("credential was deactivated by an assertion that never verified")
	}

	var sessionsAfter int
	if err := f.pool.QueryRow(f.ctx, `
		SELECT COUNT(*) FROM user_sessions WHERE user_id = $1 AND revoked_at IS NULL
	`, f.userID).Scan(&sessionsAfter); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessionsAfter != sessionsBefore {
		t.Errorf("live sessions went %d -> %d; an unverified assertion revoked sessions", sessionsBefore, sessionsAfter)
	}

	// And the genuine authenticator still works, which is the user-visible half
	// of "nothing was contained".
	if _, err := f.login(t, dev); err != nil {
		t.Errorf("genuine authenticator = %v after a forged clone attempt, want success", err)
	}
}

// TestPasskeyCloneDetectionOnCounterResetToZero covers the gap the review found
// in the counter rule: a stored counter of 10 followed by an asserted 0 is a
// regression, and the old guard skipped it by requiring the ASSERTED value to be
// non-zero. A second authenticator that keeps no counter is exactly what produces
// that shape.
func TestPasskeyCloneDetectionOnCounterResetToZero(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, false)
	dev := newVirtualAuthenticator(t)
	dev.signCount = 5
	f.register(t, dev, "Device")

	dev.signCount = 10
	if _, err := f.login(t, dev); err != nil {
		t.Fatalf("baseline login: %v", err)
	}

	dev.signCount = 0
	_, err := f.login(t, dev)

	var cloned *auth.ClonedCredentialError
	if !errors.As(err, &cloned) {
		t.Fatalf("counter reset from 10 to 0 = %v, want a ClonedCredentialError", err)
	}
	if cloned.Reason != "sign_count_regression" {
		t.Errorf("reason = %q, want %q", cloned.Reason, "sign_count_regression")
	}
}

// TestPasskeyRegisterBeginExcludesActiveCredentials pins excludeCredentials.
//
// It is what stops a user enrolling the same authenticator twice, and it is
// invisible when it breaks: the browser would go ahead, and the duplicate would
// only be caught by the partial unique index at complete — after the user has
// performed a gesture, and reported as "already registered" for a device they
// were told to add. A revoked credential must NOT appear, or re-enrolling a
// device the user removed on purpose becomes impossible.
func TestPasskeyRegisterBeginExcludesActiveCredentials(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, false)

	first := newVirtualAuthenticator(t)
	cred := f.register(t, first, "First")

	creation, _, err := f.svc.RegisterBegin(f.ctx, f.userID, f.tenantID, f.email, "", testOrigin)
	if err != nil {
		t.Fatalf("RegisterBegin: %v", err)
	}
	if !containsCredentialID(creation.Response.CredentialExcludeList, first.credID) {
		t.Errorf("excludeCredentials = %v, want it to contain the active credential; the browser would let the same device enrol twice",
			creation.Response.CredentialExcludeList)
	}

	// Revoke it, and it must drop out — the partial unique index allows re-enrol,
	// so excludeCredentials must not be the thing that blocks it.
	if err := f.svc.RevokeCredential(f.ctx, f.userID, f.tenantID, cred.ID, false); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}
	creation, _, err = f.svc.RegisterBegin(f.ctx, f.userID, f.tenantID, f.email, "", testOrigin)
	if err != nil {
		t.Fatalf("RegisterBegin after revoke: %v", err)
	}
	if containsCredentialID(creation.Response.CredentialExcludeList, first.credID) {
		t.Error("excludeCredentials still lists a revoked credential; the user could never re-enrol that device")
	}
}

func containsCredentialID(list []protocol.CredentialDescriptor, id []byte) bool {
	for _, d := range list {
		if bytes.Equal(d.CredentialID, id) {
			return true
		}
	}
	return false
}

// TestPasskeyCloneRevokesAllSessions asserts the containment the ticket asks for:
// on a clone detection every session for the user ends immediately.
//
// Goes through AuthService.LoginWebAuthn rather than the bare service, because
// the revocation is deliberately owned by the service that owns sessions.
func TestPasskeyCloneRevokesAllSessions(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)
	dev := newVirtualAuthenticator(t)
	f.register(t, dev, "Device")

	// An honest sign-in first, so there is a live session to end.
	assertion, token, err := f.svc.LoginBegin(f.ctx, testOrigin)
	if err != nil {
		t.Fatalf("LoginBegin: %v", err)
	}
	req := dev.AssertionRequest(t, testRPID, testOrigin, assertion.Response.Challenge.String(), f.userHandle(t))
	if _, _, err := f.authSvc.LoginWebAuthn(f.ctx, token, req); err != nil {
		t.Fatalf("LoginWebAuthn: %v", err)
	}

	var live int
	if err := f.pool.QueryRow(f.ctx, `
		SELECT COUNT(*) FROM user_sessions WHERE user_id = $1 AND revoked_at IS NULL
	`, f.userID).Scan(&live); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if live == 0 {
		t.Fatal("no live session after a successful passkey sign-in — cannot test revocation")
	}

	// Now trip the clone detector through the same entry point. Both backup bits
	// move together: BE=0 with BS=1 is a combination the spec forbids and
	// go-webauthn rejects on its own, which would refuse the assertion before the
	// clone comparison ever ran. A device-bound copy of a previously synced key is
	// what this represents.
	dev.backupEligible = false
	dev.backupState = false
	assertion, token, err = f.svc.LoginBegin(f.ctx, testOrigin)
	if err != nil {
		t.Fatalf("LoginBegin: %v", err)
	}
	req = dev.AssertionRequest(t, testRPID, testOrigin, assertion.Response.Challenge.String(), f.userHandle(t))
	if _, _, err := f.authSvc.LoginWebAuthn(f.ctx, token, req); !errors.Is(err, auth.ErrCredentialCloned) {
		t.Fatalf("LoginWebAuthn on clone = %v, want ErrCredentialCloned", err)
	}

	if err := f.pool.QueryRow(f.ctx, `
		SELECT COUNT(*) FROM user_sessions WHERE user_id = $1 AND revoked_at IS NULL
	`, f.userID).Scan(&live); err != nil {
		t.Fatalf("count sessions after clone: %v", err)
	}
	if live != 0 {
		t.Errorf("%d sessions still live after a clone detection, want 0", live)
	}

	var reason string
	if err := f.pool.QueryRow(f.ctx, `
		SELECT revoked_reason FROM user_sessions WHERE user_id = $1 ORDER BY id DESC LIMIT 1
	`, f.userID).Scan(&reason); err != nil {
		t.Fatalf("read revoke reason: %v", err)
	}
	if reason != auth.RevokeReasonPasskeyCloned {
		t.Errorf("revoked_reason = %q, want %q", reason, auth.RevokeReasonPasskeyCloned)
	}
}

// login runs a full assertion ceremony. A helper because half the tests here
// differ only in what the device reports, not in the choreography.
func (f *passkeyFixture) login(t *testing.T, dev *virtualAuthenticator) (*auth.WebAuthnIdentity, error) {
	t.Helper()
	assertion, token, err := f.svc.LoginBegin(f.ctx, testOrigin)
	if err != nil {
		return nil, err
	}
	req := dev.AssertionRequest(t, testRPID, testOrigin, assertion.Response.Challenge.String(), f.userHandle(t))
	return f.svc.LoginComplete(f.ctx, token, req)
}

// ---------------------------------------------------------------------------
// Credential management
// ---------------------------------------------------------------------------

// TestPasskeyLastFactorGuard proves a passwordless account cannot delete its only
// way in from a settings page — the state that produces an account nobody,
// including support, can recover without an out-of-band identity check.
func TestPasskeyLastFactorGuard(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)

	// Re-point the fixture at an account with no password row.
	f.email = "social-only@emc.local"
	f.userID = f.createUser(t, f.email, false)

	dev := newVirtualAuthenticator(t)
	cred := f.register(t, dev, "Only device")

	err := f.svc.RevokeCredential(f.ctx, f.userID, f.tenantID, cred.ID, false)
	if !errors.Is(err, auth.ErrLastFactor) {
		t.Fatalf("removing the only sign-in method = %v, want ErrLastFactor", err)
	}

	// A second passkey makes the first removable: the guard is about the last
	// factor, not about passkeys being undeletable.
	second := newVirtualAuthenticator(t)
	f.register(t, second, "Second device")
	if err := f.svc.RevokeCredential(f.ctx, f.userID, f.tenantID, cred.ID, false); err != nil {
		t.Fatalf("removing a passkey with another present = %v, want success", err)
	}

	// An admin may always remove it — support handling a lost device is the case
	// the guard must not block.
	if err := f.svc.RevokeCredential(f.ctx, f.userID, f.tenantID, second.credIDRow(t, f), true); err != nil {
		t.Fatalf("admin removal of the last passkey = %v, want success", err)
	}
}

// credIDRow finds the stored row id for this device's credential.
func (a *virtualAuthenticator) credIDRow(t *testing.T, f *passkeyFixture) string {
	t.Helper()
	var id string
	if err := f.pool.QueryRow(f.ctx, `
		SELECT id::TEXT FROM webauthn_credentials WHERE credential_id = $1 AND is_active
	`, a.credID).Scan(&id); err != nil {
		t.Fatalf("find credential row: %v", err)
	}
	return id
}

// TestPasskeyRenameAndScoping proves rename works and that neither rename nor
// revoke can reach another user's credential — reported as not found rather than
// forbidden, which would confirm it exists.
func TestPasskeyRenameAndScoping(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)
	dev := newVirtualAuthenticator(t)
	cred := f.register(t, dev, "Old name")

	renamed, err := f.svc.RenameCredential(f.ctx, f.userID, f.tenantID, cred.ID, "  New name  ")
	if err != nil {
		t.Fatalf("RenameCredential: %v", err)
	}
	if renamed.Name != "New name" {
		t.Errorf("renamed to %q, want %q (trimmed)", renamed.Name, "New name")
	}

	if _, err := f.svc.RenameCredential(f.ctx, f.userID, f.tenantID, cred.ID, "   "); !errors.Is(err, auth.ErrInvalidPasskeyName) {
		t.Errorf("blank rename = %v, want ErrInvalidPasskeyName", err)
	}

	other := f.createUser(t, "other-user@emc.local", true)
	if _, err := f.svc.RenameCredential(f.ctx, other, f.tenantID, cred.ID, "Mine now"); !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Errorf("cross-user rename = %v, want ErrCredentialNotFound", err)
	}
	if err := f.svc.RevokeCredential(f.ctx, other, f.tenantID, cred.ID, false); !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Errorf("cross-user revoke = %v, want ErrCredentialNotFound", err)
	}
}

// TestPasskeyMaxCredentialsEnforced proves the per-account ceiling holds, which
// is what bounds how many authenticators a stolen session can quietly enrol.
func TestPasskeyMaxCredentialsEnforced(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)

	yes, limit := true, 1
	if _, err := f.svc.Policy().SetPolicy(f.ctx, &f.tenantID, nil, auth.PasskeyPolicyUpdate{
		AllowPasskeys: &yes, MaxCredentialsPerUser: &limit,
	}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	f.register(t, newVirtualAuthenticator(t), "First")
	_, _, err := f.svc.RegisterBegin(f.ctx, f.userID, f.tenantID, f.email, "", testOrigin)
	if !errors.Is(err, auth.ErrTooManyCredentials) {
		t.Fatalf("second registration at the limit = %v, want ErrTooManyCredentials", err)
	}
}

// TestPasskeyReenrolAfterRevoke proves the partial unique index does its job. A
// plain unique index over every row would burn the credential id permanently, so
// a user who removed a passkey could never re-enrol the same device — and would
// be told it was "already registered", referring to a row they cannot see.
func TestPasskeyReenrolAfterRevoke(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)
	dev := newVirtualAuthenticator(t)

	cred := f.register(t, dev, "Device")
	// Password row exists on the fixture user, so the last-factor guard allows it.
	if err := f.svc.RevokeCredential(f.ctx, f.userID, f.tenantID, cred.ID, false); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}
	// Same device, same credential id.
	if again := f.register(t, dev, "Device again"); again.ID == cred.ID {
		t.Error("re-enrolment reused the revoked row; expected a new one")
	}
}

// TestPasskeyResetUserMFADeactivatesPasskeys covers the hole the master plan
// flagged: an admin reset that cleared TOTP and email but left the lost device's
// passkey working, while reporting success.
func TestPasskeyResetUserMFADeactivatesPasskeys(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)
	dev := newVirtualAuthenticator(t)
	f.register(t, dev, "Lost laptop")

	totpSvc, err := auth.NewTOTPService(f.pool, totpEnvKey(), testhelper.TestLogger())
	if err != nil {
		t.Fatalf("NewTOTPService: %v", err)
	}
	if err := totpSvc.ResetUserMFA(f.ctx, f.tenantID, nil, f.userID); err != nil {
		t.Fatalf("ResetUserMFA: %v", err)
	}

	creds, err := f.svc.ListCredentials(f.ctx, f.userID, f.tenantID)
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("%d passkeys still active after an MFA reset, want 0 — the lost device still had a factor", len(creds))
	}

	var byAdmin bool
	if err := f.pool.QueryRow(f.ctx, `
		SELECT revoked_by_admin FROM webauthn_credentials WHERE user_id = $1
	`, f.userID).Scan(&byAdmin); err != nil {
		t.Fatalf("read revoked_by_admin: %v", err)
	}
	if !byAdmin {
		t.Error("revoked_by_admin = false; the user's settings list cannot explain where the passkey went")
	}
}

// createOAuthClient inserts a minimal oauth_clients row so application-scoped
// policy can be tested. The seed creates none — trap §9.8 in the master plan.
func (f *passkeyFixture) createOAuthClient(t *testing.T, name string) int64 {
	t.Helper()
	var id int64
	if err := f.pool.QueryRow(f.ctx, `
		INSERT INTO oauth_clients (tenant_id, client_id, client_secret_hash, name, app_type)
		VALUES ($1, $2, 'not-a-real-hash', $3, 'web')
		RETURNING id
	`, f.tenantID, name+"-client-id", name).Scan(&id); err != nil {
		t.Fatalf("insert oauth client: %v", err)
	}
	return id
}

// TestPasskeyPerTenantDisplayName proves the name the user sees in their
// password manager is per-tenant, not per-deployment.
//
// This matters more than it looks. The display name is what the OS prompt says
// ("Create a passkey for …?") and it is then stored ON THE CREDENTIAL by the
// authenticator, so it is the label the user reads in their password manager
// effectively forever. A white-labelled tenant whose users see the platform's
// brand instead of their own has a product problem, not a cosmetic one.
//
// Asserted against the creation options the browser actually receives, because
// that is the only place the value has any effect — the server never reads it
// back.
func TestPasskeyPerTenantDisplayName(t *testing.T) {
	f := newPasskeyFixture(t)

	yes := true
	tenantName := "Acme Auth"
	if _, err := f.svc.Policy().SetPolicy(f.ctx, &f.tenantID, nil, auth.PasskeyPolicyUpdate{
		AllowPasskeys: &yes, RPDisplayName: &tenantName,
	}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	creation, _, err := f.svc.RegisterBegin(f.ctx, f.userID, f.tenantID, f.email, "", testOrigin)
	if err != nil {
		t.Fatalf("RegisterBegin: %v", err)
	}
	if got := creation.Response.RelyingParty.Name; got != tenantName {
		t.Errorf("rp.name = %q, want %q — the tenant's own brand must reach the OS prompt", got, tenantName)
	}
	// The RP ID still inherits, so the tenant is rebranded without becoming a
	// separate relying party. Those are independent decisions and conflating
	// them would orphan credentials on a rename.
	if got := creation.Response.RelyingParty.ID; got != testRPID {
		t.Errorf("rp.id = %q, want the inherited %q — a display-name change must not move the relying party", got, testRPID)
	}

	// Clearing it falls back to the deployment default rather than to empty:
	// an authenticator prompt with no name at all is worse than a generic one.
	blank := ""
	if _, err := f.svc.Policy().SetPolicy(f.ctx, &f.tenantID, nil, auth.PasskeyPolicyUpdate{
		RPDisplayName: &blank,
	}); err != nil {
		t.Fatalf("SetPolicy(clear): %v", err)
	}
	creation, _, err = f.svc.RegisterBegin(f.ctx, f.userID, f.tenantID, f.email, "", testOrigin)
	if err != nil {
		t.Fatalf("RegisterBegin after clear: %v", err)
	}
	if got := creation.Response.RelyingParty.Name; got != "EMC Test" {
		t.Errorf("rp.name after clearing = %q, want the server default %q", got, "EMC Test")
	}
}
