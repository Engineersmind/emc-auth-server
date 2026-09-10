package auth_test

// Tests for issue #130: the token type moves from "aud" to a "gty" claim.
//
// The suite is shaped around the one property that makes #130 non-breaking —
// verification reads "gty" when it is there and falls back to the legacy "aud"
// token-type values when it is not — plus the gate that lets #132 remove that
// fallback: the counter which says whether legacy tokens are still circulating.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// gtyOf reads the "gty" claim without verifying the signature.
//
// Unverified is right here: these tests assert what a MINT SITE put in the
// token, and going through a verify path would fold in the route policy as well,
// so a missing claim could be masked by the legacy fallback accepting the token
// anyway. That is precisely the failure this test exists to catch.
func gtyOf(t *testing.T, token string) string {
	t.Helper()

	var claims auth.Claims
	if _, _, err := jwt.NewParser().ParseUnverified(token, &claims); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	return claims.Gty
}

// TestSign_RefusesEmptyGrantType pins the fail-closed half of the contract.
//
// A token minted with no grant would fall through to the legacy "aud" branch on
// verification and silently inherit the widest grant set its audience maps to —
// so an omission would not surface as a rejection, it would surface as a token
// accepted on more routes than intended. Refusing at the signer is what keeps
// that from being possible.
func TestSign_RefusesEmptyGrantType(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	jwtSvc := newTestJWTService(t, pool, testIssuer)

	token, err := jwtSvc.Sign(context.Background(), 1, auth.AudienceAPI, "", &auth.Claims{
		UserID:   "1",
		TenantID: "1",
	})
	if !errors.Is(err, auth.ErrMissingGrantType) {
		t.Errorf("Sign(gty=\"\") error = %v, want ErrMissingGrantType", err)
	}
	if token != "" {
		t.Error("Sign(gty=\"\") returned a token; want empty")
	}
}

// TestMintSites_EmitGty covers the in-scope mint sites one case each, through
// their real entry points rather than through Sign() directly.
//
// One case each is the point: a signer added later, or an existing one that
// stops threading its grant, fails a named subtest instead of quietly minting
// legacy-shaped tokens that keep working through the fallback until #132 removes
// it and they all break at once.
//
// The SAML mint site is not here — there is no SAML handler test fixture in this
// repo at all, and standing up an IdP assertion for one claim is out of
// proportion. TestEveryMintSitePassesAGrantConstant covers it structurally
// instead, which also covers mint sites that do not exist yet.
func TestMintSites_EmitGty(t *testing.T) {
	t.Run("password login", func(t *testing.T) {
		svc, cleanup := newServiceForTest(t)
		defer cleanup()

		tokens := registerAndLogin(t, svc, uniqueEmail("gty-password"), "Password123!")
		if got := gtyOf(t, tokens.AccessToken); got != auth.GrantPassword {
			t.Errorf("login gty = %q, want %q", got, auth.GrantPassword)
		}
	})

	t.Run("refresh rotation", func(t *testing.T) {
		svc, cleanup := newServiceForTest(t)
		defer cleanup()

		ctx := context.Background()
		tokens := registerAndLogin(t, svc, uniqueEmail("gty-refresh"), "Password123!")

		rotated, err := svc.Refresh(ctx, tokens.RefreshToken)
		if err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		// refresh_token, NOT the password grant that began the session: the
		// originating grant is not recorded on the refresh-token row, so it
		// cannot be carried forward. This is why GrantRefreshToken has to be a
		// member of HumanGrants rather than a passthrough value.
		if got := gtyOf(t, rotated.AccessToken); got != auth.GrantRefreshToken {
			t.Errorf("rotated gty = %q, want %q", got, auth.GrantRefreshToken)
		}
	})

	t.Run("client credentials", func(t *testing.T) {
		pool := testhelper.NewTestDB(t)
		logger := testhelper.TestLogger()
		ctx := context.Background()

		if err := store.RunSeed(ctx, pool, logger); err != nil {
			t.Fatalf("RunSeed: %v", err)
		}
		t.Cleanup(func() { testhelper.CleanupTables(t, pool) })

		var tenantID int64
		if err := pool.QueryRow(ctx,
			`SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`,
		).Scan(&tenantID); err != nil {
			t.Fatalf("fetch seed tenant id: %v", err)
		}

		appSvc := auth.NewApplicationService(pool, logger)
		created, err := appSvc.CreateApplication(ctx, tenantID, "gty-m2m", "m2m", nil)
		if err != nil {
			t.Fatalf("CreateApplication: %v", err)
		}
		_, appID, err := appSvc.AuthenticateClient(ctx, created.ClientID, created.ClientSecret)
		if err != nil {
			t.Fatalf("AuthenticateClient: %v", err)
		}

		jwtSvc := newTestJWTService(t, pool, testIssuer)
		svc := auth.NewAuthService(pool, jwtSvc, logger)

		token, _, err := svc.IssueServiceToken(ctx, tenantID, appID)
		if err != nil {
			t.Fatalf("IssueServiceToken: %v", err)
		}
		if got := gtyOf(t, token); got != auth.GrantClientCredentials {
			t.Errorf("service token gty = %q, want %q", got, auth.GrantClientCredentials)
		}
	})

	t.Run("api key exchange", func(t *testing.T) {
		ctx, jwtSvc, tenantID, _, _ := audienceFixture(t)

		token, err := jwtSvc.SignManagement(ctx, &auth.APIKeyIdentity{
			KeyID:       42,
			TenantID:    tenantID,
			Name:        "ci-key",
			Permissions: []string{"apps:read"},
		})
		if err != nil {
			t.Fatalf("SignManagement: %v", err)
		}
		if got := gtyOf(t, token); got != auth.GrantAPIKey {
			t.Errorf("management token gty = %q, want %q", got, auth.GrantAPIKey)
		}
	})

	t.Run("agent token is stamped but grants nothing", func(t *testing.T) {
		ctx, jwtSvc, tenantID, _, _ := audienceFixture(t)

		token, err := jwtSvc.SignAgent(ctx, &auth.AgentIdentity{
			TenantID:  tenantID,
			Name:      "report-bot",
			AgentType: "assistant",
		})
		if err != nil {
			t.Fatalf("SignAgent: %v", err)
		}
		if got := gtyOf(t, token); got != auth.GrantAgent {
			t.Errorf("agent token gty = %q, want %q", got, auth.GrantAgent)
		}
		// The property CLAUDE.md deferred #11 rests on: these tokens are minted
		// but no verify path accepts them, so nothing is reachable with one.
		for _, set := range [][]string{auth.HumanGrants, auth.AdminGrants, auth.MachineGrants} {
			for _, grant := range set {
				if grant == auth.GrantAgent {
					t.Fatal("GrantAgent is a member of a route-policy grant set; agent tokens would become usable")
				}
			}
		}
	})
}

// TestVerify_DualRead is the compatibility contract in both directions: a token
// carrying "gty" verifies, and so does one carrying only the legacy "aud".
//
// The second half is the whole claim that #130 breaks nothing. Every access
// token in circulation at deploy time has the legacy shape, and they live 15
// minutes each inside refresh chains that live 30 days.
func TestVerify_DualRead(t *testing.T) {
	ctx, jwtSvc, tenantID, userIDStr, jwtSecret := audienceFixture(t)

	t.Run("gty present, aud is not consulted", func(t *testing.T) {
		// A deliberately meaningless audience: after #130 nothing reads it, and
		// #131 will put a real audience identifier there. If this token were
		// refused, that migration could not proceed.
		token, err := jwtSvc.Sign(ctx, tenantID, "api://emc/some-future-app",
			auth.GrantPassword, userClaims(userIDStr, tenantID))
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		claims, err := jwtSvc.Verify(ctx, token)
		if err != nil {
			t.Fatalf("Verify(gty token) error = %v, want nil", err)
		}
		if claims.Gty != auth.GrantPassword {
			t.Errorf("verified gty = %q, want %q", claims.Gty, auth.GrantPassword)
		}
	})

	t.Run("legacy aud, no gty", func(t *testing.T) {
		token := mintLegacyShape(t, jwtSecret, userIDStr, tenantID, auth.AudienceAPI)

		claims, err := jwtSvc.Verify(ctx, token)
		if err != nil {
			t.Fatalf("Verify(legacy token) error = %v, want nil", err)
		}
		if claims.Gty != "" {
			t.Errorf("verified gty = %q, want empty (the token carried none)", claims.Gty)
		}
	})
}

// TestVerify_PreservesAudienceIsolation_ViaGty re-proves issue #84's guarantee
// now that a different claim enforces it: a machine token cannot act as a user,
// and a user token cannot act as a machine.
//
// Asserted for BOTH token shapes. The legacy rows are the ones that matter — the
// fallback widens a single audience into a whole grant set, and a widening that
// went one set too far would silently reopen #84 for every token minted before
// the deploy.
func TestVerify_PreservesAudienceIsolation_ViaGty(t *testing.T) {
	ctx, jwtSvc, tenantID, userIDStr, jwtSecret := audienceFixture(t)

	signGty := func(grant string) string {
		token, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, grant, userClaims(userIDStr, tenantID))
		if err != nil {
			t.Fatalf("Sign(%s): %v", grant, err)
		}
		return token
	}

	tests := []struct {
		name      string
		token     string
		wantHuman bool // accepted by Verify (HumanGrants)
		wantM2M   bool // accepted by VerifyM2M (MachineGrants)
	}{
		{"gty password", signGty(auth.GrantPassword), true, false},
		{"gty client_credentials", signGty(auth.GrantClientCredentials), false, true},
		{"gty api_key", signGty(auth.GrantAPIKey), false, false},
		{"legacy aud api", mintLegacyShape(t, jwtSecret, userIDStr, tenantID, auth.AudienceAPI), true, false},
		{"legacy aud m2m", mintLegacyShape(t, jwtSecret, userIDStr, tenantID, auth.AudienceM2M), false, true},
		{"legacy aud management", mintLegacyShape(t, jwtSecret, userIDStr, tenantID, auth.AudienceManagement), false, false},
		{"legacy aud agent", mintLegacyShape(t, jwtSecret, userIDStr, tenantID, auth.AudienceAgent), false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := jwtSvc.Verify(ctx, tc.token)
			if tc.wantHuman && err != nil {
				t.Errorf("Verify() error = %v, want nil", err)
			}
			if !tc.wantHuman && !errors.Is(err, auth.ErrUnexpectedAudience) {
				t.Errorf("Verify() error = %v, want ErrUnexpectedAudience", err)
			}

			_, err = jwtSvc.VerifyM2M(ctx, tc.token)
			if tc.wantM2M && err != nil {
				t.Errorf("VerifyM2M() error = %v, want nil", err)
			}
			if !tc.wantM2M && !errors.Is(err, auth.ErrUnexpectedAudience) {
				t.Errorf("VerifyM2M() error = %v, want ErrUnexpectedAudience", err)
			}
		})
	}
}

// TestLegacyFallback_IsCounted is the gate before issue #132.
//
// #132 removes the "aud" fallback, and the only evidence that removal is safe is
// this counter reading a sustained zero. A counter that is never incremented
// also reads zero — which is exactly the state CLAUDE.md deferred #12 has been
// in for months, a metric declared with documented labels and no call sites, so
// rate-limit rejections are invisible in Prometheus. Asserting the increment is
// what stops #130 repeating it and #132 shipping on no evidence at all.
func TestLegacyFallback_IsCounted(t *testing.T) {
	ctx, jwtSvc, tenantID, userIDStr, jwtSecret := audienceFixture(t)

	t.Run("legacy token increments", func(t *testing.T) {
		// "none" is the label a first-party token produces: it carries no
		// app_id, and a blank label reads like a broken scrape rather than a
		// fact worth acting on.
		counter := metrics.LegacyAudienceVerifications.WithLabelValues("none")
		before := testutil.ToFloat64(counter)

		token := mintLegacyShape(t, jwtSecret, userIDStr, tenantID, auth.AudienceAPI)
		if _, err := jwtSvc.Verify(ctx, token); err != nil {
			t.Fatalf("Verify(legacy token): %v", err)
		}

		if after := testutil.ToFloat64(counter); after != before+1 {
			t.Errorf("counter = %v, want %v (the fallback was not recorded)", after, before+1)
		}
	})

	t.Run("gty token does not increment", func(t *testing.T) {
		// Otherwise the burn-down never reaches zero and the #132 gate can never
		// be satisfied, however complete the migration actually is.
		counter := metrics.LegacyAudienceVerifications.WithLabelValues("none")
		before := testutil.ToFloat64(counter)

		token, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, auth.GrantPassword,
			userClaims(userIDStr, tenantID))
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if _, err := jwtSvc.Verify(ctx, token); err != nil {
			t.Fatalf("Verify: %v", err)
		}

		if after := testutil.ToFloat64(counter); after != before {
			t.Errorf("counter = %v, want %v (a gty token must not count as legacy)", after, before)
		}
	})

	t.Run("app-scoped legacy token is labelled with its app_id", func(t *testing.T) {
		claims := userClaims(userIDStr, tenantID)
		claims.AppID = "77"
		claims.RegisteredClaims = jwt.RegisteredClaims{
			Issuer:    testIssuer,
			Audience:  jwt.ClaimStrings{auth.AudienceAPI},
			Subject:   userIDStr,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(jwtSecret))
		if err != nil {
			t.Fatalf("sign app-scoped legacy token: %v", err)
		}

		counter := metrics.LegacyAudienceVerifications.WithLabelValues("77")
		before := testutil.ToFloat64(counter)

		if _, err := jwtSvc.Verify(ctx, token); err != nil {
			t.Fatalf("Verify: %v", err)
		}

		// The label is what makes the burn-down actionable: it names WHICH
		// integration is still presenting legacy tokens, so #132 can be timed
		// per client rather than guessed at.
		if after := testutil.ToFloat64(counter); after != before+1 {
			t.Errorf("counter{client_id=77} = %v, want %v", after, before+1)
		}
	})
}

// TestGrantSets_AreDisjoint pins the property every route policy silently
// assumes: no grant belongs to two sets.
//
// An overlap would not look like a bug at the call site. A route declaring
// MachineGrants alone would simply begin accepting a human token, and nothing in
// the declaration would hint at it — the set names would still read correctly.
func TestGrantSets_AreDisjoint(t *testing.T) {
	sets := map[string][]string{
		"HumanGrants":   auth.HumanGrants,
		"AdminGrants":   auth.AdminGrants,
		"MachineGrants": auth.MachineGrants,
	}

	owner := map[string]string{}
	for name, set := range sets {
		if len(set) == 0 {
			t.Errorf("%s is empty; a route declaring it would fail closed on every request", name)
		}
		for _, grant := range set {
			if grant == "" {
				t.Errorf("%s contains an empty grant name", name)
				continue
			}
			if prev, seen := owner[grant]; seen {
				t.Errorf("grant %q is in both %s and %s", grant, prev, name)
				continue
			}
			owner[grant] = name
		}
	}
}

// TestEveryMintSitePassesAGrantConstant is a source-level guard, and it is the
// test that actually covers the SAML mint site.
//
// Issue #130's gate is "every mint path emits gty", which no set of
// behavioural tests can prove — they can only cover the paths someone
// remembered to write a case for, and the ticket's own surface inventory was
// wrong twice (an earlier count of three mint sites missed SAML and the two
// dedicated signers). Reading the call sites answers the actual question, and
// keeps answering it for mint sites added after this ticket closes.
//
// The compiler already forces SOME fourth argument. This forces it to be one of
// the Grant* constants, so a literal or a stray variable cannot pass.
//
// sessionGrantIndirection is the one exception, and it is checked rather than
// waived: the shared chokepoint signs with sess.grant, a field every caller
// fills in. Waiving it would leave the ten flows that funnel through
// issueTokenPairWithScope unscanned — which is most of them — so the second
// scan below follows the indirection and applies the same rule to every place
// that field is written.
const sessionGrantIndirection = "sess.grant"

func TestEveryMintSitePassesAGrantConstant(t *testing.T) {
	root := repoRoot(t)

	// Sign(ctx, tenantID, <audience>, <grant>, claims) — capture the 4th argument.
	call := regexp.MustCompile(`\.Sign\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*([^,]+),`)

	// Where sessionContext.grant is set: a composite literal field, or an
	// assignment onto an existing value (the refresh and tenant-switch paths).
	//
	// The literal pattern is anchored to `sessionContext{` rather than matching a
	// bare `grant:`, because a bare one also matches ordinary prose — every
	// fmt.Errorf("load admin grant: %w", err) in the tree, for a start. It is
	// lazy and length-capped so it cannot run past its own literal, and uses
	// [\s\S] rather than [^}] because these literals span lines and usually
	// contain an inner []string{...} whose closing brace would end the match
	// before reaching the field.
	//
	// The leading [^=,\s}] in the assignment capture keeps `sess.grant == ""` out
	// of the results: after the first `=` comes a second one, which the class
	// rejects. Go's RE2 has no negative lookahead, and a (?!=) here would not
	// fail the build — MustCompile panics at run time instead.
	grantLiteral := regexp.MustCompile(`sessionContext\{[\s\S]{0,300}?\bgrant:\s*([^,\s}]+)`)
	grantAssign := regexp.MustCompile(`\.grant\s*=\s*([^=,\s}][^,\s}]*)`)

	isGrantConst := func(expr string) bool {
		expr = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(expr), ","))
		return strings.HasPrefix(expr, "auth.Grant") || strings.HasPrefix(expr, "Grant")
	}

	var mintSites, grantWrites int
	err := filepath.Walk(filepath.Join(root, "internal"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		rel, _ := filepath.Rel(root, path)
		text := string(src)

		for _, m := range call.FindAllStringSubmatch(text, -1) {
			grant := strings.TrimSpace(m[1])
			mintSites++
			// Either the qualified constant (outside package auth) or the bare
			// one (inside it). Anything else — a literal, a local variable — is
			// a grant this package does not define.
			if isGrantConst(grant) || grant == sessionGrantIndirection {
				continue
			}
			t.Errorf("%s: Sign() called with grant %q; want a Grant* constant or %s",
				rel, grant, sessionGrantIndirection)
		}

		for _, rx := range []*regexp.Regexp{grantLiteral, grantAssign} {
			for _, m := range rx.FindAllStringSubmatch(text, -1) {
				expr := strings.TrimSpace(m[1])
				grantWrites++
				if !isGrantConst(expr) {
					t.Errorf("%s: sessionContext.grant set to %q; want a Grant* constant", rel, expr)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk source tree: %v", err)
	}

	// The mint sites named in issue #130's surface inventory: the shared
	// chokepoint, IssueServiceToken, and the SAML handler. A count that drops
	// means a mint path was removed or reshaped, and this test stopped covering
	// it — which would otherwise look identical to "all clear".
	const wantMintSites = 3
	if mintSites < wantMintSites {
		t.Errorf("found %d Sign() call sites, want at least %d — the scan is no longer finding the mint sites", mintSites, wantMintSites)
	}

	// Ten flows funnel through the chokepoint. Requiring several here means the
	// indirection allowed above is actually being followed, rather than the
	// second scan silently matching nothing.
	const wantGrantWrites = 8
	if grantWrites < wantGrantWrites {
		t.Errorf("found %d sessionContext.grant writes, want at least %d — the indirection scan is not finding the login flows", grantWrites, wantGrantWrites)
	}
}

// repoRoot walks up from the test's working directory to the module root, so the
// scan above does not depend on which package directory `go test` was run from.
func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found in any parent directory")
		}
		dir = parent
	}
}
