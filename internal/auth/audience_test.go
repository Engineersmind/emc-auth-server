package auth_test

// Tests for issue #131: per-application audience with explicit client grants.
//
// The suite is shaped around the properties that make #131 a boundary rather
// than a claim: an audience cannot be requested without a grant, cannot be
// recycled, cannot be moved by a refresh, cannot be a tenant claiming this
// server's own namespace, and cannot be widened by a scope the grant omits.
//
// Every negative case also asserts that the refusal is INDISTINGUISHABLE from
// its neighbours, because a distinguishable refusal turns the token endpoint
// into a map of every tenant's API inventory.

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// audOf reads the "aud" claim without verifying the signature.
//
// Unverified, for the same reason gty_test.go reads gty unverified: these tests
// assert what a MINT SITE put in the token. Going through a verify path would
// fold in route policy, and since #130 verification does not read "aud" at all
// when "gty" is present — so a wrong audience would pass every verify path and
// the test would prove nothing.
func audOf(t *testing.T, token string) []string {
	t.Helper()
	var claims auth.Claims
	if _, _, err := jwt.NewParser().ParseUnverified(token, &claims); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	return claims.Audience
}

// audOne returns the single audience on a token, failing if there is not
// exactly one. Exactly one is the invariant: a multi-valued "aud" means "valid
// at all of these", which is the shared audience #131 exists to abolish.
func audOne(t *testing.T, token string) string {
	t.Helper()
	got := audOf(t, token)
	if len(got) != 1 {
		t.Fatalf("aud = %v, want exactly one value", got)
	}
	return got[0]
}

// ---------------------------------------------------------------------------
// Format, slug and generation — no database
// ---------------------------------------------------------------------------

func TestValidateAudience(t *testing.T) {
	svc := auth.NewAudienceService(nil, testhelper.TestLogger())

	cases := []struct {
		name     string
		audience string
		wantErr  error
	}{
		{"canonical", "api://acme/payroll-api", nil},
		{"single-character labels", "api://a/b", nil},
		{"digits", "api://t1/app2", nil},
		{"interior hyphens", "api://a-b-c/d-e-f", nil},

		{"no scheme", "acme/payroll", auth.ErrInvalidAudienceFormat},
		{"wrong scheme", "https://acme/payroll", auth.ErrInvalidAudienceFormat},
		{"uppercase", "api://Acme/Payroll", auth.ErrInvalidAudienceFormat},
		{"underscore", "api://acme/payroll_api", auth.ErrInvalidAudienceFormat},
		{"no app label", "api://acme", auth.ErrInvalidAudienceFormat},
		{"empty app label", "api://acme/", auth.ErrInvalidAudienceFormat},
		{"empty tenant label", "api:///payroll", auth.ErrInvalidAudienceFormat},
		{"three labels", "api://acme/pay/roll", auth.ErrInvalidAudienceFormat},
		{"leading hyphen", "api://-acme/payroll", auth.ErrInvalidAudienceFormat},
		{"trailing hyphen", "api://acme-/payroll", auth.ErrInvalidAudienceFormat},
		{"label too long", "api://acme/" + strings.Repeat("a", 41), auth.ErrInvalidAudienceFormat},
		{"label at the limit", "api://acme/" + strings.Repeat("a", 40), nil},
		{"space", "api://acme/pay roll", auth.ErrInvalidAudienceFormat},
		{"path traversal", "api://acme/../emc-auth", auth.ErrInvalidAudienceFormat},

		// The reserved namespace. Prefix, not equality — a resource server
		// matching on a prefix would be fooled by the third case.
		{"reserved exactly", "api://emc-auth", auth.ErrInvalidAudienceFormat},
		{"reserved with a label", "api://emc-auth/anything", auth.ErrReservedAudience},
		{"reserved by prefix", "api://emc-authx/thing", auth.ErrReservedAudience},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.ValidateAudience(tc.audience)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("ValidateAudience(%q) = %v, want %v", tc.audience, err, tc.wantErr)
			}
		})
	}
}

// TestAudienceSlug_MatchesMigrationExpression pins the Go slug to the SQL one.
//
// Migration 00087's backfill computes
//
//	lower(regexp_replace(regexp_replace(name,'[^a-zA-Z0-9]+','-','g'),'(^-+|-+$)','','g'))
//
// and this function must agree with it exactly. If they diverge, an application
// created through the API gets a different audience than the same name would
// have been backfilled to — a divergence invisible until a resource server
// refuses a token nobody can explain.
//
// The expected values below were produced by running that SQL against Postgres,
// not by reading the regex.
func TestAudienceSlug_MatchesMigrationExpression(t *testing.T) {
	cases := []struct{ name, want string }{
		{"Payroll API", "payroll-api"},
		{"payroll-api", "payroll-api"},
		{"Marketing_Site!!", "marketing-site"},
		{"  leading and trailing  ", "leading-and-trailing"},
		{"multiple   spaces", "multiple-spaces"},
		{"CAPS", "caps"},
		{"mixed123Numbers", "mixed123numbers"},
		{"---hyphens---", "hyphens"},
		{"###", ""},
		{"", ""},
		{"a.b.c", "a-b-c"},
		{"tenant/app", "tenant-app"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := auth.AudienceSlug(tc.name); got != tc.want {
				t.Errorf("AudienceSlug(%q) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

func TestGenerateAudience(t *testing.T) {
	svc := auth.NewAudienceService(nil, testhelper.TestLogger())

	t.Run("canonical", func(t *testing.T) {
		got, err := svc.GenerateAudience("acme", "Payroll API")
		if err != nil || got != "api://acme/payroll-api" {
			t.Errorf("GenerateAudience = %q, %v; want api://acme/payroll-api, nil", got, err)
		}
	})

	t.Run("uppercase tenant slug is lowered", func(t *testing.T) {
		// chk_tenants_slug is `~*`, so an uppercase slug is legal in the
		// database. The audience format is lowercase-only, so it must be lowered
		// here exactly as migration 00087 lowers it in SQL.
		got, err := svc.GenerateAudience("UpperCo", "Portal")
		if err != nil || got != "api://upperco/portal" {
			t.Errorf("GenerateAudience = %q, %v; want api://upperco/portal, nil", got, err)
		}
	})

	t.Run("long name is truncated, not refused", func(t *testing.T) {
		// Refusing would make a long application name un-creatable, which worked
		// fine before #131. A validation added for a new claim must not take
		// away an existing ability.
		got, err := svc.GenerateAudience("acme", strings.Repeat("x", 80))
		if err != nil {
			t.Fatalf("GenerateAudience: %v", err)
		}
		if want := "api://acme/" + strings.Repeat("x", 40); got != want {
			t.Errorf("GenerateAudience = %q, want %q", got, want)
		}
		if err := svc.ValidateAudience(got); err != nil {
			t.Errorf("generated audience fails its own validation: %v", err)
		}
	})

	t.Run("punctuation-only name yields no audience", func(t *testing.T) {
		// Not an error: the NAME is legal and the row is fine. The application
		// simply behaves as one created before #131 — no audience claim — which
		// stays valid while require_audience is false.
		got, err := svc.GenerateAudience("acme", "###")
		if err != nil || got != "" {
			t.Errorf("GenerateAudience = %q, %v; want \"\", nil", got, err)
		}
	})

	t.Run("over-long tenant slug is an error, never truncated", func(t *testing.T) {
		// The tenant label identifies the tenant. Silently shortening it would
		// put two tenants in one namespace, which is the single failure this
		// whole scheme exists to prevent.
		if _, err := svc.GenerateAudience(strings.Repeat("t", 41), "App"); !errors.Is(err, auth.ErrInvalidAudienceFormat) {
			t.Errorf("GenerateAudience(long tenant) error = %v, want ErrInvalidAudienceFormat", err)
		}
	})

	t.Run("a tenant slugging to the reserved namespace is refused", func(t *testing.T) {
		// The privilege escalation this closes: a tenant that could register
		// api://emc-auth would receive a legitimately signed token bearing this
		// server's own management audience.
		if _, err := svc.GenerateAudience("emc-auth", "anything"); !errors.Is(err, auth.ErrReservedAudience) {
			t.Errorf("GenerateAudience(emc-auth) error = %v, want ErrReservedAudience", err)
		}
	})
}

func TestWithScheme_IgnoresMalformedValues(t *testing.T) {
	// A malformed AUDIENCE_SCHEME must degrade to the default, not to an
	// outage: the scheme is part of every audience already stored, so accepting
	// a bad one would mint tokens no resource server recognises AND fail
	// validation for every existing identifier on its next write.
	for _, bad := range []string{"", "api", "api:/", "API://", "://", "api://extra/"} {
		svc := auth.NewAudienceService(nil, testhelper.TestLogger()).WithScheme(bad)
		if svc.Scheme() != auth.AudienceSchemeDefault {
			t.Errorf("WithScheme(%q) = %q, want the default %q", bad, svc.Scheme(), auth.AudienceSchemeDefault)
		}
	}
	svc := auth.NewAudienceService(nil, testhelper.TestLogger()).WithScheme("urn://")
	if svc.Scheme() != "urn://" {
		t.Errorf("WithScheme(urn://) = %q, want urn://", svc.Scheme())
	}
	if err := svc.ValidateAudience("urn://acme/app"); err != nil {
		t.Errorf("configured scheme rejected its own shape: %v", err)
	}
	if err := svc.ValidateAudience("api://acme/app"); !errors.Is(err, auth.ErrInvalidAudienceFormat) {
		t.Errorf("configured scheme accepted the default scheme: %v", err)
	}
}

// TestAppUpdate_HasNoAudienceField is the ONLY thing standing between this
// codebase and a future convenience setter for `audience`.
//
// It is a reflection test rather than a behavioural one on purpose: the risk is
// not that today's update path writes the column, it is that someone adds a
// field in six months because a form needed it. That change would compile,
// pass every other test, and silently break every resource server validating
// the old value — audiences are immutable precisely because those servers are
// not ours to coordinate.
func TestAppUpdate_HasNoAudienceField(t *testing.T) {
	typ := reflect.TypeOf(auth.AppUpdate{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if name == "Audience" {
			t.Fatal("AppUpdate has an Audience field: the audience identifier is immutable by design. " +
				"Every resource server validating it would break on a change. If a caller needs a " +
				"different audience, they create a new application. See migration 00087 and issue #131 §4.")
		}
	}
	// RequireAudience, by contrast, MUST be updatable: flipping it per client is
	// the #132 rollout. Asserted so the two are not conflated by a later reader
	// who deletes the wrong one.
	if _, ok := typ.FieldByName("RequireAudience"); !ok {
		t.Error("AppUpdate has no RequireAudience field: the per-client enforcement switch is not settable, " +
			"so the #132 rollout would need direct SQL")
	}
}

func TestFilterPermissionsForClient(t *testing.T) {
	perms := []string{"users:read", "apps:write"}

	if got := auth.FilterPermissionsForClient(perms, true); len(got) != 2 {
		t.Errorf("first-party permissions = %v, want them untouched", got)
	}
	// CLAUDE.md deferred #23. A third-party client gets NOTHING, not a filtered
	// subset: `permissions` is this server's internal vocabulary and is not part
	// of the contract with an external client. An intersection with granted
	// scopes would leak whichever internal permissions happen to share a
	// spelling with a scope.
	if got := auth.FilterPermissionsForClient(perms, false); len(got) != 0 {
		t.Errorf("third-party permissions = %v, want empty", got)
	}
	if got := auth.FilterPermissionsForClient(perms, false); got == nil {
		t.Error("third-party permissions = nil, want a non-nil empty slice so the claim renders as [] not null")
	}
}

// ---------------------------------------------------------------------------
// Database-backed behaviour
// ---------------------------------------------------------------------------

// audienceEnv is the fixture for the DB tests: a seeded tenant, an application
// service and an audience service sharing one pool.
type audienceEnv struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	appSvc   *auth.ApplicationService
	audSvc   *auth.AudienceService
	authSvc  *auth.AuthService
	tenantID int64
}

func newAudienceEnv(t *testing.T) *audienceEnv {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	logger := testhelper.TestLogger()
	ctx := context.Background()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	t.Cleanup(func() { testhelper.CleanupTables(t, pool) })

	var tenantID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant: %v", err)
	}

	audSvc := auth.NewAudienceService(pool, logger)
	appSvc := auth.NewApplicationService(pool, logger).WithAudiences(audSvc)
	jwtSvc := newTestJWTService(t, pool, testIssuer)
	authSvc := auth.NewAuthService(pool, jwtSvc, logger).
		WithAudiences(audSvc).
		WithApplications(appSvc).
		WithTOTP(nil, rdb)

	return &audienceEnv{ctx: ctx, pool: pool, appSvc: appSvc, audSvc: audSvc, authSvc: authSvc, tenantID: tenantID}
}

// uniqueAppName keeps parallel packages from colliding on the audience unique
// index, which is GLOBAL and — unlike the name index — is not scoped per tenant
// and never releases a value.
func uniqueAppName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func TestCreateApplication_AssignsAudienceAndSelfGrant(t *testing.T) {
	env := newAudienceEnv(t)
	name := uniqueAppName("aud131-create")

	app, err := env.appSvc.CreateApplication(env.ctx, env.tenantID, name, "m2m", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	want := "api://emc/" + auth.AudienceSlug(name)
	if app.Audience != want {
		t.Errorf("audience = %q, want %q", app.Audience, want)
	}

	appRowID, err := strconv.ParseInt(app.ID, 10, 64)
	if err != nil {
		t.Fatalf("parse app id: %v", err)
	}

	// The self-grant, without which the application could not get a token for
	// its own API once enforcement is switched on.
	grants, err := env.audSvc.ListGrants(env.ctx, env.tenantID, appRowID)
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(grants) != 1 || grants[0].Audience != want {
		t.Fatalf("grants = %+v, want exactly one self-grant for %q", grants, want)
	}
}

// TestAudienceIsNeverRecycled is the property the FULL unique index exists for.
//
// oauth_clients' own name index is PARTIAL (WHERE deleted_at IS NULL), so
// soft-deleting an application frees its NAME for reuse. Its audience must NOT
// be freed: grants and tokens outlive the client row, and a reissued identifier
// would silently redirect them to a different application.
func TestAudienceIsNeverRecycled(t *testing.T) {
	env := newAudienceEnv(t)
	name := uniqueAppName("aud131-recycle")

	first, err := env.appSvc.CreateApplication(env.ctx, env.tenantID, name, "m2m", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	firstID, _ := strconv.ParseInt(first.ID, 10, 64)
	if err := env.appSvc.DeactivateApplication(env.ctx, env.tenantID, firstID); err != nil {
		t.Fatalf("DeactivateApplication: %v", err)
	}

	// The name is free again — that is pre-existing behaviour and is not what
	// this test challenges.
	second, err := env.appSvc.CreateApplication(env.ctx, env.tenantID, name, "m2m", nil)
	if !errors.Is(err, auth.ErrAudienceTaken) {
		t.Fatalf("recreating a soft-deleted application's name: got (%+v, %v), want ErrAudienceTaken. "+
			"An audience that can be recycled silently redirects existing grants and tokens to a different application", second, err)
	}
}

// TestAudienceTaken_IsADistinctSentinel guards the mapping the E2E run caught.
//
// The service layer was always right: recreating a soft-deleted application's
// name returns ErrAudienceTaken (TestAudienceIsNeverRecycled proves it). The
// HTTP handler was not — it matched duplicates by looking for the words
// "duplicate" or "unique" in the message, which this error does not contain, so
// a correct refusal surfaced to the operator as an opaque 500.
//
// The lesson is that a sentinel is only useful if every layer matches on it, so
// this asserts the two properties a handler needs: the error is reachable by
// errors.Is, and it is NOT confusable with the name-collision error it sits
// next to.
func TestAudienceTaken_IsADistinctSentinel(t *testing.T) {
	env := newAudienceEnv(t)
	name := uniqueAppName("aud131-sentinel")

	first, err := env.appSvc.CreateApplication(env.ctx, env.tenantID, name, "m2m", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	firstID, _ := strconv.ParseInt(first.ID, 10, 64)
	if err := env.appSvc.DeactivateApplication(env.ctx, env.tenantID, firstID); err != nil {
		t.Fatalf("DeactivateApplication: %v", err)
	}

	_, err = env.appSvc.CreateApplication(env.ctx, env.tenantID, name, "m2m", nil)
	if !errors.Is(err, auth.ErrAudienceTaken) {
		t.Fatalf("error = %v, want ErrAudienceTaken", err)
	}
	// The message must not be mistakable for the name collision: the NAME is
	// genuinely free here (its index is partial on deleted_at), so telling an
	// operator it is taken sends them hunting a live application that is not
	// there.
	if strings.Contains(err.Error(), "name") {
		t.Errorf("ErrAudienceTaken message mentions the name (%q); the name is free, the audience is not", err.Error())
	}
}

func TestCreateApplication_RefusesReservedNamespace(t *testing.T) {
	env := newAudienceEnv(t)

	// A tenant whose slug is the reserved prefix. Reached through a real tenant
	// row rather than through GenerateAudience directly, so the whole creation
	// path is covered — including the CHECK constraint, which is the backstop if
	// the service-layer refusal is ever bypassed.
	var reservedTenant int64
	if err := env.pool.QueryRow(env.ctx,
		`INSERT INTO tenants (name, slug, jwt_secret) VALUES ('Reserved', 'emc-auth', 'x')
		 ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name RETURNING id`).Scan(&reservedTenant); err != nil {
		t.Fatalf("seed reserved-slug tenant: %v", err)
	}

	_, err := env.appSvc.CreateApplication(env.ctx, reservedTenant, uniqueAppName("aud131-reserved"), "m2m", nil)
	if !errors.Is(err, auth.ErrReservedAudience) {
		t.Fatalf("CreateApplication in the reserved namespace error = %v, want ErrReservedAudience. "+
			"A tenant able to register api://emc-auth receives a legitimately signed token bearing this server's own management audience", err)
	}
}

func TestGrants_CrossTenantIsRefused(t *testing.T) {
	env := newAudienceEnv(t)

	// Tenant B with its own application, and therefore its own audience.
	var otherTenant int64
	slug := fmt.Sprintf("aud131t%d", time.Now().UnixNano())
	if err := env.pool.QueryRow(env.ctx,
		`INSERT INTO tenants (name, slug, jwt_secret) VALUES ($1, $1, 'x') RETURNING id`, slug).Scan(&otherTenant); err != nil {
		t.Fatalf("create second tenant: %v", err)
	}
	victim, err := env.appSvc.CreateApplication(env.ctx, otherTenant, uniqueAppName("aud131-victim"), "m2m", nil)
	if err != nil {
		t.Fatalf("CreateApplication(tenant B): %v", err)
	}

	// Tenant A's client asking for tenant B's audience.
	attacker, err := env.appSvc.CreateApplication(env.ctx, env.tenantID, uniqueAppName("aud131-attacker"), "m2m", nil)
	if err != nil {
		t.Fatalf("CreateApplication(tenant A): %v", err)
	}
	attackerID, _ := strconv.ParseInt(attacker.ID, 10, 64)

	_, err = env.audSvc.CreateGrant(env.ctx, env.tenantID, attackerID, victim.Audience, nil)
	if !errors.Is(err, auth.ErrInvalidTarget) {
		t.Fatalf("cross-tenant CreateGrant error = %v, want ErrInvalidTarget. "+
			"The composite foreign key from migration 00087 is what makes this impossible rather than merely refused", err)
	}
}

// TestResolveMintAudience_TheResolutionTable walks all four cases of issue #131
// §7. Getting this table wrong is how the cutover breaks a live integrator and
// locks operators out of their own console, so each row is named.
func TestResolveMintAudience_TheResolutionTable(t *testing.T) {
	env := newAudienceEnv(t)

	app, err := env.appSvc.CreateApplication(env.ctx, env.tenantID, uniqueAppName("aud131-table"), "m2m", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appRowID, _ := strconv.ParseInt(app.ID, 10, 64)

	t.Run("case 3: no client identity gets the server's own audience", func(t *testing.T) {
		// The admin console signs in through POST /auth/session with an email
		// and a password: no client_id, no audience parameter, and it never
		// calls /oauth/token. It CANNOT supply an audience, so the server must
		// assign one. This case is not optional.
		got, err := env.audSvc.ResolveMintAudience(env.ctx, auth.AudienceRequest{})
		if err != nil {
			t.Fatalf("ResolveMintAudience: %v", err)
		}
		if got.Value != auth.AudienceSelf {
			t.Errorf("audience = %q, want %q", got.Value, auth.AudienceSelf)
		}
		if got.Source != auth.AudienceSourceServer {
			t.Errorf("source = %q, want %q", got.Source, auth.AudienceSourceServer)
		}
	})

	t.Run("case 2: a client asking for nothing gets its own audience", func(t *testing.T) {
		// THE EMC INSURANCE CASE. This is what keeps a live integrator working
		// with zero changes: they pass no audience parameter and start receiving
		// a token whose aud names their own API.
		got, err := env.audSvc.ResolveMintAudience(env.ctx, auth.AudienceRequest{AppRowID: appRowID})
		if err != nil {
			t.Fatalf("ResolveMintAudience: %v", err)
		}
		if got.Value != app.Audience {
			t.Errorf("audience = %q, want the client's own %q", got.Value, app.Audience)
		}
		if got.Source != auth.AudienceSourceClientSelf {
			t.Errorf("source = %q, want %q", got.Source, auth.AudienceSourceClientSelf)
		}
	})

	t.Run("case 1: an explicit granted audience is honoured", func(t *testing.T) {
		resource, err := env.appSvc.CreateApplication(env.ctx, env.tenantID, uniqueAppName("aud131-resource"), "m2m", nil)
		if err != nil {
			t.Fatalf("CreateApplication: %v", err)
		}
		if _, err := env.audSvc.CreateGrant(env.ctx, env.tenantID, appRowID, resource.Audience, []string{"orders:read"}); err != nil {
			t.Fatalf("CreateGrant: %v", err)
		}

		got, err := env.audSvc.ResolveMintAudience(env.ctx, auth.AudienceRequest{
			AppRowID:  appRowID,
			Requested: resource.Audience,
		})
		if err != nil {
			t.Fatalf("ResolveMintAudience: %v", err)
		}
		if got.Value != resource.Audience {
			t.Errorf("audience = %q, want %q", got.Value, resource.Audience)
		}
		if len(got.GrantedScopes) != 1 || got.GrantedScopes[0] != "orders:read" {
			t.Errorf("granted scopes = %v, want [orders:read]", got.GrantedScopes)
		}
	})

	t.Run("case 4: a client with no stored audience omits the claim", func(t *testing.T) {
		// A pre-migration row, or one whose name slugified to nothing. Nulled
		// directly because the API cannot produce this state any more, and the
		// point is that a row already in this state keeps working.
		bare, err := env.appSvc.CreateApplication(env.ctx, env.tenantID, uniqueAppName("aud131-bare"), "m2m", nil)
		if err != nil {
			t.Fatalf("CreateApplication: %v", err)
		}
		bareID, _ := strconv.ParseInt(bare.ID, 10, 64)
		// The self-grant has to go first, and that is not a test workaround —
		// see TestAudienceCannotBeChangedEvenBySQL. The composite foreign key
		// refuses to let a referenced audience be updated at all.
		if _, err := env.pool.Exec(env.ctx,
			`DELETE FROM oauth_client_grants WHERE client_id = $1`, bareID); err != nil {
			t.Fatalf("drop self grant: %v", err)
		}
		if _, err := env.pool.Exec(env.ctx,
			`UPDATE oauth_clients SET audience = NULL WHERE id = $1`, bareID); err != nil {
			t.Fatalf("null the audience: %v", err)
		}

		got, err := env.audSvc.ResolveMintAudience(env.ctx, auth.AudienceRequest{AppRowID: bareID})
		if err != nil {
			t.Fatalf("ResolveMintAudience: %v", err)
		}
		if got.Value != "" {
			t.Errorf("audience = %q, want empty so the claim is omitted", got.Value)
		}
		if got.Source != auth.AudienceSourceNone {
			t.Errorf("source = %q, want %q", got.Source, auth.AudienceSourceNone)
		}

		// ...unless the client asked for enforcement, which is the #132 switch.
		if _, err := env.pool.Exec(env.ctx,
			`UPDATE oauth_clients SET require_audience = true WHERE id = $1`, bareID); err != nil {
			t.Fatalf("set require_audience: %v", err)
		}
		if _, err := env.audSvc.ResolveMintAudience(env.ctx, auth.AudienceRequest{AppRowID: bareID}); !errors.Is(err, auth.ErrAudienceRequired) {
			t.Errorf("with require_audience = true, error = %v, want ErrAudienceRequired", err)
		}
	})
}

// TestAudienceCannotBeChangedEvenBySQL records a guarantee that turned out to
// be stronger than designed, found by a test failing for the right reason.
//
// Issue #131 §4 says there is "no update path on audience at all", and the Go
// side delivers that by having no field to set (TestAppUpdate_HasNoAudienceField).
// The composite foreign key added in migration 00087 goes further: because it
// references (tenant_id, audience) and declares no ON UPDATE action, Postgres
// refuses to UPDATE a referenced audience — including to NULL, and including
// from psql.
//
// So immutability is not merely "the API offers no setter". It is enforced for
// every writer, which is the standard the reserved-namespace CHECK is held to.
// An operator who genuinely must retire an identifier deletes its grants first,
// which is an explicit two-step act rather than a silent re-point.
//
// ON UPDATE CASCADE would defeat this and must not be added: it would let a
// rename propagate cleanly through the grant table and break every resource
// server validating the old value, which is the failure the immutability rule
// exists to prevent.
func TestAudienceCannotBeChangedEvenBySQL(t *testing.T) {
	env := newAudienceEnv(t)

	app, err := env.appSvc.CreateApplication(env.ctx, env.tenantID, uniqueAppName("aud131-immutable"), "m2m", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appRowID, _ := strconv.ParseInt(app.ID, 10, 64)

	for _, attempt := range []struct{ name, sql string }{
		{"rename", `UPDATE oauth_clients SET audience = 'api://emc/somewhere-else' WHERE id = $1`},
		{"clear", `UPDATE oauth_clients SET audience = NULL WHERE id = $1`},
	} {
		t.Run(attempt.name, func(t *testing.T) {
			if _, err := env.pool.Exec(env.ctx, attempt.sql, appRowID); err == nil {
				t.Error("direct SQL changed a referenced audience: immutability is not enforced at the database level")
			}
		})
	}

	// The audience is still what it was.
	got, err := env.appSvc.GetApplication(env.ctx, env.tenantID, appRowID)
	if err != nil {
		t.Fatalf("GetApplication: %v", err)
	}
	if got.Audience != app.Audience {
		t.Errorf("audience = %q, want the original %q", got.Audience, app.Audience)
	}
}

// TestUngrantedAudience_IsIndistinguishableFromNonexistent is the
// anti-enumeration property, and it is the reason resolveTargetGrant has
// exactly one failure return.
//
// Two distinguishable answers would let any client with credentials enumerate
// every audience in the deployment by diffing the errors — a map of every
// tenant's internal API surface.
func TestUngrantedAudience_IsIndistinguishableFromNonexistent(t *testing.T) {
	env := newAudienceEnv(t)

	client, err := env.appSvc.CreateApplication(env.ctx, env.tenantID, uniqueAppName("aud131-probe"), "m2m", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	clientID, _ := strconv.ParseInt(client.ID, 10, 64)

	// A real audience this client holds no grant for.
	ungranted, err := env.appSvc.CreateApplication(env.ctx, env.tenantID, uniqueAppName("aud131-ungranted"), "m2m", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}

	probes := map[string]string{
		"exists but not granted": ungranted.Audience,
		"does not exist":         "api://emc/" + uniqueAppName("nope"),
		"another tenant's shape": "api://someone-else/their-api",
		"malformed":              "not-an-audience",
		"reserved":               auth.AudienceSelf + "/admin",
	}

	var messages []string
	for name, probe := range probes {
		_, err := env.audSvc.ResolveMintAudience(env.ctx, auth.AudienceRequest{
			AppRowID:  clientID,
			Requested: probe,
		})
		if !errors.Is(err, auth.ErrInvalidTarget) {
			t.Fatalf("%s: error = %v, want ErrInvalidTarget", name, err)
		}
		messages = append(messages, err.Error())
	}
	for i := range messages {
		if messages[i] != messages[0] {
			t.Fatalf("refusal messages differ: %q vs %q. Any difference is an enumeration oracle for the deployment's API inventory",
				messages[0], messages[i])
		}
	}
}

// TestAudienceGrantDenials_IsActuallyIncremented is the assertion CLAUDE.md
// deferred #12 is missing.
//
// A counter that is declared but never incremented reads as a flat zero, which
// is indistinguishable from "no denials happened" — and #132 would then ship on
// evidence that does not exist. RateLimitHits has been in exactly that state
// for months.
func TestAudienceGrantDenials_IsActuallyIncremented(t *testing.T) {
	env := newAudienceEnv(t)

	client, err := env.appSvc.CreateApplication(env.ctx, env.tenantID, uniqueAppName("aud131-metric"), "m2m", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	clientID, _ := strconv.ParseInt(client.ID, 10, 64)

	before := testutil.CollectAndCount(metrics.AudienceGrantDenials)
	if _, err := env.audSvc.ResolveMintAudience(env.ctx, auth.AudienceRequest{
		AppRowID:  clientID,
		Requested: "api://emc/" + uniqueAppName("denied"),
	}); !errors.Is(err, auth.ErrInvalidTarget) {
		t.Fatalf("expected ErrInvalidTarget, got %v", err)
	}
	if after := testutil.CollectAndCount(metrics.AudienceGrantDenials); after <= before {
		t.Errorf("emc_auth_audience_grant_denials_total series count = %d, was %d: the denial counter did not move. "+
			"Without it a refusal is invisible, because the client is told invalid_target either way", after, before)
	}
}

// TestRefresh_CannotChangeItsAudience pins the audience to the refresh chain.
//
// Without the pin a client could obtain a token for API A, then rotate its
// refresh token while naming API B and walk from one grant to another without
// ever presenting a credential for B.
func TestRefresh_CannotChangeItsAudience(t *testing.T) {
	env := newAudienceEnv(t)

	email := uniqueEmail("aud131-refresh")
	tokens := registerAndLogin(t, env.authSvc, email, "Password123!")

	// A first-party login: no client, so the server's own audience.
	if got := audOne(t, tokens.AccessToken); got != auth.AudienceSelf {
		t.Fatalf("first-party login aud = %q, want %q", got, auth.AudienceSelf)
	}

	rotated, err := env.authSvc.Refresh(env.ctx, tokens.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := audOne(t, rotated.AccessToken); got != auth.AudienceSelf {
		t.Errorf("rotated aud = %q, want the pinned %q", got, auth.AudienceSelf)
	}

	// And the pin is really on the row, not merely re-derived. A chain whose
	// audience was cleared behaves as pre-#131 rather than inventing one.
	var stored *string
	if err := env.pool.QueryRow(env.ctx,
		`SELECT audience FROM refresh_tokens WHERE token_hash = $1`,
		auth.HashToken(rotated.RefreshToken)).Scan(&stored); err != nil {
		t.Fatalf("read pinned audience: %v", err)
	}
	if stored == nil || *stored != auth.AudienceSelf {
		t.Errorf("stored pin = %v, want %q", stored, auth.AudienceSelf)
	}
}

// TestClientCredentials_KeepsWorkingWithNoAudienceParameter is the
// zero-changes-for-integrators claim, exercised end to end through the real
// mint path.
func TestClientCredentials_KeepsWorkingWithNoAudienceParameter(t *testing.T) {
	env := newAudienceEnv(t)

	app, err := env.appSvc.CreateApplication(env.ctx, env.tenantID, uniqueAppName("aud131-m2m"), "m2m", []string{"orders:read"})
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	_, appRowID, err := env.appSvc.AuthenticateClient(env.ctx, app.ClientID, app.ClientSecret)
	if err != nil {
		t.Fatalf("AuthenticateClient: %v", err)
	}

	token, _, err := env.authSvc.IssueServiceToken(env.ctx, env.tenantID, appRowID, "")
	if err != nil {
		t.Fatalf("IssueServiceToken: %v", err)
	}
	if got := audOne(t, token); got != app.Audience {
		t.Errorf("aud = %q, want the client's own %q", got, app.Audience)
	}

	// And an ungranted audience on the same path is refused.
	if _, _, err := env.authSvc.IssueServiceToken(env.ctx, env.tenantID, appRowID, "api://emc/"+uniqueAppName("nope")); !errors.Is(err, auth.ErrInvalidTarget) {
		t.Errorf("IssueServiceToken(ungranted) error = %v, want ErrInvalidTarget", err)
	}
}

// TestGrantScopes_AreIntersected proves a token never carries a scope the grant
// omits, on the client_credentials path where registered scopes become the
// permissions array directly.
func TestGrantScopes_AreIntersected(t *testing.T) {
	env := newAudienceEnv(t)

	resource, err := env.appSvc.CreateApplication(env.ctx, env.tenantID, uniqueAppName("aud131-api"), "m2m", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	// The client is registered for two scopes...
	client, err := env.appSvc.CreateApplication(env.ctx, env.tenantID, uniqueAppName("aud131-caller"), "m2m",
		[]string{"orders:read", "orders:write"})
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	clientRowID, _ := strconv.ParseInt(client.ID, 10, 64)
	// ...but the grant permits only one.
	if _, err := env.audSvc.CreateGrant(env.ctx, env.tenantID, clientRowID, resource.Audience, []string{"orders:read"}); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}

	token, _, err := env.authSvc.IssueServiceToken(env.ctx, env.tenantID, clientRowID, resource.Audience)
	if err != nil {
		t.Fatalf("IssueServiceToken: %v", err)
	}

	var claims auth.Claims
	if _, _, err := jwt.NewParser().ParseUnverified(token, &claims); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if len(claims.Permissions) != 1 || claims.Permissions[0] != "orders:read" {
		t.Errorf("permissions = %v, want [orders:read]: a token must never carry a scope the grant omits", claims.Permissions)
	}
	if got := audOne(t, token); got != resource.Audience {
		t.Errorf("aud = %q, want %q", got, resource.Audience)
	}
}

// TestIDToken_IsRejectedAsAnAccessToken. An ID token's aud is the client_id
// (OIDC Core §2), which is deliberately NOT an audience identifier and NOT a
// grant. It carries no gty, so verification falls to the legacy branch, where
// a client_id maps to no grants at all.
//
// This is the confusion that per-API audiences make easy to attempt: both
// tokens now carry a plausible-looking aud, so the test states out loud that
// one cannot stand in for the other.
func TestIDToken_IsRejectedAsAnAccessToken(t *testing.T) {
	env := newAudienceEnv(t)

	app, err := env.appSvc.CreateApplication(env.ctx, env.tenantID, uniqueAppName("aud131-idtoken"), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}

	jwtSvc := newTestJWTService(t, env.pool, testIssuer)
	idToken, err := jwtSvc.SignIDToken(env.ctx, auth.IDTokenParams{
		TenantID:      env.tenantID,
		ClientID:      app.ClientID,
		GrantedScopes: []string{auth.ScopeOpenID},
	}, auth.IDTokenSubject{UserID: "1"})
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}

	// Rejected — but note WHERE, because the reason is not the one you would
	// predict and asserting the predicted one would have made this test a lie.
	//
	// An ID token never reaches the audience check at all: IDTokenClaims carries
	// no tenant_id claim, so key resolution fails first and the token is refused
	// as unverifiable. That is a STRONGER refusal than ErrUnexpectedAudience —
	// it fails before any claim is trusted — and it holds for a structural
	// reason (an ID token describes a user to a client and has no tenant scope
	// of its own) rather than because of a policy list that could be edited.
	//
	// So this test asserts rejection, and deliberately does not pin the
	// sentinel: pinning it would make a future improvement to key resolution
	// look like a regression.
	if _, err := jwtSvc.Verify(env.ctx, idToken); err == nil {
		t.Fatal("an ID token verified as an access token: aud is the client_id, which is not a grant and must not satisfy any route")
	}

	// The property that matters for #131: the two aud values are different
	// shapes, so neither can be mistaken for the other. An ID token's aud is a
	// client_id ("app_..."), an access token's is an audience identifier
	// ("api://tenant/app"), and no verify path maps a client_id to any grant.
	if got := audOne(t, idToken); got != app.ClientID {
		t.Errorf("ID token aud = %q, want the client_id %q", got, app.ClientID)
	}
	if strings.HasPrefix(audOne(t, idToken), auth.AudienceSchemeDefault) {
		t.Error("ID token aud looks like an audience identifier; it must stay the client_id so the two token kinds cannot be confused")
	}
}

// TestRevoke_CannotCrossClientsWithinATenant covers CLAUDE.md deferred #22,
// closed by refresh_tokens.application_id in migration 00087.
//
// Client authentication was already required and the UPDATE was already scoped
// by tenant, so this was never an unauthenticated hole. What remained is that
// two clients inside ONE tenant could revoke each other's tokens, because there
// was no column to compare an authenticated client_id against.
func TestRevoke_CannotCrossClientsWithinATenant(t *testing.T) {
	env := newAudienceEnv(t)

	owner, err := env.appSvc.CreateApplication(env.ctx, env.tenantID, uniqueAppName("aud131-owner"), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	ownerID, _ := strconv.ParseInt(owner.ID, 10, 64)
	other, err := env.appSvc.CreateApplication(env.ctx, env.tenantID, uniqueAppName("aud131-other"), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	otherID, _ := strconv.ParseInt(other.ID, 10, 64)

	// A refresh token belonging to the first client.
	email := uniqueEmail("aud131-revoke")
	if _, err := env.authSvc.Register(env.ctx, auth.RegisterInput{
		Email: email, Password: "Password123!", FirstName: "T", LastName: "U",
		ClientID: owner.ClientID, ClientSecret: owner.ClientSecret,
	}); err != nil {
		t.Fatalf("Register(app-scoped): %v", err)
	}
	login, err := env.authSvc.Login(env.ctx, auth.LoginInput{
		Email: email, Password: "Password123!",
		ClientID: owner.ClientID, ClientSecret: owner.ClientSecret,
	})
	if err != nil || login.Token == nil {
		t.Fatalf("Login(app-scoped): %v", err)
	}

	// The other client in the same tenant must not be able to revoke it.
	revoked, err := env.authSvc.RevokeRefreshTokenForTenant(env.ctx, login.Token.RefreshToken, env.tenantID, otherID)
	if err != nil {
		t.Fatalf("RevokeRefreshTokenForTenant: %v", err)
	}
	if revoked {
		t.Error("another client in the same tenant revoked this client's refresh token (CLAUDE.md deferred #22)")
	}

	// The owning client can.
	revoked, err = env.authSvc.RevokeRefreshTokenForTenant(env.ctx, login.Token.RefreshToken, env.tenantID, ownerID)
	if err != nil {
		t.Fatalf("RevokeRefreshTokenForTenant(owner): %v", err)
	}
	if !revoked {
		t.Error("the owning client could not revoke its own refresh token")
	}
}

// TestAppScopedLogin_CarriesTheClientsAudience is the other half of the
// zero-changes claim: an app-authenticated USER login, not just a machine
// token, gets the application's audience.
func TestAppScopedLogin_CarriesTheClientsAudience(t *testing.T) {
	env := newAudienceEnv(t)

	app, err := env.appSvc.CreateApplication(env.ctx, env.tenantID, uniqueAppName("aud131-applogin"), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}

	email := uniqueEmail("aud131-appuser")
	if _, err := env.authSvc.Register(env.ctx, auth.RegisterInput{
		Email: email, Password: "Password123!", FirstName: "T", LastName: "U",
		ClientID: app.ClientID, ClientSecret: app.ClientSecret,
	}); err != nil {
		t.Fatalf("Register(app-scoped): %v", err)
	}
	login, err := env.authSvc.Login(env.ctx, auth.LoginInput{
		Email: email, Password: "Password123!",
		ClientID: app.ClientID, ClientSecret: app.ClientSecret,
	})
	if err != nil || login.Token == nil {
		t.Fatalf("Login(app-scoped): %v", err)
	}

	if got := audOne(t, login.Token.AccessToken); got != app.Audience {
		t.Errorf("app-scoped login aud = %q, want the application's own %q", got, app.Audience)
	}

	// And the rotation keeps it — the pin, on the path an application actually
	// uses.
	rotated, err := env.authSvc.Refresh(env.ctx, login.Token.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := audOne(t, rotated.AccessToken); got != app.Audience {
		t.Errorf("rotated app-scoped aud = %q, want %q", got, app.Audience)
	}
}
