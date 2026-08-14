package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// Claims is the full JWT payload for emc-auth tokens.
// It embeds jwt.RegisteredClaims for standard fields (iss, aud, exp, sub, iat).
//
// AppID is set when the token was issued through a registered application
// (X-Client-ID on login/register, or the client_credentials grant).
// It is omitted from the JSON payload when empty so existing tokens without
// it remain valid — the Verify path ignores missing optional claims.
type Claims struct {
	UserID      string   `json:"user_id"`
	TenantID    string   `json:"tenant_id"`
	AppID       string   `json:"app_id,omitempty"`
	Email       string   `json:"email"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	// AdminScope and AdminApps describe how far the caller's tenant-administration
	// rights reach across the tenant's applications (issue #97). Permissions say
	// WHAT an administrator may do; these say WHICH applications they may do it
	// to. Both are empty for ordinary end users, who hold no admin permissions
	// and never reach the guarded routes anyway.
	//
	// AdminScope is AdminScopeTenant for a tenant owner (and for API-key
	// management tokens), or AdminScopeApps for a co-owner, in which case
	// AdminApps lists the application row ids they administer.
	AdminScope string   `json:"admin_scope,omitempty"`
	AdminApps  []string `json:"admin_apps,omitempty"`
	// SessionID is the OIDC "sid" claim: the session (refresh-token family) this
	// access token was minted into.
	//
	// It is what makes one session revocable on its own: the middleware checks this
	// value against a short-lived denylist and refuses exactly the revoked session.
	//
	// Without it there is no way to invalidate a live access token at all. The
	// users.token_version column reads like the account-wide equivalent, and several
	// revocation paths bump it, but nothing in this codebase verifies that counter —
	// it has never affected token validity. The denylist is the only mechanism.
	//
	// Named "sid" on the wire because that is the OIDC-registered claim name
	// (OIDC Core, and required by back-channel logout), so a standards-aware
	// relying party already knows how to read it.
	//
	// Empty on tokens minted before this claim existed and on tokens that have no
	// session at all — client-credentials and agent tokens. Absence therefore
	// means "not session-scoped" and must never be treated as a wildcard: the
	// denylist check skips an empty sid rather than blocking on it, which is safe
	// because such tokens cannot be revoked per-session anyway. A user token with
	// no sid is still covered account-wide, since the denylist check also consults
	// a per-account key derived from the user and tenant claims.
	SessionID string `json:"sid,omitempty"`

	// Scope is the space-delimited OAuth scope set granted to this token
	// (RFC 6749 §3.3), populated only by the authorization code flow (issue #6).
	//
	// EMPTY MEANS UNSCOPED, NOT UNAUTHORIZED — and that asymmetry is deliberate,
	// unlike AdminScope above where the empty string is denied.
	//
	// Every token minted before #6, and every first-party token minted today by
	// password login, registration, refresh rotation, MFA completion, magic
	// link, social callback and SAML, carries no scope claim. Those flows have
	// no scope concept: the user authenticated directly to us and the token
	// stands for the whole of that account. Treating their empty scope as
	// "grants nothing" would break every existing consumer at once.
	//
	// The two claims differ because they answer different questions. AdminScope
	// bounds how far an administrator's reach extends, so an unset value must
	// fail closed. Scope records what a third-party client was granted, and only
	// a flow that can grant scopes ever sets it — so an unset value means the
	// question was never asked, and the caller is a first-party holder of a full
	// session.
	//
	// Consumers must therefore branch on presence, not on content:
	// no claim → release everything, as before; claim present → release only
	// what it lists.
	Scope string `json:"scope,omitempty"`

	jwt.RegisteredClaims
}

// ScopeList splits the space-delimited Scope claim. Returns nil when the claim
// is absent, which callers must distinguish from an empty granted set — see the
// Scope field comment.
func (c *Claims) ScopeList() []string {
	if c.Scope == "" {
		return nil
	}
	return strings.Fields(c.Scope)
}

// Admin scope values for Claims.AdminScope.
//
// The empty string is NOT a third tier meaning "unrestricted" — RequireAppScope
// denies it. Treating the zero value as tenant-wide would make any future bug
// that forgets to populate the claim fail open, which is the wrong direction
// for the claim that bounds administrative reach.
//
// The cost is that access tokens minted before this claim existed are refused
// on per-application admin routes. Access tokens live 15 minutes and both
// refresh rotation and the renewal middleware re-mint them with the claim
// populated, so the window is short and self-healing.
const (
	// AdminScopeTenant grants administration of every application in the
	// caller's own tenant, including applications created after the token was
	// issued. Held by tenant owners and API-key management tokens.
	AdminScopeTenant = "tenant"
	// AdminScopeApps restricts administration to the applications listed in
	// Claims.AdminApps. Held by co-owners.
	AdminScopeApps = "apps"
)

// AgentClaims is the JWT payload for machine-to-machine agent tokens (08-01).
type AgentClaims struct {
	AgentID      string   `json:"agent_id"`
	TenantID     string   `json:"tenant_id"`
	AgentType    string   `json:"agent_type"`
	Capabilities []string `json:"capabilities"`
	jwt.RegisteredClaims
}

// AgentTokenTTL is the lifetime of an agent access token.
const AgentTokenTTL = 1 * time.Hour

// Token audiences. The "aud" claim is this server's token-type discriminator:
// it records which flow minted a token so verification can refuse a token that
// was issued for a different purpose (issue #84). Every token is signed with
// exactly one audience.
//
// Audience alone is not authorization — permissions/role still gate what a
// caller may do. Audience answers the prior question: "is this kind of token
// even accepted on this route?"
const (
	// AudienceAPI marks human/end-user session tokens: password login,
	// registration, refresh rotation, MFA completion, magic link, social
	// (OAuth/OIDC) callback, and SAML JIT login.
	AudienceAPI = "emc-auth-api"

	// AudienceM2M marks client_credentials service tokens (no user behind
	// them; Role is "service" and Permissions come from oauth_clients.scopes).
	AudienceM2M = "emc-auth-m2m"

	// AudienceManagement marks short-lived tokens exchanged from an API key
	// via POST /auth/management-token.
	AudienceManagement = "emc-auth-management"

	// AudienceAgent marks agent tokens minted by SignAgent. No verification
	// path consumes these yet — see SignAgent.
	AudienceAgent = "emc-auth-agent"
)

// ErrUnexpectedAudience is returned when a token is well-formed and correctly
// signed but was minted for a different audience than the caller accepts —
// e.g. a service (M2M) token presented on a user self-service route. This is a
// token-confusion / replay signal, not an ordinary expiry, so it is a distinct
// sentinel that middleware can count and log separately.
var ErrUnexpectedAudience = errors.New("jwt: unexpected audience")

// ErrNoAudienceAllowed guards against a programming error: calling
// VerifyForAudience with an empty allow-list would otherwise silently accept
// every audience, defeating the check.
var ErrNoAudienceAllowed = errors.New("jwt: no allowed audience specified")

// ErrEmptyIssuer is returned by NewJWTService when no issuer is configured.
// Verification enforces iss unconditionally, so a service without an issuer
// could never verify its own tokens — fail at construction, not at request time.
var ErrEmptyIssuer = errors.New("jwt: issuer must not be empty")

// ErrUnexpectedIssuer is returned when a token is well-formed and correctly
// signed but its "iss" is neither the issuer of the tenant it claims nor the
// legacy global issuer.
//
// A distinct sentinel rather than a generic parse failure because the two mean
// different things operationally: an expired token is routine, whereas a validly
// signed token bearing a foreign issuer means either a stale token past the
// migration window or another deployment sharing our key material. Both are worth
// counting and logging separately.
var ErrUnexpectedIssuer = errors.New("jwt: unexpected issuer")

// JWTService signs and verifies JWTs using a per-tenant HS256 secret.
type JWTService struct {
	pool *pgxpool.Pool
	// issuer is the legacy server-wide value for the "iss" claim (JWT_ISSUER).
	//
	// Since issue #7 it is no longer what new tokens carry when issuers is set —
	// see issuerFor. It remains the value accepted on the legacy verification
	// branch, and the sole issuer for embedders that never wire a resolver.
	issuer string
	// issuers resolves the per-tenant OIDC issuer (issue #7). When nil the
	// service stays on the single global issuer, which is the pre-#7 behaviour
	// and what tests and any embedder that has not wired it still get.
	issuers *TenantIssuerResolver
	// allowLegacyIssuer keeps tokens carrying the global issuer verifiable during
	// the migration window. Setting it false is the cutover.
	//
	// Only meaningful when issuers != nil; without a resolver the global issuer is
	// the only issuer, and refusing it would leave nothing able to verify anything.
	allowLegacyIssuer bool
	// keys supplies per-tenant asymmetric signing keys (issue #95). When nil the
	// service stays on legacy symmetric HS256; when set, tokens are signed RS256
	// and verification resolves the key by the token's kid header.
	keys *SigningKeyService
	// allowLegacyHS256 keeps the symmetric verification path alive during the
	// migration window (issue #95, Phases 2–3). Setting it false is the Phase 4
	// cutover: HS256 is refused outright and both algorithm pins narrow to RS256.
	//
	// Only meaningful when keys != nil; without signing keys, refusing HS256 would
	// leave nothing able to verify anything.
	allowLegacyHS256 bool
}

// NewJWTService creates a JWTService backed by the given pool.
// issuer should be the server's base URL, e.g. "https://auth.emc.local".
//
// An empty issuer is rejected at construction rather than tolerated at verify
// time: every token this server mints carries iss, so verification enforces it
// unconditionally. Allowing an empty issuer would make that check depend on a
// runtime value and silently disable it on a misconfigured deploy, letting a
// token minted by another server that shares the tenant secret pass.
//
// Without WithSigningKeys the service signs HS256 with the per-tenant secret —
// the pre-#95 behaviour, retained so tests and any embedder that has not wired
// the key service keep working.
func NewJWTService(pool *pgxpool.Pool, issuer string) (*JWTService, error) {
	if issuer == "" {
		return nil, ErrEmptyIssuer
	}
	return &JWTService{pool: pool, issuer: issuer}, nil
}

// WithSigningKeys switches signing to asymmetric RS256 using per-tenant key pairs
// (issue #95, Phase 2). Verification then accepts RS256 by kid *and* legacy HS256
// without one, so tokens minted before the switch stay valid until they expire.
func (s *JWTService) WithSigningKeys(keys *SigningKeyService) *JWTService {
	s.keys = keys
	// Accept legacy HS256 by default: switching signing to RS256 must not
	// invalidate tokens minted moments earlier. WithLegacyHS256(false) performs the
	// Phase 4 cutover once none are left in circulation.
	s.allowLegacyHS256 = true
	return s
}

// WithLegacyHS256 controls whether symmetric HS256 tokens still verify
// (issue #95, Phase 4 cutover).
//
// Passing false is the one-way step that actually removes the forging risk this
// issue exists to fix: until HS256 is refused, anyone holding a tenant's
// jwt_secret can still mint a token for any user in that tenant, no matter how
// good the asymmetric path is. Phases 2–3 add the capability to verify safely;
// only this removes the capability to forge.
//
// Do not flip it until no live HS256 token remains. The evidence for that is the
// emc_auth_legacy_hs256_verifications_total counter sitting at zero, not a
// stopwatch. The longest-lived symmetric token is the 1 h agent token.
func (s *JWTService) WithLegacyHS256(allow bool) *JWTService {
	s.allowLegacyHS256 = allow
	return s
}

// WithTenantIssuers switches the "iss" claim from the single global JWT_ISSUER to
// a per-tenant OIDC issuer (issue #7). Verification then accepts the tenant's own
// issuer *and* the legacy global value, so tokens minted before the switch stay
// valid until they expire.
//
// Deliberately mirrors WithSigningKeys: same opt-in shape, same
// accept-both-during-migration default, same cutover switch. The two migrations
// are the same problem one step apart — #95 made the key per-tenant, this makes
// the identifier that names that key per-tenant.
func (s *JWTService) WithTenantIssuers(issuers *TenantIssuerResolver) *JWTService {
	s.issuers = issuers
	// Accept the legacy issuer by default: switching mint behaviour must not
	// invalidate tokens minted moments earlier. WithLegacyIssuer(false) performs
	// the cutover once none are left in circulation.
	s.allowLegacyIssuer = true
	return s
}

// WithLegacyIssuer controls whether tokens carrying the old global issuer still
// verify (issue #7 cutover).
//
// Do not flip it until no live token carries the old issuer. The evidence for that
// is emc_auth_legacy_issuer_verifications_total sitting at zero, not elapsed time.
func (s *JWTService) WithLegacyIssuer(allow bool) *JWTService {
	s.allowLegacyIssuer = allow
	return s
}

// issuerFor returns the "iss" value to mint for a tenant: the tenant's own OIDC
// issuer when a resolver is wired, otherwise the legacy global value.
func (s *JWTService) issuerFor(ctx context.Context, tenantID int64) (string, error) {
	if s.issuers == nil {
		return s.issuer, nil
	}
	issuer, err := s.issuers.Issuer(ctx, tenantID)
	if err != nil {
		// Deliberately fails the mint rather than falling back to the global
		// issuer. A silent fallback would emit a token whose iss does not match
		// the discovery document a relying party fetched, which fails at the
		// relying party — far from the cause, and only for some tenants.
		return "", err
	}
	return issuer, nil
}

// issuerAllowed checks a verified token's "iss" against the issuer of the tenant
// it claims, falling back to the legacy global issuer during the migration.
//
// It runs after signature verification, alongside the audience check and for the
// same reason: only then is the tenant_id claim trustworthy enough to decide which
// issuer the token should have carried. golang-jwt's WithIssuer option cannot
// express this — it compares against one constant string, decided before the token
// is parsed, whereas the expected value here depends on the token's own contents.
//
// Both checks live at the single choke point every verification passes through, so
// neither can be skipped by a new caller.
func (s *JWTService) issuerAllowed(ctx context.Context, claims *Claims) error {
	if s.issuers == nil {
		// Pre-#7 behaviour, byte-for-byte: one issuer, exact match. Previously
		// enforced by jwt.WithIssuer inside the parser.
		if claims.Issuer != s.issuer {
			return fmt.Errorf("verify jwt: got %q, want %q: %w",
				claims.Issuer, s.issuer, ErrUnexpectedIssuer)
		}
		return nil
	}

	// An empty tenant_id cannot name an expected issuer. Fail rather than fall
	// through to the legacy branch, which would let a token omit the claim to
	// pick the weaker check.
	tenantID, err := strconv.ParseInt(claims.TenantID, 10, 64)
	if err != nil {
		return fmt.Errorf("verify jwt: invalid tenant_id %q: %w", claims.TenantID, ErrUnexpectedIssuer)
	}

	expected, err := s.issuers.Issuer(ctx, tenantID)
	if err == nil && claims.Issuer == expected {
		return nil
	}
	// A resolver error is not fatal on its own: the token may legitimately be a
	// pre-#7 one, which the legacy branch below can still accept. It does mean the
	// per-tenant comparison could not be made, so the token gets no better than
	// legacy treatment.

	if claims.Issuer == s.issuer {
		if !s.allowLegacyIssuer {
			metrics.LegacyIssuerVerifications.WithLabelValues("rejected").Inc()
			return fmt.Errorf("verify jwt: legacy issuer %q is no longer accepted: %w",
				claims.Issuer, ErrUnexpectedIssuer)
		}
		metrics.LegacyIssuerVerifications.WithLabelValues("accepted").Inc()
		return nil
	}

	if err != nil {
		return fmt.Errorf("verify jwt: cannot resolve issuer for tenant %d: %w", tenantID, err)
	}
	return fmt.Errorf("verify jwt: got %q, want %q: %w", claims.Issuer, expected, ErrUnexpectedIssuer)
}

// signingKeyFor returns the tenant's active asymmetric key, or nil when the
// service is still in legacy HS256 mode.
func (s *JWTService) signingKeyFor(ctx context.Context, tenantID int64) (*SigningKey, error) {
	if s.keys == nil {
		return nil, nil
	}
	// Ensure rather than plain lookup: a tenant created before this feature (or by
	// a fixture / restored backup) would otherwise be unable to issue any token.
	key, err := s.keys.EnsureTenantKey(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve signing key for tenant %d: %w", tenantID, err)
	}
	return key, nil
}

// signClaims signs claims for a tenant, choosing the algorithm by configuration:
// RS256 with the tenant's private key when asymmetric signing is wired, HS256
// with the tenant's shared secret otherwise.
//
// Every token this server mints goes through here, so the kid header and the
// algorithm choice cannot drift between token types — the class of bug where one
// forgotten Sign* path keeps emitting the old format.
func (s *JWTService) signClaims(ctx context.Context, tenantID int64, claims jwt.Claims, what string) (string, error) {
	key, err := s.signingKeyFor(ctx, tenantID)
	if err != nil {
		return "", err
	}

	if key != nil {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = key.KID
		signed, err := token.SignedString(key.Private)
		if err != nil {
			return "", fmt.Errorf("sign %s (RS256): %w", what, err)
		}
		return signed, nil
	}

	// Legacy symmetric fallback, reached only when no signing keys are wired.
	// No kid is set: a kid must name a key a verifier can actually resolve, and a
	// symmetric secret appears in no JWKS. Emitting an identifier that looks like a
	// key ID but resolves to nothing would send verifiers on a lookup that cannot
	// succeed. Absence is the honest signal, and the verify path already treats a
	// missing kid as "legacy, use the tenant secret".
	secret, err := s.tenantSecret(ctx, tenantID)
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("sign %s: %w", what, err)
	}
	return signed, nil
}

// tenantSecret fetches the jwt_secret for the given tenant from the DB.
func (s *JWTService) tenantSecret(ctx context.Context, tenantID int64) (string, error) {
	var secret string
	err := s.pool.QueryRow(ctx,
		`SELECT jwt_secret FROM tenants WHERE id = $1 AND is_active = true`,
		tenantID,
	).Scan(&secret)
	if err != nil {
		return "", fmt.Errorf("fetch tenant jwt_secret: %w", err)
	}
	if secret == "" {
		return "", errors.New("tenant jwt_secret is empty")
	}
	return secret, nil
}

// AccessTokenTTL is the lifetime of an access token (AUTH-06).
// 15 minutes matches the API contract; transparent middleware renewal keeps
// browser sessions alive without client-side retry logic.
const AccessTokenTTL = 15 * time.Minute

// AccessTokenTTLSeconds is AccessTokenTTL as a whole number of seconds.
// Division of a constant Duration by time.Second is a constant expression,
// whereas AccessTokenTTL.Seconds() is a method call — so this is the form
// callers can use in const declarations and compile-time assertions.
//
// Typed int64 rather than left as time.Duration: the quotient of two Durations
// is still a Duration, and a Duration named "…Seconds" is exactly the
// unit-confusion ST1011 exists to catch.
const AccessTokenTTLSeconds int64 = int64(AccessTokenTTL / time.Second)

// RefreshTokenTTL is the lifetime of a refresh token (AUTH-06).
const RefreshTokenTTL = 30 * 24 * time.Hour

// ManagementTokenTTL is the lifetime of an API-key-derived management token.
// Short-lived by design — callers must re-exchange the API key to get a new one.
const ManagementTokenTTL = 15 * time.Minute

// Sign creates and signs a JWT for the given claims using the tenant's HS256 secret.
func (s *JWTService) Sign(ctx context.Context, tenantID int64, audience string, c *Claims) (string, error) {
	issuer, err := s.issuerFor(ctx, tenantID)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	c.RegisteredClaims = jwt.RegisteredClaims{
		ID:        uuid.New().String(),
		Issuer:    issuer,
		Audience:  jwt.ClaimStrings{audience},
		Subject:   c.UserID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(AccessTokenTTL)),
	}
	return s.signClaims(ctx, tenantID, c, "jwt")
}

// SignManagement issues a short-lived management JWT from an API key identity.
// The token carries the API key's permissions so it can call /admin/* endpoints
// for the key's tenant — equivalent to Auth0's client_credentials management token.
func (s *JWTService) SignManagement(ctx context.Context, identity *APIKeyIdentity) (string, error) {
	issuer, err := s.issuerFor(ctx, identity.TenantID)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	claims := &Claims{
		UserID:   "key:" + strconv.FormatInt(identity.KeyID, 10),
		TenantID: strconv.FormatInt(identity.TenantID, 10),
		Email:    identity.Name + "@apikey",
		Role:     "api_key",
		// An API key belongs to the tenant, not to any one application, and its
		// permissions were already scoped when the key was issued. Without this
		// the key would lose access to every per-application admin route the
		// moment RequireAppScope starts guarding them.
		AdminScope:  AdminScopeTenant,
		Permissions: identity.Permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{AudienceManagement},
			Subject:   "key:" + strconv.FormatInt(identity.KeyID, 10),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ManagementTokenTTL)),
		},
	}

	return s.signClaims(ctx, identity.TenantID, claims, "management token")
}

// SignAgent creates and signs a JWT for an authenticated agent identity.
// Uses the tenant's HS256 secret — same trust boundary as user JWTs.
//
// NOTE: nothing in this server verifies these tokens yet — there is no
// VerifyAgent and no middleware consuming AudienceAgent (Phase 8 "AI/Agent
// Security" is still partial). Because tokens are minted with AudienceAgent and
// no verify path allows that audience, an agent token cannot be replayed
// against user, management, or M2M routes. Wiring agent-token verification is
// tracked separately from issue #84.
func (s *JWTService) SignAgent(ctx context.Context, identity *AgentIdentity) (string, error) {
	issuer, err := s.issuerFor(ctx, identity.TenantID)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	claims := &AgentClaims{
		AgentID:      identity.AgentID.String(),
		TenantID:     strconv.FormatInt(identity.TenantID, 10),
		AgentType:    identity.AgentType,
		Capabilities: identity.Capabilities,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{AudienceAgent},
			Subject:   identity.AgentID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(AgentTokenTTL)),
		},
	}

	return s.signClaims(ctx, identity.TenantID, claims, "agent jwt")
}

// Verify parses and validates a user/session JWT (AudienceAPI only).
//
// It is the strict default: tokens minted for any other audience — M2M service
// tokens, API-key management tokens, agent tokens — are rejected with
// ErrUnexpectedAudience. Routes that legitimately accept more than one token
// type must say so explicitly via VerifyForAudience.
func (s *JWTService) Verify(ctx context.Context, tokenString string) (*Claims, error) {
	return s.VerifyForAudience(ctx, tokenString, AudienceAPI)
}

// VerifyM2M parses and validates a client_credentials service token
// (AudienceM2M only), rejecting user, management, and agent tokens.
func (s *JWTService) VerifyM2M(ctx context.Context, tokenString string) (*Claims, error) {
	return s.VerifyForAudience(ctx, tokenString, AudienceM2M)
}

// VerifyForAudience parses and validates a JWT string, accepting it only if its
// "aud" claim is one of allowed. Key resolution happens inside the keyfunc (see
// below), and signature, algorithm, issuer, expiry, and audience are all
// verified before the claims are returned.
//
// Audience is checked only after the signature is proven, so an attacker cannot
// use the audience result to learn anything about an unsigned token.
//
// Callers pass the set of token types a route accepts, e.g. admin routes accept
// {AudienceAPI, AudienceManagement, AudienceM2M} because a human operator, an
// API-key integration, and a machine client are all legitimate admin callers,
// whereas user self-service routes accept {AudienceAPI} alone.
// Passing no audience is a programming error (ErrNoAudienceAllowed) rather than
// a silent "allow everything".
func (s *JWTService) VerifyForAudience(ctx context.Context, tokenString string, allowed ...string) (*Claims, error) {
	if len(allowed) == 0 {
		return nil, ErrNoAudienceAllowed
	}

	// Algorithm pins. There are TWO of them — this option and the keyfunc's own
	// method check below — and both must list an algorithm for it to be accepted.
	// Phase 2 widens both to {RS256, HS256}; Phase 4 narrows both to RS256 alone.
	// Relaxing only one would be an alg-substitution hole.
	methods := []string{jwt.SigningMethodHS256.Alg()}
	switch {
	case s.keys != nil && s.allowLegacyHS256:
		// Migration window (Phases 2–3): sign RS256, verify either.
		methods = []string{jwt.SigningMethodRS256.Alg(), jwt.SigningMethodHS256.Alg()}
	case s.keys != nil:
		// Phase 4 cutover: RS256 only. Narrowed here AND in the keyfunc below.
		methods = []string{jwt.SigningMethodRS256.Alg()}
	}
	opts := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods(methods),
		// iss is NOT checked here. Since issue #7 the expected issuer depends on
		// which tenant the token claims, and jwt.WithIssuer can only compare
		// against one string fixed before parsing. The check moved to
		// issuerAllowed below, after the signature is proven — see there. It is
		// still enforced unconditionally and on every path, because it sits at
		// this same single choke point, next to the audience check.
	}

	// Key resolution happens inside the keyfunc, which is what closes ME-07.
	//
	// Previously this function ran a separate ParseUnverified pass purely to read
	// tenant_id and fetch a secret, so any unauthenticated caller could drive a DB
	// query with a garbage token (REVIEW_PR4_PR5.md:435,650 — DB-lookup
	// amplification). golang-jwt decodes the header and claims BEFORE invoking the
	// keyfunc, so everything that pass provided is already available here for free.
	//
	// For RS256 the key is chosen by the header's kid alone and no claim is
	// consulted, so the asymmetric path performs no claim-driven DB read at all.
	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodRSA:
			return s.rsaKeyForToken(ctx, t)
		case *jwt.SigningMethodHMAC:
			return s.legacyHMACKeyForToken(ctx, t)
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
	}, opts...)
	if err != nil {
		return nil, fmt.Errorf("verify jwt: %w", err)
	}
	if !parsed.Valid {
		return nil, errors.New("jwt is not valid")
	}

	// Issuer and audience checks run last — the signature is proven at this
	// point, so the token really was minted by us and its claims can be trusted
	// to decide what it should have carried.
	if err := s.issuerAllowed(ctx, claims); err != nil {
		return nil, err
	}
	if !audienceAllowed(claims.Audience, allowed) {
		return nil, fmt.Errorf("verify jwt: got %v, want one of %v: %w",
			[]string(claims.Audience), allowed, ErrUnexpectedAudience)
	}
	return claims, nil
}

// tenantIDFromToken reads the tenant_id claim off a token whose signature is not
// yet verified.
//
// It is the untrusted-input problem in miniature: the value decides which key we
// fetch, so a caller picks the lookup. Both key paths call it — the RS256 path
// uses it to scope the kid lookup to a tenant — so the exposure is the same for
// each, and the caches it can reach are what bound it. See rsaKeyForToken for the
// trust model that applies there.
func tenantIDFromToken(t *jwt.Token) (int64, error) {
	claims, ok := t.Claims.(*Claims)
	if !ok || claims.TenantID == "" {
		return 0, errors.New("jwt missing tenant_id claim")
	}
	tenantID, err := strconv.ParseInt(claims.TenantID, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid tenant_id in jwt: %w", err)
	}
	return tenantID, nil
}

// rsaKeyForToken resolves the public key for an RS256 token from its kid header.
//
// The kid lookup is scoped to the token's tenant, which is what makes tenant
// isolation cryptographic rather than advisory: a token claiming tenant B cannot
// be verified with tenant A's key even if it names A's kid, because that kid is
// not in B's key set. This is the property per-tenant keys exist to preserve —
// with a single server-wide key it would rest entirely on the tenant_id claim.
//
// The trust model, stated precisely, because it is easy to overclaim: the tenant
// used for scoping comes from the token's *unverified* tenant_id claim, so an
// unauthenticated caller does choose which tenant's key set is consulted. That is
// not a bypass — naming a different tenant only makes the lookup miss, and a hit
// still has to survive signature verification — but it does mean this path is not
// header-only, and the DB reads it can drive are what must stay bounded. Two
// things bound them: SigningKeyService caches per tenant and collapses concurrent
// misses into one load, and it declines to cache a tenant that resolves to no
// keys, so cycling arbitrary ids cannot grow the cache.
//
// Making the lookup genuinely header-only means encoding the tenant into the kid
// (tenant:thumbprint). That is deferred deliberately: the kid is currently an
// RFC 7638 thumbprint that any verifier can recompute from the published JWKS to
// confirm a kid names the key it claims to, and prefixing it forfeits that check
// for every already-published key. It is worth doing at the next kid-format
// change, not as a review fix that would silently break external verifiers.
func (s *JWTService) rsaKeyForToken(ctx context.Context, t *jwt.Token) (interface{}, error) {
	if s.keys == nil {
		// Asymmetric signing is not configured, so an RS256 token cannot be one of
		// ours. Refuse rather than reach for some other key.
		return nil, errors.New("RS256 token but asymmetric signing is not configured")
	}
	kid, ok := t.Header["kid"].(string)
	if !ok || kid == "" {
		// RS256 without a kid is unresolvable: we hold one key pair per tenant per
		// rotation generation and have no way to choose. Trial-verifying against
		// every key would turn verification into an oracle.
		return nil, errors.New("RS256 token has no kid header")
	}
	tenantID, err := tenantIDFromToken(t)
	if err != nil {
		return nil, err
	}
	pub, err := s.keys.PublicKeyByKID(ctx, tenantID, kid)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// legacyHMACKeyForToken resolves the per-tenant shared secret for an HS256 token.
//
// This is the pre-#95 path, kept alive through Phases 2–3 so tokens minted before
// the asymmetric switch keep working until they expire, and removed in Phase 4.
// Every call increments LegacyHS256Verifications: that counter reaching and
// staying at zero is the evidence that gates the Phase 4 cutover, replacing the
// original plan of waiting out AgentTokenTTL and hoping.
func (s *JWTService) legacyHMACKeyForToken(ctx context.Context, t *jwt.Token) (interface{}, error) {
	// The second of the two algorithm pins. WithValidMethods above already refuses
	// HS256 after the cutover; this makes the refusal independent of that option, so
	// no single change can silently re-open the symmetric path.
	if s.keys != nil && !s.allowLegacyHS256 {
		metrics.LegacyHS256Verifications.WithLabelValues("rejected").Inc()
		return nil, errors.New("HS256 tokens are no longer accepted")
	}

	reason := "no_kid"
	if kid, ok := t.Header["kid"].(string); ok && kid != "" {
		// A symmetric token carrying a kid did not come from a current code path —
		// nothing we mint sets one on the HS256 branch. Worth distinguishing in the
		// metric because it means either a very old token or a forged header.
		reason = "unexpected_kid"
	}
	metrics.LegacyHS256Verifications.WithLabelValues(reason).Inc()

	tenantID, err := tenantIDFromToken(t)
	if err != nil {
		return nil, err
	}
	secret, err := s.tenantSecret(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return []byte(secret), nil
}

// audienceAllowed reports whether aud names exactly one audience and that
// audience is in allowed.
//
// The single-value requirement is deliberate: every Sign* method in this package
// mints exactly one audience, so a multi-valued aud did not come from a current
// code path and must not be able to satisfy a route by carrying one acceptable
// value alongside others.
func audienceAllowed(aud jwt.ClaimStrings, allowed []string) bool {
	if len(aud) != 1 {
		return false
	}
	for _, want := range allowed {
		if aud[0] == want {
			return true
		}
	}
	return false
}
