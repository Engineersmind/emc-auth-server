package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// IDTokenTTL is the lifetime of an OIDC ID token.
//
// Matched to the access token rather than made longer. An ID token is a
// statement about an authentication event that the client consumes once, at
// sign-in, to establish its own session; it is not a credential to be presented
// back to us. A long-lived one only widens the window in which a stale
// assertion still validates.
const IDTokenTTL = AccessTokenTTL

// IDTokenClaims is the OIDC Core §2 ID token payload.
//
// Separate from Claims, and deliberately so. The two differ in the one field
// that matters most:
//
//	Claims.aud    is this server's token-TYPE discriminator (emc-auth-api,
//	              emc-auth-m2m, …) — issue #84's defence against a machine
//	              token acting as a user.
//	IDTokenClaims.aud is the client_id, as OIDC Core requires, so a client can
//	              confirm the token was minted for it and not for some other
//	              application.
//
// Those two meanings cannot share a claim, and audienceAllowed permits exactly
// one audience value, so an ID token cannot go through Sign. The collision is
// tracked as CLAUDE.md deferred item #10 (move token type to `gty`, free `aud`
// for the audience identifier); minting ID tokens on their own path keeps #6
// unblocked without starting that migration.
//
// There is no VerifyIDToken and there must not be one. An ID token is never
// presented back to this server for authorization — accepting one anywhere
// would reintroduce exactly the token-confusion #84 closed, since its `aud` is
// an attacker-registerable client_id rather than a fixed token type.
type IDTokenClaims struct {
	// Nonce binds the token to the client's authorization request (OIDC Core
	// §3.1.2.1). Omitted when the request carried none. Security audit
	// 2026-08-07 FED-3 requires it before an inbound authorize endpoint exists.
	Nonce string `json:"nonce,omitempty"`

	// AuthTime is when the user actually authenticated, which is not the same
	// as when this token was issued: a code redeemed 50 seconds after login
	// produces iat=now, auth_time=50s ago. Clients enforcing a max_age compare
	// against this.
	AuthTime int64 `json:"auth_time,omitempty"`

	// AtHash is the access token hash (OIDC Core §3.1.3.6) — left half of
	// SHA-256 of the access token, base64url. It lets a client that received
	// both in one response confirm they belong together, which is what stops an
	// attacker substituting their own access token alongside a genuine ID token.
	AtHash string `json:"at_hash,omitempty"`

	// Profile claims, released only when the granted scopes permit
	// (OIDC Core §5.4). A claim absent because its scope was not granted is
	// omitted entirely rather than sent empty — an empty string is a statement
	// that the value is empty, which is different from "not released".
	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	UpdatedAt     int64  `json:"updated_at,omitempty"`

	jwt.RegisteredClaims
}

// IDTokenSubject carries the user facts an ID token may describe. The caller
// loads these; this file decides which are released.
type IDTokenSubject struct {
	UserID        string
	Email         string
	EmailVerified bool
	Name          string
	GivenName     string
	FamilyName    string
	UpdatedAt     time.Time
}

// IDTokenParams is everything SignIDToken needs that is not the subject.
type IDTokenParams struct {
	TenantID int64
	// ClientID becomes the `aud` claim — the public client_id string, not the
	// numeric row id, because that is the value the client knows itself by.
	ClientID string
	// GrantedScopes gates which profile claims are released.
	GrantedScopes []string
	Nonce         string
	AuthTime      time.Time
	// AccessToken, when non-empty, produces the at_hash claim.
	AccessToken string
}

// ComputeAtHash returns the OIDC Core §3.1.3.6 at_hash for an access token:
// base64url(no padding) of the LEFT HALF of the SHA-256 digest.
//
// The left half, not the whole digest. The spec derives the half-length from
// the signing algorithm's hash size — RS256 means SHA-256, so 32 bytes becomes
// the leading 16. Sending the full digest produces a value every conformant
// client rejects.
func ComputeAtHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// SignIDToken mints an OIDC ID token for a completed authorization.
//
// `sub` is the raw user_id, matching what Sign already puts in the access
// token's Subject and what /oauth/userinfo returns. OIDC Core requires the ID
// token's sub, the access token's sub and UserInfo's sub to agree; a different
// value here would give one person two identities. (Settled in #7a — pairwise
// subjects remain possible later as a per-client setting, applied only to a
// client that has never received a subject.)
//
// The token is signed with the tenant's RS256 key and carries the tenant's
// issuer, so a client following `iss` → discovery → `jwks_uri` reaches the key
// set that verifies it — the chain #7a completed.
func (s *JWTService) SignIDToken(ctx context.Context, p IDTokenParams, subj IDTokenSubject) (string, error) {
	issuer, err := s.issuerFor(ctx, p.TenantID)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()

	claims := &IDTokenClaims{
		Nonce: p.Nonce,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:     uuid.New().String(),
			Issuer: issuer,
			// aud = client_id. See the type comment for why this cannot be one
			// of the AudienceXxx token-type constants.
			Audience:  jwt.ClaimStrings{p.ClientID},
			Subject:   subj.UserID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(IDTokenTTL)),
		},
	}
	if !p.AuthTime.IsZero() {
		claims.AuthTime = p.AuthTime.Unix()
	}
	if p.AccessToken != "" {
		claims.AtHash = ComputeAtHash(p.AccessToken)
	}

	// Scope-gated claims. `openid` alone releases nothing beyond `sub` — that
	// is the whole of OIDC Core §5.4's contract, and releasing an email to a
	// client that only asked for `openid` would hand over data the user's
	// consent (when it exists) never covered.
	if HasScope(p.GrantedScopes, ScopeEmail) {
		claims.Email = subj.Email
		verified := subj.EmailVerified
		claims.EmailVerified = &verified
	}
	if HasScope(p.GrantedScopes, ScopeProfile) {
		claims.Name = subj.Name
		claims.GivenName = subj.GivenName
		claims.FamilyName = subj.FamilyName
		if !subj.UpdatedAt.IsZero() {
			claims.UpdatedAt = subj.UpdatedAt.Unix()
		}
	}

	return s.signClaims(ctx, p.TenantID, claims, "id token")
}
