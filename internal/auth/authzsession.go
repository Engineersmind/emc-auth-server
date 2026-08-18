package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Server-side state for the hosted login pages at /oauth/authorize (issue #6).
//
// Two records, both in Redis, both keyed by the SHA-256 of a random handle so a
// database or cache dump yields nothing redeemable — the same shape as
// OAuthState in oauthflow.go.
//
//	AuthzRequest — an authorization request parked while the user logs in.
//	AuthzSession — proof that a user completed login at this endpoint.

const (
	// authzRequestTTL bounds how long a user may sit on the login page.
	// Generous enough to type a password and fetch a code from a phone,
	// short enough that an abandoned request does not stay resumable.
	authzRequestTTL = 15 * time.Minute

	// AuthzSessionTTL is how long a completed hosted login is remembered, so a
	// user moving between applications is not asked for their password again.
	//
	// This is the SSO window and it is deliberately modest. It is not an access
	// token: it authorizes nothing on its own, it only lets /oauth/authorize
	// mint a code without re-prompting.
	AuthzSessionTTL = 12 * time.Hour

	// authzNonceTTL is how long a burned nonce is remembered (security audit
	// 2026-08-07, FED-3).
	//
	// Set to the ID token lifetime, because that is the whole window in which a
	// replayed nonce could buy an attacker anything. The nonce exists so a client
	// can confirm an ID token answers the authentication request it started
	// (OIDC Core §3.1.2.1); a second ID token carrying the same nonce is only
	// useful while it is still valid. Once it has expired the client rejects it
	// on `exp` before it ever looks at `nonce`, so remembering the value beyond
	// that point costs Redis keys and prevents nothing.
	//
	// Deliberately NOT authzRequestTTL. A parked request may sit on the login
	// page for 15 minutes, but the nonce is not burned until a code is actually
	// issued, so the clock starts at issuance and not at arrival.
	authzNonceTTL = IDTokenTTL

	// AuthzSessionCookie is the browser cookie holding the SSO session handle.
	//
	// Deliberately NOT the portal's emc_access_token. Two reasons, either
	// sufficient on its own:
	//
	//  1. #101 made cookie sessions unavailable to application-scoped logins on
	//     purpose (errCookieSessionForApps). Reusing that cookie here would
	//     quietly reintroduce what that issue removed.
	//  2. The portal cookie is set on the API origin, so /oauth/authorize would
	//     see a tenant ADMINISTRATOR's console session and silently sign them
	//     into any tenant's application. An admin session and an end-user
	//     session at a tenant application are different subjects with different
	//     blast radii; conflating them is a privilege boundary failure.
	AuthzSessionCookie = "emc_authz_session"
)

var (
	// ErrAuthzRequestNotFound is returned when a login-page submission carries a
	// handle that has expired, was already used, or never existed.
	ErrAuthzRequestNotFound = errors.New("oauth: authorization request expired or not found")

	// ErrAuthzSessionNotFound is returned when no valid SSO session backs the
	// presented cookie.
	ErrAuthzSessionNotFound = errors.New("oauth: no active authorization session")

	// ErrNonceReplayed is returned by BurnNonce when this client has already had
	// an authorization code issued against the same nonce value.
	ErrNonceReplayed = errors.New("oauth: nonce has already been used")
)

// AuthzRequest is a validated authorization request held while the user
// authenticates.
//
// Every field is captured at /oauth/authorize AFTER validation and is read back
// from here — never re-read from the form the browser posts. A login form that
// carried its own redirect_uri or scope would let anyone who can render a form
// at our origin choose where the code goes.
type AuthzRequest struct {
	ClientID      string   `json:"client_id"`
	TenantID      int64    `json:"tenant_id"`
	AppRowID      int64    `json:"app_row_id"`
	RedirectURI   string   `json:"redirect_uri"`
	Scopes        []string `json:"scopes"`
	State         string   `json:"state"`
	Nonce         string   `json:"nonce"`
	CodeChallenge string   `json:"code_challenge"`

	// AppName is the client's display name, captured from the same LookupClient
	// call that validated the client at /oauth/authorize.
	//
	// Carried here purely so the login and MFA pages do not re-query
	// oauth_clients on every render — a page can be re-rendered on each failed
	// password or OTP attempt, which is exactly the path that should not be
	// doing avoidable DB work. Cosmetic: it is only ever interpolated into a
	// page title and is never read for a security decision, which is why
	// carrying it in the parked request is safe.
	AppName string `json:"app_name,omitempty"`

	// OTPSessionToken is set once a password has been accepted and a second
	// factor is outstanding, carrying the challenge across to the MFA page.
	OTPSessionToken string `json:"otp_session_token,omitempty"`
	// OTPMethods mirrors the challenge's available methods for rendering.
	OTPMethods []string `json:"otp_methods,omitempty"`

	// Email is recorded once the password step succeeds, so the identity of the
	// authenticated user survives into the MFA step.
	//
	// It must be carried here rather than re-read from the form: the MFA page
	// posts only a code and a handle, and adding an email field to it would
	// mean accepting the identity from a form after the password that proved it
	// was already checked — letting anyone who reaches the MFA page name a
	// different account.
	Email string `json:"email,omitempty"`
}

// AuthzSession is a completed hosted login.
//
// It holds only the identity, not tokens. The access and refresh tokens for a
// given application are minted at the token endpoint from a code; keeping a
// token pair in the SSO record would mean one browser session held live
// credentials for every application the user ever visited.
type AuthzSession struct {
	UserID   int64     `json:"user_id"`
	TenantID int64     `json:"tenant_id"`
	Email    string    `json:"email"`
	AuthTime time.Time `json:"auth_time"`
}

// AuthzSessionStore persists both records.
type AuthzSessionStore struct {
	redis *redis.Client
}

// NewAuthzSessionStore constructs the store.
func NewAuthzSessionStore(rdb *redis.Client) *AuthzSessionStore {
	return &AuthzSessionStore{redis: rdb}
}

func authzRequestKey(handle string) string { return "oauth:authz:req:" + HashToken(handle) }
func authzSessionKey(handle string) string { return "oauth:authz:sess:" + HashToken(handle) }

// authzNonceKey scopes a burned nonce to the tenant and client that chose it.
//
// Scoped per client, not global. A nonce is only meaningful relative to the
// client that generated it, and clients pick their own values — a global key
// space would let one client with a weak generator (a counter, a fixed string in
// a test suite) refuse another client's legitimate sign-ins. tenant_id is
// included even though client_id is globally unique, so the key carries the same
// isolation boundary as every other record in this file.
//
// The tuple is hashed rather than interpolated: the nonce is arbitrary input off
// a query string, so putting it in the key verbatim would give a caller a say in
// the Redis key space and no bound on its size.
//
// clientID and nonce are hashed INDIVIDUALLY before being joined, so the fields
// cannot run together. Joining the raw values on ":" would leave the boundary
// ambiguous the moment either contained one — client_id ("a:b", nonce "c") and
// client_id ("a", nonce "b:c") would be the same key, which is a nonce from one
// client silently spending another's. Fixed-width digests make the join
// injective.
func authzNonceKey(tenantID int64, clientID, nonce string) string {
	return "oauth:authz:nonce:" + HashToken(
		strconv.FormatInt(tenantID, 10)+":"+HashToken(clientID)+":"+HashToken(nonce))
}

// BurnNonce claims a nonce for one authorization code and refuses it thereafter
// (security audit 2026-08-07, FED-3). An empty nonce is a no-op: OIDC Core makes
// it OPTIONAL for the authorization-code flow, so its absence is not a replay.
//
// SET NX is what makes this a burn rather than a check: the test and the claim
// are one Redis round-trip, so two authorize requests arriving together cannot
// both observe the nonce as unused. A separate EXISTS-then-SET would be exactly
// the race this is meant to close.
//
// Fails CLOSED — a Redis error refuses the request. That is not a new outage
// mode: /oauth/authorize already cannot function without Redis (SaveRequest
// parks every request there, and the SSO short-circuit reads its session from
// there), so there is no state of the world in which failing open here keeps a
// working flow alive. It would only mean that the one component whose failure is
// most likely to be induced deliberately is also the one that disables this
// check.
func (s *AuthzSessionStore) BurnNonce(ctx context.Context, tenantID int64, clientID, nonce string) error {
	if nonce == "" {
		return nil
	}
	ok, err := s.redis.SetNX(ctx, authzNonceKey(tenantID, clientID, nonce), "1", authzNonceTTL).Result()
	if err != nil {
		return fmt.Errorf("burn authz nonce: %w", err)
	}
	if !ok {
		return ErrNonceReplayed
	}
	return nil
}

// ReleaseNonce un-burns a nonce, for use when the code issuance that the burn
// was claimed for then failed.
//
// Without this, a transient database error while minting the code would leave
// the nonce spent: the client's perfectly reasonable retry of the same
// authorization request would come back as a replay, turning a recoverable
// blip into a sign-in that stays broken for the TTL. The burn only needs to hold
// when a code was actually issued.
//
// Best-effort. If the release itself fails the caller is already returning an
// error to the client, and the nonce expires on its own.
func (s *AuthzSessionStore) ReleaseNonce(ctx context.Context, tenantID int64, clientID, nonce string) {
	if nonce == "" {
		return
	}
	_ = s.redis.Del(ctx, authzNonceKey(tenantID, clientID, nonce)).Err()
}

// SaveRequest stores a parked authorization request and returns its handle.
func (s *AuthzSessionStore) SaveRequest(ctx context.Context, req *AuthzRequest) (string, error) {
	handle, err := GenerateRefreshToken()
	if err != nil {
		return "", fmt.Errorf("generate authz request handle: %w", err)
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("marshal authz request: %w", err)
	}
	if err := s.redis.Set(ctx, authzRequestKey(handle), payload, authzRequestTTL).Err(); err != nil {
		return "", fmt.Errorf("store authz request: %w", err)
	}
	return handle, nil
}

// GetRequest reads a parked request WITHOUT consuming it.
//
// Non-consuming because a wrong password must leave the request resumable —
// burning it on the first failed attempt would send the user back to the client
// application with an error after one typo. Single-use is enforced where it
// matters instead: on the authorization code, which is consumed atomically.
func (s *AuthzSessionStore) GetRequest(ctx context.Context, handle string) (*AuthzRequest, error) {
	if handle == "" {
		return nil, ErrAuthzRequestNotFound
	}
	raw, err := s.redis.Get(ctx, authzRequestKey(handle)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrAuthzRequestNotFound
		}
		return nil, fmt.Errorf("load authz request: %w", err)
	}
	var req AuthzRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("unmarshal authz request: %w", err)
	}
	return &req, nil
}

// UpdateRequest rewrites a parked request in place, preserving its remaining
// TTL. Used to attach the OTP challenge after a password is accepted.
//
// KEEPTTL matters: refreshing the expiry on every step would let an attacker
// who holds a handle keep a half-completed login alive indefinitely by
// replaying the password step.
func (s *AuthzSessionStore) UpdateRequest(ctx context.Context, handle string, req *AuthzRequest) error {
	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal authz request: %w", err)
	}
	return s.redis.Set(ctx, authzRequestKey(handle), payload, redis.KeepTTL).Err()
}

// DeleteRequest consumes a parked request once a code has been issued for it.
func (s *AuthzSessionStore) DeleteRequest(ctx context.Context, handle string) {
	// Best-effort: the code has already been issued and the request carries no
	// authority on its own. Failing the response over a cache delete would turn
	// a successful login into an error the user cannot act on.
	_ = s.redis.Del(ctx, authzRequestKey(handle)).Err()
}

// CreateSession records a completed login and returns the cookie handle.
func (s *AuthzSessionStore) CreateSession(ctx context.Context, sess *AuthzSession) (string, error) {
	handle, err := GenerateRefreshToken()
	if err != nil {
		return "", fmt.Errorf("generate authz session handle: %w", err)
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		return "", fmt.Errorf("marshal authz session: %w", err)
	}
	if err := s.redis.Set(ctx, authzSessionKey(handle), payload, AuthzSessionTTL).Err(); err != nil {
		return "", fmt.Errorf("store authz session: %w", err)
	}
	return handle, nil
}

// GetSession resolves a cookie handle to a completed login.
func (s *AuthzSessionStore) GetSession(ctx context.Context, handle string) (*AuthzSession, error) {
	if handle == "" {
		return nil, ErrAuthzSessionNotFound
	}
	raw, err := s.redis.Get(ctx, authzSessionKey(handle)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrAuthzSessionNotFound
		}
		return nil, fmt.Errorf("load authz session: %w", err)
	}
	var sess AuthzSession
	if err := json.Unmarshal(raw, &sess); err != nil {
		return nil, fmt.Errorf("unmarshal authz session: %w", err)
	}
	return &sess, nil
}

// DeleteSession ends an SSO session.
func (s *AuthzSessionStore) DeleteSession(ctx context.Context, handle string) {
	if handle == "" {
		return
	}
	_ = s.redis.Del(ctx, authzSessionKey(handle)).Err()
}
