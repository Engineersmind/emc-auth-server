package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
