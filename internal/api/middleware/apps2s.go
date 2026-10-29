package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	redisv9 "github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
	"github.com/engineersmind/emc-auth-server/internal/requestctx"
)

// ---------------------------------------------------------------------------
// Rate limiting for application backends calling on behalf of their users.
//
// THE PROBLEM
//
// Every end-user route that takes application credentials (/auth/apps/*,
// /auth/forgot-password, /auth/reset-password, /auth/token) used to sit behind
// limiters keyed on the caller's IP (5/min) and its client_id (10/min). A product
// backend presents ONE egress IP and ONE client_id for all of its users, so a
// whole product was throttled as if it were one person, and the application's
// own app_rate_limits row — checked afterwards — could only lower that.
//
// THE MODEL
//
// The same one Auth0, Okta and Cognito use: volume is limited per application,
// abuse is limited per user, and a trusted backend may report the user's IP.
//
//	1. Resolve      identify the caller; per-IP flood guard (skipped for the
//	                application's registered server IPs); strict per-IP limit for
//	                callers whose credentials did not verify.
//	2. App quota    AppClientRateLimiter, the application's app_rate_limits row.
//	3. Per user     UserLimit, keyed on client_id + the user the request is about.
//
// Resolve never rejects a request for bad credentials. Handlers keep owning that
// answer — /forgot-password deliberately replies 200 to an unknown client, and
// /reset-password accepts no credentials at all — so a middleware 401 would
// change behaviour integrators rely on. It only decides which limits apply.
// ---------------------------------------------------------------------------

// ForwardedForHeader carries the end user's IP from a trusted backend. See
// AppS2S.resolveEndUserIP for when it is believed.
const ForwardedForHeader = "X-EMC-Forwarded-For"

// appCallerKey is the echo context key for the resolved *AppCaller.
const appCallerKey = "emc.app_caller"

// AppCaller is what Resolve learned about the calling application.
type AppCaller struct {
	// ClientID as presented. Unverified unless Verified is true.
	ClientID string
	// HasCredentials is true when a non-empty client secret was presented. A
	// Basic header with an empty secret (a public OAuth client) does not count.
	HasCredentials bool
	// Verified is true when the client secret checked out against an active
	// application.
	Verified bool
	// Failed is true when the secret was checked and is wrong. Distinct from
	// "not verified": a database error leaves both false, and the request is
	// then treated like one that presented no credentials rather than as a
	// guess.
	Failed bool
	// TenantID and AppID identify the application: set when Verified, or when
	// a client_id without a secret arrived from that application's registered
	// server IP (ServerIP).
	TenantID int64
	AppID    int64
	// ConnIP is the address the request arrived from (c.RealIP()).
	ConnIP string
	// ServerIP is true when ConnIP is a registered server IP of the application
	// the client_id names.
	ServerIP bool
	// EndUserIP is the end user's address: the forwarded value when Forwarded is
	// true, otherwise ConnIP.
	EndUserIP string
	Forwarded bool
}

// CallerFrom returns the caller Resolve stored on this request, if any.
func CallerFrom(c echo.Context) (*AppCaller, bool) {
	caller, ok := c.Get(appCallerKey).(*AppCaller)
	return caller, ok && caller != nil
}

// EndUserIP is the address to attribute this request to: the end user's IP when
// a trusted backend forwarded it, otherwise c.RealIP(). Handlers use it for the
// captcha counter, audit events and risk checks, so all of them see the person
// rather than the product's server.
func EndUserIP(c echo.Context) string {
	if caller, ok := CallerFrom(c); ok && caller.Forwarded {
		return caller.EndUserIP
	}
	return c.RealIP()
}

// ServerTrustLookup is the in-memory view of application server settings
// (auth.AppTrustService). It must not touch the database: it runs before the
// per-IP guard.
type ServerTrustLookup interface {
	Lookup(clientID string) (auth.ServerTrust, bool)
}

// ClientAuthenticator verifies application credentials
// (auth.ApplicationService).
type ClientAuthenticator interface {
	AuthenticateClient(ctx context.Context, clientID, clientSecret string) (tenantID, appID int64, err error)
}

// AppUserLimits are the per-user limits, per minute, for each route.
type AppUserLimits struct {
	Register        int
	Login           int
	MagicLink       int
	MagicLinkVerify int
	ForgotPassword  int
	ResetPassword   int
	Roles           int
	Me              int
	// The flows below were limited per IP only, so a backend completing them
	// for its users shared one small budget. For a proven backend they are
	// limited per end user instead (by forwarded IP, or by email).
	MFAChallenge       int // /auth/login/otp, /otp/resend, /login/mfa/*
	OAuthExchange      int // /auth/oauth/exchange
	PasskeyLogin       int // /auth/passkey/login/complete
	ResendVerification int // /auth/resend-verification
}

// AppS2SConfig sizes the limits. Zero values take the defaults, never "unlimited".
type AppS2SConfig struct {
	// PerIPRate is the flood guard for callers not on the application's server
	// list. Default DefaultAppPerIPRate.
	PerIPRate int
	// UnverifiedPerIPRate applies to callers whose credentials did not verify,
	// and to anonymous callers not on a server list. Default 5 (AUTH-07): this
	// is the bucket that bounds client-secret guessing.
	UnverifiedPerIPRate int
	// BadCredentialsPerClientRate bounds wrong secrets for one client_id across
	// every IP. Default 10, the per-client_id rate TokenRateLimiter applied.
	BadCredentialsPerClientRate int
	Users                       AppUserLimits
}

const (
	// DefaultAppPerIPRate is the flood guard per IP for application traffic that
	// is not from a registered server IP. 10/second: well above any one person,
	// and the bound on how fast an unregistered caller can make Resolve verify
	// credentials against the database.
	DefaultAppPerIPRate = 600
	// DefaultAppUnverifiedPerIPRate is AUTH-07's per-IP login rate.
	DefaultAppUnverifiedPerIPRate = 5
	// DefaultBadCredentialsPerClientRate is AUTH-07's per-client rate.
	DefaultBadCredentialsPerClientRate = 10
)

// DefaultAppUserLimits are the per-user limits used when none are configured.
//
// None is below what one user could already do through a single backend IP
// under the limiters this replaced (5/min per IP on every one of these routes),
// so no live integration gets a 429 it did not get before. They are an upper
// bound per user, not a reduction.
func DefaultAppUserLimits() AppUserLimits {
	return AppUserLimits{
		Register:        5,
		Login:           5,
		MagicLink:       5,
		MagicLinkVerify: 10,
		ForgotPassword:  5,
		ResetPassword:   10,
		Roles:           10,
		Me:              30,
		// Each equals what one address got before (OTPRateLimiter 10/min,
		// OAuthRateLimiter and TokenRateLimiter 5/min), now applied per end
		// user rather than shared by every user behind a backend.
		MFAChallenge:       10,
		OAuthExchange:      5,
		PasskeyLogin:       5,
		ResendVerification: 5,
	}
}

func (cfg AppS2SConfig) withDefaults() AppS2SConfig {
	def := DefaultAppUserLimits()
	pick := func(v, d int) int {
		if v <= 0 {
			return d
		}
		return v
	}
	cfg.PerIPRate = pick(cfg.PerIPRate, DefaultAppPerIPRate)
	cfg.UnverifiedPerIPRate = pick(cfg.UnverifiedPerIPRate, DefaultAppUnverifiedPerIPRate)
	cfg.BadCredentialsPerClientRate = pick(cfg.BadCredentialsPerClientRate, DefaultBadCredentialsPerClientRate)
	cfg.Users = AppUserLimits{
		Register:        pick(cfg.Users.Register, def.Register),
		Login:           pick(cfg.Users.Login, def.Login),
		MagicLink:       pick(cfg.Users.MagicLink, def.MagicLink),
		MagicLinkVerify: pick(cfg.Users.MagicLinkVerify, def.MagicLinkVerify),
		ForgotPassword:  pick(cfg.Users.ForgotPassword, def.ForgotPassword),
		ResetPassword:   pick(cfg.Users.ResetPassword, def.ResetPassword),
		Roles:           pick(cfg.Users.Roles, def.Roles),
		Me:              pick(cfg.Users.Me, def.Me),

		MFAChallenge:       pick(cfg.Users.MFAChallenge, def.MFAChallenge),
		OAuthExchange:      pick(cfg.Users.OAuthExchange, def.OAuthExchange),
		PasskeyLogin:       pick(cfg.Users.PasskeyLogin, def.PasskeyLogin),
		ResendVerification: pick(cfg.Users.ResendVerification, def.ResendVerification),
	}
	return cfg
}

// AppS2S builds the middleware for application end-user routes.
type AppS2S struct {
	cfg       AppS2SConfig
	trust     ServerTrustLookup
	clients   ClientAuthenticator
	limits    AppLimitLookup
	verified  *verifiedClientCache
	knownGood *knownGoodAddrs
	logger    zerolog.Logger
}

// WithRedis shares the "known good address" marks across instances, so a
// backend that verified on one instance is recognised on all of them. Without
// it each instance keeps its own.
func (s *AppS2S) WithRedis(rdb *redisv9.Client) *AppS2S {
	s.knownGood.rdb = rdb
	return s
}

// AppLimitLookup returns an application's configured quota
// (auth.AppRateLimitService).
type AppLimitLookup interface {
	GetLimit(ctx context.Context, tenantID, applicationID int64) (rpm, burst int)
}

// WithAppLimits lets the OAuth limiters raise a verified client's allowance to
// its application's quota. Without it they keep their fixed rates.
func (s *AppS2S) WithAppLimits(l AppLimitLookup) *AppS2S {
	s.limits = l
	return s
}

// appRPM is the caller's application quota, or 0 when unknown.
func (s *AppS2S) appRPM(ctx context.Context, caller *AppCaller) int {
	if s.limits == nil || !caller.Verified {
		return 0
	}
	rpm, _ := s.limits.GetLimit(ctx, caller.TenantID, caller.AppID)
	return rpm
}

// OAuthTokenLimit replaces OAuthTokenRateLimiter on POST /oauth/token.
//
// The legacy limit is a fixed 120/min per client_id. For an OIDC product that
// is the ceiling on every user's code exchange and every refresh, whatever the
// application's quota says. For a client whose secret verified, the limit is
// now the larger of 120 and the application's quota — never lower than before.
// Every other request (public clients, unverified secrets) goes through the
// legacy limiter unchanged. Mount after ResolveOAuthClient.
func (s *AppS2S) OAuthTokenLimit() echo.MiddlewareFunc {
	legacy := OAuthTokenRateLimiter()
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		viaLegacy := legacy(next)
		return func(c echo.Context) error {
			caller, ok := CallerFrom(c)
			if !ok || !caller.Verified {
				return viaLegacy(c)
			}
			// Its own key, not the legacy oauth_token:client:<id>: requests
			// with a wrong secret for this client_id still spend the legacy
			// bucket, and must not be able to empty the real client's.
			rate := max(OAuthTokenPerClientRate, s.appRPM(c.Request().Context(), caller))
			if !allowVia(c.Request().Context(), oauthTokenStore, "oauth_token", "oauth_token:verified:"+caller.ClientID, rate) {
				metrics.RateLimitHits.WithLabelValues("oauth_token").Inc()
				c.Response().Header().Set("Retry-After", "60")
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error":             "slow_down",
					"error_description": "too many token requests",
				})
			}
			return next(c)
		}
	}
}

// OAuthTokenLegacyExhausted peeks OAuthTokenRateLimiter's per-client bucket.
func OAuthTokenLegacyExhausted(c echo.Context, clientID string) bool {
	return exhaustedVia(c.Request().Context(), oauthTokenStore, "oauth_token", "oauth_token:client:"+clientID, OAuthTokenPerClientRate)
}

// OAuthRevokeLegacyExhausted peeks RevokeRateLimiter's per-IP bucket.
func OAuthRevokeLegacyExhausted(c echo.Context, _ string) bool {
	ip := c.RealIP()
	if ip == "" {
		ip = c.Request().RemoteAddr
	}
	return exhaustedVia(c.Request().Context(), revokeStore, "revoke", "revoke:ip:"+ip, RevokePerIPRate)
}

// OAuthRevokeLimit replaces RevokeRateLimiter on POST /oauth/revoke.
//
// The legacy limit is 60/min per IP: a backend revoking tokens as its users
// sign out shares that across all of them. A client whose secret verified keeps
// a per-IP limit — so a client calling from several addresses gets at least
// what it had on each — but at the larger of 60 and its application's quota,
// in a bucket of its own. Everyone else keeps the legacy per-IP limit. Mount
// after ResolveOAuthClient.
func (s *AppS2S) OAuthRevokeLimit() echo.MiddlewareFunc {
	legacy := RevokeRateLimiter()
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		viaLegacy := legacy(next)
		return func(c echo.Context) error {
			caller, ok := CallerFrom(c)
			if !ok || !caller.Verified {
				return viaLegacy(c)
			}
			rate := max(RevokePerIPRate, s.appRPM(c.Request().Context(), caller))
			key := "revoke:verified:" + caller.ClientID + ":" + caller.ConnIP
			if !allowVia(c.Request().Context(), revokeStore, "revoke", key, rate) {
				metrics.RateLimitHits.WithLabelValues("revoke").Inc()
				c.Response().Header().Set("Retry-After", "60")
				return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "slow_down"})
			}
			return next(c)
		}
	}
}

// NewAppS2S creates the middleware set. trust may be nil (no server lists, no
// forwarding); clients may be nil only in tests, in which case no caller ever
// verifies.
func NewAppS2S(cfg AppS2SConfig, trust ServerTrustLookup, clients ClientAuthenticator, logger zerolog.Logger) *AppS2S {
	startCleanup()
	return &AppS2S{
		cfg:       cfg.withDefaults(),
		trust:     trust,
		clients:   clients,
		verified:  newVerifiedClientCache(verifiedClientTTL, verifiedClientMax),
		knownGood: newKnownGoodAddrs(),
		logger:    logger,
	}
}

// UserLimits returns the effective per-user limits after defaults.
func (s *AppS2S) UserLimits() AppUserLimits { return s.cfg.Users }

// Surfaces name the groups of routes that share one strict per-IP bucket for
// anonymous and unverified callers. They are the two groups the limiters this
// replaced kept apart (token-ip and reset-ip), so an anonymous password reset
// never competes with, say, a captcha fetch from the same address — the same
// separation live integrations had before.
const (
	// SurfaceApp: /auth/token, /auth/apps/*, /captcha/challenge.
	SurfaceApp = "app"
	// SurfaceReset: /auth/forgot-password, /auth/reset-password.
	SurfaceReset = "reset"
	// The surfaces below are mounted with the optional resolvers, where only
	// credentials that FAILED reach the strict bucket; anonymous callers keep
	// the route's own limiter.
	SurfaceMFA     = "mfa"     // /auth/login/otp, /otp/resend, /login/mfa/*
	SurfaceOAuth   = "oauth"   // /auth/oauth/exchange, /oauth/token, /oauth/revoke
	SurfacePasskey = "passkey" // /auth/passkey/login/*
	SurfaceAccount = "account" // /auth/resend-verification
)

func headerCredentials(c echo.Context) (string, string, bool) {
	if id, secret, ok := basicCredentials(c.Request().Header.Get(echo.HeaderAuthorization)); ok {
		return id, secret, true
	}
	return basicCredentials(c.Request().Header.Get(ClientAuthHeader))
}

// resolveMode says how a route treats callers that do not prove themselves.
type resolveMode struct {
	// optional: the route does not require application credentials and keeps
	// its own per-IP limiter for anonymous callers, which Resolve leaves alone.
	optional bool
	// failedFallsBack: a secret that fails verification is left to the route's
	// own limiter instead of the bad-credential buckets. For the RFC 6749
	// endpoints, where a public client may legitimately send a secret the
	// handler ignores, and the legacy per-client limiter already bounded
	// guessing before this change.
	failedFallsBack bool
	// legacyExhausted, when set, peeks the route's legacy limiter for this
	// client without spending. See guardVerification.
	legacyExhausted func(c echo.Context, clientID string) bool
}

// Resolve identifies the caller from Authorization: Basic (or
// X-Client-Authorization on routes that also carry a user Bearer token) and
// applies the per-IP limits. Mount it first on every application route.
func (s *AppS2S) Resolve(surface string) echo.MiddlewareFunc {
	return s.resolve(surface, resolveMode{}, headerCredentials)
}

// ResolveBodyClient is Resolve for routes that name the application by a
// client_id in the JSON body and carry no secret (POST /captcha/challenge). The
// caller can never verify, so only the server list can lift the strict limit.
func (s *AppS2S) ResolveBodyClient(surface string) echo.MiddlewareFunc {
	return s.resolve(surface, resolveMode{}, func(c echo.Context) (string, string, bool) {
		return clientIDFromBody(c), "", false
	})
}

// ResolveOptional is Resolve for routes that do not require application
// credentials and keep their own per-IP limiter (MFA completion, passkey
// sign-in, resend-verification).
//
// Credentials are an opt-in for backends. A request without them is left
// exactly as it was: no strict bucket here, and the route's own limiter
// applies. A request whose credentials verify is a backend acting for its
// users; the route's per-IP limiter skips it (see TrustedBackend) and the
// per-user and application limits mounted after this one take over. A request
// whose credentials do NOT verify gets the bad-credential buckets, as on every
// other route, so this is not a way around secret guessing.
func (s *AppS2S) ResolveOptional(surface string) echo.MiddlewareFunc {
	return s.resolve(surface, resolveMode{optional: true}, headerCredentials)
}

// ResolveOptionalBodyClient is ResolveOptional for routes that name the
// application by a client_id in the JSON body (POST /auth/oauth/exchange).
// Basic credentials, when sent, take precedence and can verify; a body
// client_id alone cannot, but from that application's registered server IP it
// still identifies the backend.
//
// Basic credentials for one application with a body naming another are
// ignored, and the request is treated as carrying only the body client_id.
// Otherwise any tenant's valid credentials would lift the per-IP limit on
// requests that the handler resolves — and the quota charges — against a
// different application.
func (s *AppS2S) ResolveOptionalBodyClient(surface string) echo.MiddlewareFunc {
	return s.resolve(surface, resolveMode{optional: true}, func(c echo.Context) (string, string, bool) {
		bodyID := clientIDFromBody(c)
		if id, secret, ok := headerCredentials(c); ok && (bodyID == "" || bodyID == id) {
			return id, secret, true
		}
		return bodyID, "", false
	})
}

// ResolveOAuthClient is ResolveOptional for the RFC 6749 endpoints
// (/oauth/token, /oauth/revoke), which accept client credentials either as
// HTTP Basic (client_secret_basic) or in the form body (client_secret_post).
// Reading the form here is safe: net/http caches the parsed form, so the
// handler still sees every field.
//
// Only a verified secret changes anything here. A wrong secret — or a public
// client sending a secret the handler ignores — falls through to the legacy
// limiter exactly as before this change. legacyExhausted is that limiter's
// non-spending peek (OAuthTokenLegacyExhausted, OAuthRevokeLegacyExhausted).
func (s *AppS2S) ResolveOAuthClient(surface string, legacyExhausted func(echo.Context, string) bool) echo.MiddlewareFunc {
	mode := resolveMode{optional: true, failedFallsBack: true, legacyExhausted: legacyExhausted}
	return s.resolve(surface, mode, func(c echo.Context) (string, string, bool) {
		if id, secret, ok := basicCredentials(c.Request().Header.Get(echo.HeaderAuthorization)); ok {
			return id, secret, true
		}
		id := c.FormValue("client_id")
		if id == "" {
			return "", "", false
		}
		return id, c.FormValue("client_secret"), true
	})
}

// TrustedBackend reports whether Resolve identified this request as an
// application's backend: its client secret verified, or it named an
// application by client_id (presenting no secret) from that application's
// registered server IP.
//
// Route limiters that key on the caller's IP use it to step aside: for a
// backend the IP is shared by every user it serves, so the per-user and
// application limits mounted alongside apply instead. Without a Resolve
// middleware on the route it is always false, so those limiters behave
// exactly as before everywhere else.
func TrustedBackend(c echo.Context) bool {
	caller, ok := CallerFrom(c)
	if !ok {
		return false
	}
	return caller.Verified || (caller.ServerIP && !caller.HasCredentials)
}

// BackendsOnly runs mw only for trusted backends and passes everyone else
// straight through.
//
// It mounts the application quota on routes that never had one. Applying it
// to every caller there would be a NEW limit — a browser-facing integration
// whose users each stayed under the old per-IP limit could exceed the quota in
// aggregate. Applying it only to callers that the per-IP limiter now skips
// means the quota replaces a limit rather than adding one.
func BackendsOnly(mw echo.MiddlewareFunc) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		limited := mw(next)
		return func(c echo.Context) error {
			if TrustedBackend(c) {
				return limited(c)
			}
			return next(c)
		}
	}
}

func (s *AppS2S) resolve(surface string, mode resolveMode, creds func(echo.Context) (clientID, secret string, present bool)) echo.MiddlewareFunc {
	unverifiedPrefix := "app-unverified-ip:" + surface + ":"
	optional := mode.optional
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx := c.Request().Context()
			caller := &AppCaller{ConnIP: connIP(c)}
			clientID, secret, present := creds(c)
			// An empty secret is not a credential. "Basic client_id:" is how
			// some OAuth libraries send a public client; counting it as a
			// failed secret would put those clients on the strict limit.
			present = present && secret != ""
			caller.ClientID = clientID
			caller.HasCredentials = present

			trust, known := s.lookupTrust(clientID)
			caller.ServerIP = known && trust.AllowsIP(caller.ConnIP)
			if caller.ServerIP && !present {
				// Identified by address, not secret: attribute the request to
				// that application so its quota, not nobody's, is charged.
				caller.TenantID, caller.AppID = trust.TenantID, trust.ApplicationID
			}

			// Flood guard. Charged before any database work so that it bounds
			// how fast an unregistered caller can make the server verify
			// credentials. A registered server IP is exempt: it carries every
			// user of its product, and the application quota bounds it instead.
			//
			// On optional routes an anonymous caller does no credential work,
			// and the route's own limiter already bounds it; charging it here
			// too would add a limit it never had.
			if !caller.ServerIP && (present || !optional) {
				if !allowVia(c.Request().Context(), appIPStore, "app_ip", "app-ip:"+caller.ConnIP, s.cfg.PerIPRate) {
					return rejectIP(c, "app_ip", s.cfg.PerIPRate)
				}
			}

			if present {
				// Trusted addresses — the application's registered server IPs,
				// and addresses where this client_id's secret verified recently
				// — skip every budget below, so nothing a stranger does with
				// the public client_id can slow the real backend down.
				//
				// Every other address passes the guards on EVERY credentialed
				// request, cached or not. Letting a cache hit skip them would
				// reopen the oracle: during a lockout a wrong guess gets 429
				// while the right secret, if this instance has it cached,
				// would get through. The cache only saves the database lookup.
				trusted := caller.ServerIP || s.knownGood.has(ctx, clientID, caller.ConnIP)
				var outcome verifyOutcome
				cachedTID, cachedAID, cached := s.verified.lookup(clientID, secret)
				label, rate, blocked, spent := s.guardVerification(c, mode, caller, clientID, trusted, cached)
				switch {
				case blocked && !mode.failedFallsBack:
					return rejectIP(c, label, rate)
				case blocked:
					// OAuth endpoints: do not verify, and let the legacy
					// limiter answer exactly as it did before this change.
					outcome = verifyUnknown
				case cached:
					caller.TenantID, caller.AppID, outcome = cachedTID, cachedAID, verifyOK
				default:
					caller.TenantID, caller.AppID, outcome = s.verify(ctx, clientID, secret)
				}
				// The attempt budgets were spent before the outcome was known,
				// which is what makes them hold under concurrency. Give them
				// back unless the request turned out to be a guess: a real
				// backend's traffic, from however many addresses, never uses
				// them up. A refusal above also kept what it spent.
				if !blocked && outcome != verifyWrongSecret {
					for _, t := range spent {
						refundVia(ctx, appIPStore, t.label, t.key, t.rate)
					}
				}
				if outcome == verifyOK && !caller.ServerIP {
					s.knownGood.mark(ctx, clientID, caller.ConnIP)
				}
				caller.Verified = outcome == verifyOK
				caller.Failed = outcome == verifyWrongSecret

				// Record a wrong secret for the NEXT request's admission check,
				// but never refuse THIS one because of it. A refusal decided
				// after the check depends on the check's outcome: on a route
				// whose handler hides that outcome (forgot-password answers 200
				// to a bad client) a 429 here would say "wrong" while a right
				// secret got through. Admission is decided only before the
				// check, in guardVerification, where the outcome is unknown.
				if caller.Failed && !mode.failedFallsBack {
					ipKey, clientKey := badCredentialKeys(caller.ConnIP, clientID)
					allowVia(ctx, appIPStore, "app_bad_credentials_ip", ipKey, s.cfg.UnverifiedPerIPRate)
					if !caller.ServerIP {
						allowVia(ctx, appIPStore, "app_bad_credentials_client", clientKey, s.cfg.BadCredentialsPerClientRate)
					}
				}
			}

			// Strict limit for anonymous callers. A request with no client_id
			// at all names no application, so no server list can vouch for it:
			// a backend calling /reset-password for its users sends its Basic
			// credentials to be treated as one. The exemption covers a
			// client_id without a secret from that application's registered
			// server IP (POST /captcha/challenge).
			//
			// Optional routes keep their own limiter for anonymous callers.
			// Credentials that failed were bounded above; a database error
			// during verification is treated as anonymous rather than as a
			// guess.
			if !caller.Verified && !caller.Failed && !caller.ServerIP && !optional {
				if !allowVia(ctx, appIPStore, "app_unverified_ip", unverifiedPrefix+caller.ConnIP, s.cfg.UnverifiedPerIPRate) {
					return rejectIP(c, "app_unverified_ip", s.cfg.UnverifiedPerIPRate)
				}
			}

			caller.EndUserIP = caller.ConnIP
			if ip, ok := s.resolveEndUserIP(c, caller, trust, known); ok {
				caller.EndUserIP = ip
				caller.Forwarded = true
				// Sessions record their device from requestctx; give them the
				// user's address rather than the backend's.
				req := c.Request()
				c.SetRequest(req.WithContext(requestctx.WithRequestInfo(req.Context(), ip, req.UserAgent())))
			}

			c.Set(appCallerKey, caller)
			return next(c)
		}
	}
}

// resolveEndUserIP decides whether to believe X-EMC-Forwarded-For.
//
// All of these must hold, mirroring Auth0's "Trust Token Endpoint IP Header":
// the client secret verified; the application has trust_forwarded_ip on; and if
// the application registered server IPs, the request came from one of them. The
// last condition means a leaked secret alone cannot be used to forge user
// addresses from somewhere else.
func (s *AppS2S) resolveEndUserIP(c echo.Context, caller *AppCaller, trust auth.ServerTrust, known bool) (string, bool) {
	raw := strings.TrimSpace(c.Request().Header.Get(ForwardedForHeader))
	if raw == "" {
		return "", false
	}
	ignore := func(reason string) (string, bool) {
		metrics.ForwardedIPIgnored.WithLabelValues(reason).Inc()
		return "", false
	}
	// A registered server IP is REQUIRED, not optional. Without it, the
	// holder of the client secret could send the header from anywhere and
	// rotate it at will — a fresh per-user budget per invented address on the
	// routes where per-user limits bound guessing. Tying forwarding to the
	// application's own registered egress means only its real backend can
	// vouch for user addresses.
	switch {
	case !caller.Verified:
		return ignore("client_not_verified")
	case !known || trust.ApplicationID != caller.AppID || !trust.TrustForwardedIP:
		return ignore("not_trusted")
	case !caller.ServerIP:
		return ignore("not_from_server_ip")
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil || addr.Zone() != "" {
		return ignore("invalid")
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() || addr.IsMulticast() {
		return ignore("invalid")
	}
	return addr.String(), true
}

type verifyOutcome int

const (
	// verifyUnknown: the check could not be made (no authenticator, database
	// error). Neither trusted nor counted as a guess.
	verifyUnknown verifyOutcome = iota
	verifyOK
	verifyWrongSecret
)

// verify checks a client secret, serving recent successes from memory so the
// backend's steady traffic does not cost a query per request. Failures are not
// cached; the bad-credential buckets bound them instead.
func (s *AppS2S) verify(ctx context.Context, clientID, secret string) (tenantID, appID int64, outcome verifyOutcome) {
	if s.clients == nil {
		return 0, 0, verifyUnknown
	}
	key := verifiedClientKey(clientID, secret)
	tenantID, appID, err := s.clients.AuthenticateClient(ctx, clientID, secret)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidClient) {
			return 0, 0, verifyWrongSecret
		}
		s.logger.Warn().Err(err).Msg("app s2s: client verification failed — treating caller as unidentified")
		return 0, 0, verifyUnknown
	}
	s.verified.put(key, verifiedClient{tenantID: tenantID, appID: appID})
	return tenantID, appID, verifyOK
}

// verifyAttemptsPerIP bounds how many UNCACHED secret checks one address that
// has not recently verified for this client_id may trigger per minute.
//
// Spent BEFORE the check, atomically, whatever the outcome. That is what makes
// the bound hold under concurrency — a budget checked first and spent only on
// failure lets a burst of simultaneous guesses all pass the check before any
// failure is recorded — and what keeps a refusal from revealing whether a
// secret was right: once spent, right and wrong secrets get the same 429.
//
// Refunded when the secret proves correct (or the check could not be made),
// so only wrong secrets stay counted: a real backend arriving from any number
// of new addresses never uses it up. After its first request from an address,
// that address is known good (re-marked whenever it verifies) and pays only
// the generous trusted budget below, and only on cache misses.
const verifyAttemptsPerIP = 10

// verifyAttemptsTrustedPerIP bounds UNCACHED checks from a trusted address (a
// registered server IP, or one where this client_id verified recently).
//
// A real backend's cache misses are about one per instance per minute per
// application, so 30 is never reached in normal operation. It exists because
// trust is per address: someone else sharing the backend's egress (PaaS shared
// egress, carrier NAT, a corporate proxy) is "trusted" too, and without an
// atomic budget a concurrent burst of their guesses would all be checked. Cache
// hits are free — they require the right secret already.
const verifyAttemptsTrustedPerIP = 30

// OAuth endpoints use the legacy limiter's own per-client rate as their
// cross-address attempt budget, so guessing there is bounded exactly as
// before this change — but atomically.
const oauthVerifyAttemptsPerClient = OAuthTokenPerClientRate

// guardVerification decides, before an uncached secret is checked, whether the
// check may happen at all. It never reveals the secret's correctness: every
// condition here is decided without looking at the secret.
//
// Exempt from the per-client and attempt budgets: the application's registered
// server IPs, and addresses where this client_id's secret verified within the
// last knownGoodTTL. A stranger who knows the public client_id can exhaust
// those budgets for strangers, but not for the real backend.
//
// Every budget that decides whether a check happens is SPENT before the check,
// atomically (allowVia), not peeked: a peek-then-spend budget lets a burst of
// concurrent requests — from one address or many — all pass before any of
// them is recorded. The failure-bucket peeks below remain as a sequential
// backstop; the spent budgets are what hold under concurrency.
func (s *AppS2S) guardVerification(c echo.Context, mode resolveMode, caller *AppCaller, clientID string, trusted, cached bool) (label string, rate int, blocked bool, spent []spentToken) {
	ctx := c.Request().Context()
	spend := func(label, key string, rate int) bool {
		if !allowVia(ctx, appIPStore, label, key, rate) {
			return false
		}
		spent = append(spent, spentToken{label: label, key: key, rate: rate})
		return true
	}

	if trusted {
		// One admission decision for every credentialed request from this
		// address, made BEFORE the cache is consulted. If a cached secret
		// skipped it, someone sharing the backend's egress (PaaS shared
		// egress, carrier NAT) could exhaust the wrong-secret budget and then
		// tell a right guess (cache hit, admitted) from a wrong one (429).
		//
		// The cost is deliberate and the same as before this change: five
		// wrong secrets a minute from a shared address hold up every
		// credentialed request from it for the rest of that minute, as the
		// legacy 5/min per-IP limit already did for any five requests.
		if !mode.failedFallsBack {
			ipKey, _ := badCredentialKeys(caller.ConnIP, clientID)
			if exhaustedVia(ctx, appIPStore, "app_bad_credentials_ip", ipKey, s.cfg.UnverifiedPerIPRate) {
				return "app_bad_credentials_ip", s.cfg.UnverifiedPerIPRate, true, nil
			}
		}
		if cached {
			return "", 0, false, nil
		}
		if !spend("app_verify_attempts_trusted_ip", "app-verify-trusted-ip:"+caller.ConnIP, verifyAttemptsTrustedPerIP) {
			return "app_verify_attempts_trusted_ip", verifyAttemptsTrustedPerIP, true, spent
		}
		return "", 0, false, spent
	}

	// OAuth endpoints: before this change their only bound on guessing was the
	// legacy limiter, applied to right and wrong secrets alike. Once that is
	// spent, verifying anyway would let the right secret through to its own
	// bucket while wrong ones got 429 — an oracle. Peek it first.
	if mode.legacyExhausted != nil && mode.legacyExhausted(c, clientID) {
		return "legacy", 0, true, nil
	}

	ipKey, clientKey := badCredentialKeys(caller.ConnIP, clientID)
	if !mode.failedFallsBack {
		if exhaustedVia(ctx, appIPStore, "app_bad_credentials_ip", ipKey, s.cfg.UnverifiedPerIPRate) {
			return "app_bad_credentials_ip", s.cfg.UnverifiedPerIPRate, true, nil
		}
		if exhaustedVia(ctx, appIPStore, "app_bad_credentials_client", clientKey, s.cfg.BadCredentialsPerClientRate) {
			return "app_bad_credentials_client", s.cfg.BadCredentialsPerClientRate, true, nil
		}
	}

	// Spent last, so a refusal above does not also waste an attempt. Per
	// address, then per client_id across every address: the second is the
	// atomic cross-address bound that the failure peeks cannot give.
	if !spend("app_verify_attempts_ip", "app-verify-ip:"+caller.ConnIP, verifyAttemptsPerIP) {
		return "app_verify_attempts_ip", verifyAttemptsPerIP, true, spent
	}
	// Separate keys for the two rates: one GCRA key spent at two different
	// rates interferes with itself, so OAuth traffic could deny /apps/* checks.
	clientRate, clientPrefix := s.cfg.BadCredentialsPerClientRate, "app-verify-client:"
	if mode.failedFallsBack {
		clientRate, clientPrefix = oauthVerifyAttemptsPerClient, "app-verify-client-oauth:"
	}
	if !spend("app_verify_attempts_client", clientPrefix+strings.TrimPrefix(clientKey, "app-badcred-client:"), clientRate) {
		return "app_verify_attempts_client", clientRate, true, spent
	}
	return "", 0, false, spent
}

// spentToken records a budget token guardVerification spent, so it can be
// refunded once the request proves not to be a guess.
type spentToken struct {
	label, key string
	rate       int
}

// badCredentialKeys are the bucket keys for wrong secrets: per address, across
// every surface, and per client_id across every address. The client_id is
// hashed because it is attacker-chosen.
func badCredentialKeys(ip, clientID string) (ipKey, clientKey string) {
	sum := sha256.Sum256([]byte(clientID))
	return "app-badcred-ip:" + ip, "app-badcred-client:" + hex.EncodeToString(sum[:16])
}

// lookupTrust is nil-safe: with no trust source, no application has a server
// list or forwarding.
func (s *AppS2S) lookupTrust(clientID string) (auth.ServerTrust, bool) {
	if s.trust == nil || clientID == "" {
		return auth.ServerTrust{}, false
	}
	return s.trust.Lookup(clientID)
}

// SubjectFunc names the end user a request is about. apply=false skips the
// per-user limit for this request.
type SubjectFunc func(c echo.Context, caller *AppCaller) (subject string, apply bool)

// UserLimit limits each end user separately: the bucket is keyed on the
// application and the subject, so one backend IP and one client_id can serve
// any number of users while each user stays at perMinute.
//
// Applies to verified callers and to anonymous ones (a browser calling
// /reset-password). Requests whose credentials did not verify are skipped: the
// handler refuses them before any user is touched, and counting them would let
// anyone who knows a public client_id and a victim's email lock the victim out.
//
// Keys are hashed, so email addresses never appear in Redis.
func (s *AppS2S) UserLimit(label string, perMinute int, subject SubjectFunc) echo.MiddlewareFunc {
	if perMinute <= 0 {
		perMinute = DefaultAppUserLimits().Login
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			caller, ok := CallerFrom(c)
			if !ok || (caller.HasCredentials && !caller.Verified) {
				return next(c)
			}
			sub, apply := subject(c, caller)
			if !apply {
				return next(c)
			}
			if sub == "" {
				// Missing or unreadable field: one shared bucket per application,
				// so a broken body cannot be used to skip the limit.
				sub = "unknown"
			}
			client := "-"
			if caller.AppID > 0 {
				client = strconv.FormatInt(caller.AppID, 10)
			}
			sum := sha256.Sum256([]byte(client + "\x00" + sub))
			key := label + ":" + client + ":" + hex.EncodeToString(sum[:16])

			if !allowVia(c.Request().Context(), appUserStore, label, key, perMinute) {
				metrics.RateLimitHits.WithLabelValues(label).Inc()
				h := c.Response().Header()
				h.Set("Retry-After", "60")
				h.Set("X-RateLimit-Limit", strconv.Itoa(perMinute))
				h.Set("X-RateLimit-Remaining", "0")
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error":       "too many requests for this user — try again later",
					"limiter":     "user",
					"retry_after": "60",
				})
			}
			return next(c)
		}
	}
}

// SubjectEmail keys on the "email" field of the JSON body, lower-cased and
// trimmed so case and padding cannot buy a fresh bucket.
func SubjectEmail(c echo.Context, _ *AppCaller) (string, bool) {
	return strings.ToLower(strings.TrimSpace(peekBodyString(c, "email"))), true
}

// SubjectUserID keys on the "user_id" field of the JSON body, canonicalised the
// way the roles handler reads it (strconv.ParseInt): "12", "012" and "+12" are
// one user, so they must be one bucket, or varying the spelling would bypass
// the limit.
func SubjectUserID(c echo.Context, _ *AppCaller) (string, bool) {
	raw := peekBodyString(c, "user_id")
	if id, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return strconv.FormatInt(id, 10), true
	}
	// Not a number: the handler refuses it, so any stable key will do.
	return strings.TrimSpace(raw), true
}

// SubjectEndUserIP keys on the end user's forwarded address, for routes whose
// request names no user — one-time tokens (/reset-password, magic-link verify).
// A per-token key would be useless there: every guess is a new token. When the
// address was not forwarded the per-IP limits in Resolve already apply to the
// real caller, so this one is skipped.
func SubjectEndUserIP(_ echo.Context, caller *AppCaller) (string, bool) {
	if !caller.Forwarded {
		return "", false
	}
	return "ip:" + caller.EndUserIP, true
}

// SubjectGuessBudget is SubjectEndUserIP for routes that redeem a one-time
// token (/reset-password, magic-link verify), where the limit is what bounds
// guessing.
//
// A verified backend that does not forward its users' addresses is otherwise
// bounded only by its quota there — far above the 5/min per IP those routes
// had. It gets one bucket for the whole application instead, at the same
// per-user rate: never below what one backend IP had before, and no longer a
// way to guess tokens faster just by holding valid credentials. Forwarding the
// user's IP restores a bucket per user.
func SubjectGuessBudget(c echo.Context, caller *AppCaller) (string, bool) {
	if sub, ok := SubjectEndUserIP(c, caller); ok {
		return sub, true
	}
	if caller.Verified {
		return "unforwarded", true
	}
	return "", false
}

// SubjectBearerUser keys on the user in the access token, read WITHOUT verifying
// it. That is enough for bucketing: a forged token only earns its author a
// bucket of their own, and the JWT middleware after this still rejects it.
//
// The token is found exactly where JWTRenew finds it — bearerToken (any case of
// "Bearer", or a raw JWT), then the access-token cookie — so every form the
// route accepts is bucketed per user rather than in one shared bucket.
func SubjectBearerUser(c echo.Context, _ *AppCaller) (string, bool) {
	token, found := bearerToken(c)
	if !found {
		if cookie, err := c.Cookie(AccessTokenCookie); err == nil && cookie.Value != "" {
			token, found = cookie.Value, true
		}
	}
	if !found {
		return "", true
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(parts[1]) > 8<<10 {
		return "", true
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", true
	}
	var claims struct {
		TenantID string `json:"tenant_id"`
		UserID   string `json:"user_id"`
		Sub      string `json:"sub"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return "", true
	}
	user := claims.UserID
	if user == "" {
		user = claims.Sub
	}
	if user == "" {
		return "", true
	}
	return claims.TenantID + ":" + user, true
}

// peekBodyString reads one top-level string field from a JSON body and restores
// the body so the handler's Bind still sees all of it.
//
// It decodes the way the handlers do — echo's Bind is a json.Decoder into a
// struct — so both see the SAME value. A map lookup would not: struct decoding
// matches field names case-insensitively and lets the last duplicate win, so
// {"email":"decoy","Email":"victim"} would bucket the decoy while the handler
// acted on the victim. Decoding into a one-field struct tagged with the same
// name gives identical matching, duplicate and trailing-data behaviour.
func peekBodyString(c echo.Context, field string) string {
	req := c.Request()
	if req.Body == nil {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(req.Body, 1<<16))
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(data))
	if err != nil || len(data) == 0 {
		return ""
	}
	holder := reflect.New(reflect.StructOf([]reflect.StructField{{
		Name: "V",
		Type: reflect.TypeOf(""),
		Tag:  reflect.StructTag(`json:"` + field + `"`),
	}}))
	if json.NewDecoder(bytes.NewReader(data)).Decode(holder.Interface()) != nil {
		return ""
	}
	v := holder.Elem().Field(0).String()
	if len(v) > maxRateLimitEmailLen {
		v = v[:maxRateLimitEmailLen]
	}
	return v
}

// basicCredentials parses "Basic base64(id:secret)".
func basicCredentials(header string) (clientID, secret string, ok bool) {
	if !strings.HasPrefix(header, "Basic ") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(header[len("Basic "):])
	if err != nil {
		return "", "", false
	}
	id, secret, found := strings.Cut(string(decoded), ":")
	if !found || id == "" {
		return "", "", false
	}
	return id, secret, true
}

// connIP is c.RealIP() with the port stripped from a RemoteAddr fallback, so
// every connection from one host shares a bucket.
func connIP(c echo.Context) string {
	if ip := c.RealIP(); ip != "" {
		if host, _, err := net.SplitHostPort(ip); err == nil {
			return host
		}
		return ip
	}
	if host, _, err := net.SplitHostPort(c.Request().RemoteAddr); err == nil {
		return host
	}
	return c.Request().RemoteAddr
}

func rejectIP(c echo.Context, label string, perMinute int) error {
	metrics.RateLimitHits.WithLabelValues(label).Inc()
	h := c.Response().Header()
	h.Set("Retry-After", "60")
	h.Set("X-RateLimit-Limit", strconv.Itoa(perMinute))
	h.Set("X-RateLimit-Remaining", "0")
	return c.JSON(http.StatusTooManyRequests, map[string]string{
		"error":       "too many requests from this IP address",
		"limiter":     "ip",
		"retry_after": "60",
	})
}

// ---------------------------------------------------------------------------
// Verified-client cache
// ---------------------------------------------------------------------------

const (
	// verifiedClientTTL bounds how long a secret stays trusted for limiting
	// after it is rotated away. Authentication itself is unaffected: handlers
	// verify against the database on every request.
	verifiedClientTTL = 60 * time.Second
	verifiedClientMax = 4096
)

type verifiedClient struct {
	tenantID, appID int64
	expires         time.Time
}

type verifiedClientCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	entries map[string]verifiedClient
}

func newVerifiedClientCache(ttl time.Duration, max int) *verifiedClientCache {
	return &verifiedClientCache{ttl: ttl, max: max, entries: map[string]verifiedClient{}}
}

// verifiedClientKey never stores the secret itself.
func verifiedClientKey(clientID, secret string) string {
	sum := sha256.Sum256([]byte(clientID + "\x00" + secret))
	return string(sum[:])
}

// lookup serves a secret verified within the TTL.
func (v *verifiedClientCache) lookup(clientID, secret string) (tenantID, appID int64, ok bool) {
	e, hit := v.get(verifiedClientKey(clientID, secret))
	return e.tenantID, e.appID, hit
}

func (v *verifiedClientCache) get(key string) (verifiedClient, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.entries[key]
	if !ok || time.Now().After(e.expires) {
		return verifiedClient{}, false
	}
	return e, true
}

func (v *verifiedClientCache) put(key string, e verifiedClient) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.entries) >= v.max {
		// Only successfully verified secrets get here, so a full cache means
		// thousands of real applications; starting over costs one query each.
		v.entries = map[string]verifiedClient{}
	}
	e.expires = time.Now().Add(v.ttl)
	v.entries[key] = e
}

// ---------------------------------------------------------------------------
// Known-good addresses
// ---------------------------------------------------------------------------

// knownGoodTTL is how long an address stays known good for a client_id after
// its secret verified there. The verified cache expires every minute, so a
// live backend re-marks its address long before this lapses.
const knownGoodTTL = 10 * time.Minute

const knownGoodLocalMax = 10_000

// knownGoodAddrs remembers (client_id, address) pairs where the client secret
// recently verified. In Redis when configured, so every instance agrees, with
// an in-process copy that also serves when Redis is unavailable.
type knownGoodAddrs struct {
	rdb   *redisv9.Client
	mu    sync.Mutex
	local map[string]time.Time
}

func newKnownGoodAddrs() *knownGoodAddrs {
	return &knownGoodAddrs{local: map[string]time.Time{}}
}

func knownGoodKey(clientID, ip string) string {
	sum := sha256.Sum256([]byte(clientID))
	return "s2s:goodaddr:" + hex.EncodeToString(sum[:16]) + ":" + ip
}

// knownGoodRefresh is how stale a mark may get before a verified request
// refreshes it. Called on every verified request, so this is what keeps a busy
// backend from writing to Redis on each one, while its mark never lapses.
const knownGoodRefresh = time.Minute

func (k *knownGoodAddrs) mark(ctx context.Context, clientID, ip string) {
	key := knownGoodKey(clientID, ip)
	now := time.Now()
	k.mu.Lock()
	if exp, ok := k.local[key]; ok && exp.Sub(now) > knownGoodTTL-knownGoodRefresh {
		k.mu.Unlock()
		return
	}
	if len(k.local) >= knownGoodLocalMax {
		k.local = map[string]time.Time{}
	}
	k.local[key] = now.Add(knownGoodTTL)
	k.mu.Unlock()
	if k.rdb != nil {
		_ = k.rdb.Set(ctx, key, 1, knownGoodTTL).Err()
	}
}

// has fails closed: a Redis error means "not known", which only makes a
// stranger-proof exemption unavailable, never grants one.
func (k *knownGoodAddrs) has(ctx context.Context, clientID, ip string) bool {
	key := knownGoodKey(clientID, ip)
	k.mu.Lock()
	exp, ok := k.local[key]
	k.mu.Unlock()
	if ok && time.Now().Before(exp) {
		return true
	}
	if k.rdb != nil {
		n, err := k.rdb.Exists(ctx, key).Result()
		return err == nil && n > 0
	}
	return false
}
