package middleware

import (
	"errors"
	"net/http"
	"strings"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// userContextKey is the echo context key under which *auth.Claims is stored.
// All handlers and downstream middleware read claims via c.Get(userContextKey).
const userContextKey = "user"

// Cookie names used for browser-session authentication (see auth/session handlers).
const (
	AccessTokenCookie  = "emc_access_token"
	RefreshTokenCookie = "emc_refresh_token"
)

// JWTRequired returns an Echo middleware that:
//  1. Reads the Authorization header (must be "Bearer <token>"); falls back to
//     the emc_access_token HttpOnly cookie for browser-session clients.
//  2. Verifies the JWT signature, algorithm, issuer, expiry, and audience using
//     the per-tenant secret (fetched from DB).
//  3. Stores the validated *auth.Claims in the echo context under key "user".
//  4. Returns HTTP 401 if no valid token is found in either location.
//
// allowedAudiences declares which token types the mounted routes accept
// (issue #84). It is variadic for call-site readability, but omitting it is a
// configuration error: auth.VerifyForAudience then fails closed with
// ErrNoAudienceAllowed rather than accepting every token type.
//
// Rejections are deliberately reported as the same generic token_invalid 401 as
// any other bad token, so a caller cannot use the response to discover that it
// holds a validly-signed token of the wrong type. Operators see the detail on
// the emc_auth_token_audience_rejections_total metric instead.
//
// Performance note (NFR-01): verification does one DB round-trip to fetch the tenant
// secret. With pgxpool (MaxConns=25) and the p99 < 2ms DB query target, this adds ≤2ms latency.
func JWTRequired(jwtSvc *auth.JWTService, allowedAudiences ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			tokenString, found := bearerToken(c)
			viaCookie := false
			if !found {
				// Fall back to HttpOnly cookie set by /auth/session endpoints.
				if cookie, err := c.Cookie(AccessTokenCookie); err == nil && cookie.Value != "" {
					tokenString = cookie.Value
					found = true
					viaCookie = true
				}
			}

			if !found || tokenString == "" {
				// No credential at all. RFC 6750 §3.1 says the challenge SHOULD
				// NOT carry an error code in this case — there is no failed
				// credential to describe, only an invitation to authenticate.
				return unauthorized(c, "token_missing", "authorization required",
					`Bearer realm="`+bearerRealm+`"`)
			}

			claims, err := jwtSvc.VerifyForAudience(c.Request().Context(), tokenString, allowedAudiences...)
			if err != nil {
				// Distinguish expired tokens from invalid ones.
				// Clients should refresh on token_expired; redirect to login on token_invalid.
				if errors.Is(err, gojwt.ErrTokenExpired) {
					return unauthorized(c, "token_expired", "access token expired",
						`Bearer realm="`+bearerRealm+`", error="invalid_token", `+
							`error_description="the access token expired"`)
				}
				if errors.Is(err, auth.ErrUnexpectedAudience) {
					metrics.TokenAudienceRejections.
						WithLabelValues(presentedAudience(tokenString), c.Path()).Inc()
				}
				// Deliberately the same challenge for every remaining failure —
				// bad signature, unknown tenant, wrong audience. Naming the
				// reason here would hand back precisely the oracle the generic
				// JSON body withholds (issue #84).
				return unauthorized(c, "token_invalid", "invalid token",
					`Bearer realm="`+bearerRealm+`", error="invalid_token"`)
			}

			// Publish claims for downstream handlers and apply the
			// session-identity check before the handler runs.
			return proceedAuthenticated(c, claims, viaCookie, next)
		}
	}
}

// bearerRealm names the protection space in the RFC 6750 challenge. One value
// for the whole server: the realm identifies who to authenticate WITH, and that
// is this auth server regardless of which route refused.
const bearerRealm = "emc-auth"

// unauthorized writes a 401 carrying the RFC 6750 §3 WWW-Authenticate challenge
// alongside the JSON body this API already returned.
//
// Why the header matters, given the body was already there. A bearer-protected
// resource that answers 401 without a challenge is not conformant, and standard
// OIDC/OAuth client libraries read the challenge rather than the body: on
// error="invalid_token" they discard the credential and re-authenticate, while
// a bare 401 is treated by several as a transport fault worth retrying — with
// the same dead token.
//
// This lives in the middleware, not only in the handler, because the middleware
// is where the common rejection happens. handlers/oidc.go sets its own challenge
// for the case where a request reaches the handler with unusable claims, but a
// token of the wrong audience never gets that far: JWTRequired refuses it first
// (issue #84), and until now that path emitted no challenge at all. The gap
// survived because the handler test calls the handler directly, so it exercised
// the one path that was already correct.
//
// The two cache directives are RFC 6750 §3 as well, and they matter less for
// correctness than for not being surprising: 401 is not heuristically cacheable
// under RFC 9111 §4.2.2, so a conforming intermediary would not store this
// anyway. They are set because a response that turns on a credential should say
// so itself rather than rely on every proxy in the path reading the status code
// the same way, and because every other credential-bearing response in this
// codebase already says it — the token endpoint (oauth_token.go), the authorize
// pages (oauth_authorize.go), and userinfo (oidc.go). This was the one bearer
// path that did not. From the Copilot review on PR #111.
func unauthorized(c echo.Context, code, message, challenge string) error {
	head := c.Response().Header()
	head.Set("WWW-Authenticate", challenge)
	head.Set("Cache-Control", "no-store")
	head.Set("Pragma", "no-cache")
	return c.JSON(http.StatusUnauthorized, map[string]string{
		"error": message,
		"code":  code,
	})
}

// presentedAudience reads the "aud" claim for metric labelling only.
//
// Safe to parse unverified here: this is called solely after
// VerifyForAudience has already proven the signature and rejected the token on
// audience alone, so the claim really was minted by this server.
//
// The result is normalized to a known audience (or "other") to keep the metric's
// label cardinality bounded — Sign() accepts an arbitrary audience string, so an
// unrecognised value must not become a new time series.
func presentedAudience(tokenString string) string {
	parsed, _, err := gojwt.NewParser().ParseUnverified(tokenString, &auth.Claims{})
	if err != nil {
		return "other"
	}
	claims, ok := parsed.Claims.(*auth.Claims)
	if !ok || len(claims.Audience) != 1 {
		return "other"
	}
	switch claims.Audience[0] {
	case auth.AudienceAPI, auth.AudienceM2M, auth.AudienceManagement, auth.AudienceAgent:
		return claims.Audience[0]
	default:
		return "other"
	}
}

// bearerToken extracts the token string from "Authorization: Bearer <token>".
// Also accepts a raw JWT (no scheme prefix) to support Swagger UI's apiKey flow.
// Returns ("", false) if the header is absent or malformed.
func bearerToken(c echo.Context) (string, bool) {
	header := c.Request().Header.Get("Authorization")
	if header == "" {
		return "", false
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		token := strings.TrimSpace(parts[1])
		return token, token != ""
	}
	// Raw JWT (no scheme) — Swagger UI apiKey sends the value as-is.
	if len(parts) == 1 && strings.HasPrefix(parts[0], "eyJ") {
		return parts[0], true
	}
	return "", false
}
