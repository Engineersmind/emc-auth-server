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
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "authorization required",
					"code":  "token_missing",
				})
			}

			claims, err := jwtSvc.VerifyForAudience(c.Request().Context(), tokenString, allowedAudiences...)
			if err != nil {
				// Distinguish expired tokens from invalid ones.
				// Clients should refresh on token_expired; redirect to login on token_invalid.
				if errors.Is(err, gojwt.ErrTokenExpired) {
					return c.JSON(http.StatusUnauthorized, map[string]string{
						"error": "access token expired",
						"code":  "token_expired",
					})
				}
				if errors.Is(err, auth.ErrUnexpectedAudience) {
					metrics.TokenAudienceRejections.
						WithLabelValues(presentedAudience(tokenString), c.Path()).Inc()
				}
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "invalid token",
					"code":  "token_invalid",
				})
			}

			// Publish claims for downstream handlers and apply the
			// session-identity check before the handler runs.
			return proceedAuthenticated(c, claims, viaCookie, next)
		}
	}
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
