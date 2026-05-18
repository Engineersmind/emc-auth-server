package middleware

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

const (
	// APIKeyContextKey is the Echo context key where the APIKeyIdentity is stored.
	APIKeyContextKey = "api_key_identity"
	// APIKeyHeader is the header name expected by the APIKeyAuth middleware.
	APIKeyHeader = "X-API-Key"
)

// APIKeyAuth returns a middleware that authenticates requests using the X-API-Key header.
// On success, the resolved APIKeyIdentity is stored in the Echo context under APIKeyContextKey.
// On failure, returns 401 with a structured error body.
//
// This middleware is for machine-to-machine endpoints only (APIKEY-04).
// It is NOT combined with JWTRequired — endpoints choose one or the other.
func APIKeyAuth(svc *auth.APIKeyService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			rawKey := c.Request().Header.Get(APIKeyHeader)
			if rawKey == "" {
				// Also accept Authorization: ApiKey <key>
				authHeader := c.Request().Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "ApiKey ") {
					rawKey = strings.TrimPrefix(authHeader, "ApiKey ")
				}
			}

			if rawKey == "" {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "API key required — set X-API-Key header or Authorization: ApiKey <key>",
				})
			}

			identity, err := svc.AuthenticateAPIKey(c.Request().Context(), rawKey)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "invalid or revoked API key",
				})
			}

			c.Set(APIKeyContextKey, identity)
			return next(c)
		}
	}
}

// APIKeyIdentityFromCtx retrieves the resolved APIKeyIdentity from the Echo context.
// Returns nil if not set (endpoint is not behind APIKeyAuth middleware).
func APIKeyIdentityFromCtx(c echo.Context) *auth.APIKeyIdentity {
	v, _ := c.Get(APIKeyContextKey).(*auth.APIKeyIdentity)
	return v
}

// APIKeyRequirePermission returns a middleware that checks whether the resolved API key
// identity carries the required permission. Must be used after APIKeyAuth.
func APIKeyRequirePermission(perm string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			identity := APIKeyIdentityFromCtx(c)
			if identity == nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "API key identity not found in context",
				})
			}
			for _, p := range identity.Permissions {
				if p == perm {
					return next(c)
				}
			}
			return c.JSON(http.StatusForbidden, map[string]string{
				"error": "API key lacks required permission: " + perm,
			})
		}
	}
}
