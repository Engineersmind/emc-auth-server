package middleware

import (
	"errors"
	"net/http"
	"strconv"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// renewalWriter wraps http.ResponseWriter and buffers Set-Cookie headers so
// they are flushed atomically with the handler's status code before any body
// bytes are written.
//
// Without this, Go's net/http would send headers the moment the handler calls
// WriteHeader or Write, and any cookies we tried to add afterwards would be
// silently ignored (or cause a "superfluous WriteHeader" panic).
type renewalWriter struct {
	http.ResponseWriter
	cookies     []*http.Cookie
	wroteHeader bool
}

func (rw *renewalWriter) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}
	for _, c := range rw.cookies {
		http.SetCookie(rw.ResponseWriter, c)
	}
	rw.ResponseWriter.WriteHeader(code)
	rw.wroteHeader = true
}

func (rw *renewalWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// JWTRenew returns an Echo middleware that authenticates requests and performs
// transparent token renewal for cookie-based (browser/SPA) clients.
//
// Flow:
//  1. Valid access token → attach claims, call next. (Fast path, no DB write.)
//  2. Expired access token + refresh cookie → acquire Redis lock, rotate,
//     wrap the response writer so new Set-Cookie headers flush before the
//     body, attach fresh claims, call next.
//  3. Expired access token + no refresh cookie → 401 (Bearer-only clients
//     must handle refresh themselves).
//  4. Replay detected → revoke entire token family, clear cookies, 401.
//
// This replaces the JWTRequired middleware on all routes where browsers are
// expected. JWTRequired may still be used on pure-API routes that never issue
// cookies.
func JWTRenew(
	jwtSvc *auth.JWTService,
	authSvc *auth.AuthService,
	redisCli *redis.Client,
	cookieCfg CookieConfig,
	auditLog *audit.Logger,
	logger zerolog.Logger,
) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// ── Step 1: read access token (Bearer header or cookie) ──────────
			tokenString, found := bearerToken(c)
			if !found {
				if cookie, err := c.Cookie(AccessTokenCookie); err == nil && cookie.Value != "" {
					tokenString = cookie.Value
					found = true
				}
			}

			if !found {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "authorization required",
					"code":  "token_missing",
				})
			}

			claims, err := jwtSvc.Verify(c.Request().Context(), tokenString)
			if err == nil {
				c.Set(userContextKey, claims)
				return next(c)
			}

			// Any error other than expiry is fatal (tampered signature, wrong issuer, etc.)
			if !errors.Is(err, gojwt.ErrTokenExpired) {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "invalid token",
					"code":  "token_invalid",
				})
			}

			// ── Step 2: access token expired — try refresh cookie ────────────
			refreshCookie, cookieErr := c.Cookie(RefreshTokenCookie)
			if cookieErr != nil || refreshCookie.Value == "" {
				// No refresh cookie: Bearer client. Return the standard 401 so
				// the client can call /auth/refresh explicitly.
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "access token expired",
					"code":  "token_expired",
				})
			}

			// ── Step 3: rotate with distributed lock ─────────────────────────
			result, grace, refreshErr := authSvc.RefreshWithLock(c.Request().Context(), refreshCookie.Value, redisCli)
			if refreshErr != nil {
				ClearAuthCookies(c)
				if errors.Is(refreshErr, auth.ErrTokenReplay) {
					logger.Warn().
						Str("ip", c.RealIP()).
						Str("path", c.Request().URL.Path).
						Msg("renewal: replay detected — session family revoked")
					auditLog.Log(c.Request().Context(), audit.Event{
						Action:    audit.ActionAuthReplayDetected,
						IPAddress: c.RealIP(),
						UserAgent: c.Request().UserAgent(),
					})
					return c.JSON(http.StatusUnauthorized, map[string]string{
						"error": "session terminated — security event detected",
						"code":  "unauthenticated",
					})
				}
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "session expired",
					"code":  "unauthenticated",
				})
			}

			// ── Grace path: concurrent rotation already completed ─────────────
			// Another concurrent request rotated this family while we were waiting
			// for the lock. Proceed without issuing new cookies — the browser will
			// receive the fresh cookies from the other request's response.
			if grace != nil {
				c.Set(userContextKey, graceToAuthClaims(grace))
				return next(c)
			}

			// ── Step 4: wrap response writer — cookies flush before body ──────
			wrapper := &renewalWriter{ResponseWriter: c.Response().Writer}
			for _, cookie := range BuildAuthCookies(result.AccessToken, result.RefreshToken, cookieCfg) {
				wrapper.cookies = append(wrapper.cookies, cookie)
			}
			c.Response().Writer = wrapper

			// ── Step 5: verify the freshly-signed token to get clean claims ───
			newClaims, verifyErr := jwtSvc.Verify(c.Request().Context(), result.AccessToken)
			if verifyErr != nil {
				logger.Error().Err(verifyErr).Msg("renewal: failed to verify freshly-signed access token")
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal error"})
			}
			c.Set(userContextKey, newClaims)

			// ── Step 6: audit ─────────────────────────────────────────────────
			tid, uid := claimsToAuditIDs(newClaims)
			auditLog.Log(c.Request().Context(), audit.Event{
				TenantID:     tid,
				UserID:       uid,
				Action:       audit.ActionAuthTokenRefresh,
				ResourceType: "session",
				IPAddress:    c.RealIP(),
				UserAgent:    c.Request().UserAgent(),
			})

			return next(c)
		}
	}
}

// graceToAuthClaims converts a GraceResult (from concurrent-rotation path)
// into the *auth.Claims shape that downstream handlers expect via c.Get("user").
func graceToAuthClaims(g *auth.GraceResult) *auth.Claims {
	return &auth.Claims{
		UserID:      strconv.FormatInt(g.UserID, 10),
		TenantID:    strconv.FormatInt(g.TenantID, 10),
		Email:       g.Email,
		Role:        g.Role,
		Permissions: g.Permissions,
	}
}

// claimsToAuditIDs parses the string UserID / TenantID in JWT claims into
// the *int64 pointers that audit.Event expects.
func claimsToAuditIDs(c *auth.Claims) (tenantID, userID *int64) {
	if t, err := strconv.ParseInt(c.TenantID, 10, 64); err == nil {
		tenantID = &t
	}
	if u, err := strconv.ParseInt(c.UserID, 10, 64); err == nil {
		userID = &u
	}
	return tenantID, userID
}
