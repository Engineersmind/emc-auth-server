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
	"github.com/engineersmind/emc-auth-server/internal/metrics"
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

			// The accepted audience is named here rather than inherited from
			// Verify(): the routes this middleware guards are user self-service
			// endpoints (/me, /otp/*, /change-email) that assume a real user and a
			// browser session, so a service (M2M), management, or agent token is
			// refused here even though it may be perfectly valid on admin routes
			// (issue #84). Declaring it at the call site keeps this route group
			// pinned to AudienceAPI even if Verify() ever widens its own set.
			claims, err := jwtSvc.VerifyForAudience(c.Request().Context(), tokenString, auth.AudienceAPI)
			if err == nil {
				c.Set(userContextKey, claims)
				return next(c)
			}

			// Any error other than expiry is fatal (tampered signature, wrong
			// issuer, wrong audience, etc.) — note a non-user token is never
			// renewed into a session: it fails closed here rather than falling
			// through to refresh-token rotation below.
			if !errors.Is(err, gojwt.ErrTokenExpired) {
				// These are the routes where a wrong-audience token is the
				// strongest replay signal: a service, management, or agent token
				// has no business on a user self-service endpoint, so unlike the
				// admin group (which legitimately accepts three audiences) any
				// rejection here is worth counting.
				if errors.Is(err, auth.ErrUnexpectedAudience) {
					metrics.TokenAudienceRejections.
						WithLabelValues(presentedAudience(tokenString), c.Path()).Inc()
				}
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
				// Attribute the failure to the token's owner when it resolves to a
				// real account (expired/replayed included); unknown tokens stay
				// anonymous. logFailure builds, attributes, and emits the event.
				logFailure := func(action, reason string, httpStatus int) {
					ev := audit.Event{
						Action:       action,
						AuthMethod:   audit.AuthMethodRefreshToken,
						ResourceType: "session",
						IPAddress:    c.RealIP(),
						UserAgent:    c.Request().UserAgent(),
						Status:       audit.StatusFailure,
						HTTPStatus:   httpStatus,
						RequestID:    c.Response().Header().Get(echo.HeaderXRequestID),
						Metadata: map[string]any{
							"reason":     reason,
							"error_code": reason,
							"http_route": c.Path(),
						},
					}
					if owner, ok := authSvc.ResolveTokenOwner(c.Request().Context(), refreshCookie.Value); ok {
						ev.UserID = &owner.UserID
						ev.TenantID = &owner.TenantID
						ev.ActorEmail = owner.Email
					}
					auditLog.Log(c.Request().Context(), ev)
				}

				if errors.Is(refreshErr, auth.ErrServiceUnavailable) {
					logFailure(audit.ActionAuthTokenRefreshFailed, "service_unavailable", http.StatusServiceUnavailable)
					return c.JSON(http.StatusServiceUnavailable, map[string]string{
						"error": "service temporarily unavailable — please retry",
						"code":  "service_unavailable",
					})
				}
				ClearAuthCookies(c, cookieCfg)
				if errors.Is(refreshErr, auth.ErrTokenReplay) {
					logger.Warn().
						Str("ip", c.RealIP()).
						Str("path", c.Request().URL.Path).
						Msg("renewal: replay detected — session family revoked")
					logFailure(audit.ActionAuthReplayDetected, "refresh_token_reuse", http.StatusUnauthorized)
					return c.JSON(http.StatusUnauthorized, map[string]string{
						"error": "session terminated — security event detected",
						"code":  "unauthenticated",
					})
				}
				logFailure(audit.ActionAuthTokenRefreshFailed, "invalid_refresh_token", http.StatusUnauthorized)
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
			wrapper.cookies = append(wrapper.cookies, BuildAuthCookies(result.AccessToken, result.RefreshToken, cookieCfg)...)
			c.Response().Writer = wrapper

			// ── Step 5: verify the freshly-signed token to get clean claims ───
			newClaims, verifyErr := jwtSvc.Verify(c.Request().Context(), result.AccessToken)
			if verifyErr != nil {
				logger.Error().Err(verifyErr).Msg("renewal: failed to verify freshly-signed access token")
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal error"})
			}
			c.Set(userContextKey, newClaims)

			// ── Step 6: audit ─────────────────────────────────────────────────
			tid, uid, appID := claimsToAuditIDs(newClaims)
			auditLog.Log(c.Request().Context(), audit.Event{
				TenantID:      tid,
				UserID:        uid,
				ApplicationID: appID,
				Action:        audit.ActionAuthTokenRefresh,
				AuthMethod:    audit.AuthMethodRefreshToken,
				ResourceType:  "session",
				IPAddress:     c.RealIP(),
				UserAgent:     c.Request().UserAgent(),
				HTTPStatus:    http.StatusOK,
				RequestID:     c.Response().Header().Get(echo.HeaderXRequestID),
				Metadata:      map[string]any{"http_route": c.Path()},
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
func claimsToAuditIDs(c *auth.Claims) (tenantID, userID, appID *int64) {
	if t, err := strconv.ParseInt(c.TenantID, 10, 64); err == nil {
		tenantID = &t
	}
	if u, err := strconv.ParseInt(c.UserID, 10, 64); err == nil {
		userID = &u
	}
	if a, err := strconv.ParseInt(c.AppID, 10, 64); err == nil {
		appID = &a
	}
	return tenantID, userID, appID
}
