package middleware

import "github.com/labstack/echo/v4"

// OrgFlowChain is the middleware chain for the end-user organisation routes
// (/apps/login/organization, /apps/switch-organization and the invitation
// preview and accept routes). A product backend sending its client credentials
// is charged to its application's shared quota, only for its own application's
// tokens; everyone else keeps the per-IP token limiter. routes.go and the tests
// share this builder so the tests pin what is actually registered.
func OrgFlowChain(s *AppS2S, scope SubjectScopeFunc, appQuota echo.MiddlewareFunc, cfg RateLimitConfig) []echo.MiddlewareFunc {
	return []echo.MiddlewareFunc{
		s.ResolveOptional(SurfaceOrg),
		ScopeToCaller(scope),
		BackendsOnly(appQuota),
		TokenRateLimiter(cfg),
	}
}

// AppOrgManagementChain is the chain for the organisation-management routes an
// application's own backend calls with Authorization: Basic. Resolve holds
// callers whose secret does not verify to the strict per-IP bucket; verified
// backends are limited by the application quota instead of per IP.
func AppOrgManagementChain(s *AppS2S, appQuota echo.MiddlewareFunc) []echo.MiddlewareFunc {
	return []echo.MiddlewareFunc{s.Resolve(SurfaceApp), appQuota}
}
