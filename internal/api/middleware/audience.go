package middleware

import (
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// Route audience policy — issue #132.
//
// #130 freed the "aud" claim by moving the token type to "gty"; #131 put a real
// per-application audience in it. Neither changed who may reach which route, so
// the isolation was available but not enforced: a token minted for a tenant's
// own API still reached this server's management surface, because every route
// accepted every audience.
//
// THE SERVER'S API IS TWO SURFACES, AND THE BOUNDARY HAS TO HOLD BOTH WAYS.
//
// Identity endpoints (/auth/me, /auth/refresh, /auth/session, the MFA and
// passkey enrolment routes, /account/sessions) exist FOR app-scoped tokens.
// emc-insurance-platform obtains a token from /auth/apps/login whose audience
// is its OWN api://<tenant>/<app>, then calls GET /auth/me with it to find out
// who the user is — every authenticated request in that platform passes through
// that call. Demanding api://emc-auth there would return 401 on all of it and
// force every integrator to fetch a second token just to ask who their user is.
// So identity routes accept any audience the caller's own tenant owns.
//
// Admin endpoints (/tenants, /applications, /users, /roles, /audit-logs and the
// rest of adminGroup) are the opposite: a token minted for a tenant's own API
// must never reach this server's management surface. They require
// auth.AudienceSelf.
//
// WHY A REAL AUDIENCE IS JUDGED REGARDLESS OF EITHER FLAG.
//
// The two enforcement switches — the per-client oauth_clients.require_audience
// column and the deployment-wide REQUIRE_AUDIENCE — gate only what happens to a
// token carrying NO audience. A token that does carry one is always held to the
// route policy, and that cannot break a legacy consumer: tokens minted before
// #131 carry the old token-type strings ("emc-auth-api" and friends, no scheme)
// or nothing at all, never a real identifier. So the boundary starts holding for
// migrated tokens the moment this deploys, while un-migrated tokens keep working
// until an operator opts their application in. That is what makes the rollout
// staged rather than a cutover.
type audiencePolicy int

const (
	// policyTenant accepts auth.AudienceSelf or any audience registered to a
	// live application in the caller's own tenant.
	policyTenant audiencePolicy = iota
	// policySelf accepts only auth.AudienceSelf.
	policySelf
)

// RequireTenantAudience guards the identity surface: it accepts a token whose
// audience is registered anywhere in the caller's own tenant, and this server's
// own audience as well, since first-party portal sessions carry that.
//
// requireGlobal is config.RequireAudience, resolved at wiring time so this
// package does not depend on config.
func RequireTenantAudience(audSvc *auth.AudienceService, requireGlobal bool) echo.MiddlewareFunc {
	return requireAudience(audSvc, requireGlobal, policyTenant)
}

// RequireSelfAudience guards the management surface: only this server's own
// audience is accepted, so a token minted for a tenant's API cannot administer
// the server that issued it.
func RequireSelfAudience(audSvc *auth.AudienceService, requireGlobal bool) echo.MiddlewareFunc {
	return requireAudience(audSvc, requireGlobal, policySelf)
}

// requireAudience is mounted AFTER JWTRequired (or JWTRenew) on a group, so the
// token is already verified and *auth.Claims is already published on the
// context. It re-reads nothing from the wire.
//
// Mounted as its own middleware rather than folded into JWTRequired's variadic
// signature deliberately: JWTRequired is called from a dozen places, and adding
// a parameter would touch every one of them for the benefit of two. This is
// additive, so a group that mounts nothing keeps today's behaviour exactly.
func requireAudience(audSvc *auth.AudienceService, requireGlobal bool, policy audiencePolicy) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims, ok := c.Get(userContextKey).(*auth.Claims)
			if !ok || claims == nil {
				// The group is misconfigured: this middleware is mounted without
				// a JWT guard ahead of it. Fail closed rather than wave the
				// request through on an absent claim set.
				return unauthorized(c, "token_invalid", "invalid token",
					`Bearer realm="`+bearerRealm+`", error="invalid_token"`)
			}

			// audSvc is nil only in the degraded start-up path where the audience
			// service could not be constructed. Enforcing then would refuse every
			// request on the server; the token has still passed signature, issuer,
			// expiry and grant-type verification, so the pre-#131 boundary is
			// intact and this dimension is skipped.
			if audSvc == nil {
				return next(c)
			}

			presented, hasReal := realAudience(claims)

			if !hasReal {
				// No real audience: either the claim is absent or it still holds
				// a legacy token-type string. Accepted unless something has opted
				// this caller in — see the type comment for why this is the only
				// flag-gated branch.
				enforcing := requireGlobal
				if !enforcing {
					if appRowID, err := strconv.ParseInt(claims.AppID, 10, 64); err == nil && appRowID > 0 {
						required, err := audSvc.ClientRequiresAudience(c.Request().Context(), appRowID)
						if err != nil {
							// Fail CLOSED on a database error here, unlike the
							// metrics label in audience.go which fails open. That
							// one only mislabels a rejection that has already
							// happened; this one decides whether an audience-less
							// token reaches a route, and answering "not enforcing"
							// on a blip would silently disable the switch an
							// operator has deliberately turned on.
							return unauthorized(c, "token_invalid", "invalid token",
								`Bearer realm="`+bearerRealm+`", error="invalid_token"`)
						}
						enforcing = required
					}
				}
				if enforcing {
					metrics.TokenAudienceRejections.WithLabelValues("none", c.Path()).Inc()
					return unauthorized(c, "token_invalid", "invalid token",
						`Bearer realm="`+bearerRealm+`", error="invalid_token"`)
				}
				// Counted so the operator can watch this reach zero before the
				// fallback is deleted in a later release. Keyed by application so
				// a straggler is identifiable rather than merely visible.
				metrics.LegacyAudienceVerifications.WithLabelValues(claims.AppID).Inc()
				return next(c)
			}

			allowed, err := policyAllows(c, audSvc, policy, claims, presented)
			if err != nil {
				return unauthorized(c, "token_invalid", "invalid token",
					`Bearer realm="`+bearerRealm+`", error="invalid_token"`)
			}
			if !allowed {
				// Bounded label: presented came from a signature-verified token
				// this server minted, so its cardinality is the number of
				// applications, not attacker-controlled.
				metrics.TokenAudienceRejections.WithLabelValues(presented, c.Path()).Inc()
				// The same generic challenge as every other token failure. Naming
				// the audience dimension would tell a caller it holds a validly
				// signed token of the wrong scope, which is the oracle issue #84
				// closed.
				return unauthorized(c, "token_invalid", "invalid token",
					`Bearer realm="`+bearerRealm+`", error="invalid_token"`)
			}
			return next(c)
		}
	}
}

// policyAllows applies one route policy to a presented audience.
func policyAllows(c echo.Context, audSvc *auth.AudienceService, policy audiencePolicy,
	claims *auth.Claims, presented string) (bool, error) {

	if presented == auth.AudienceSelf {
		// Accepted by both surfaces. On the identity side because first-party
		// portal sessions (POST /auth/session, which carries no client_id and so
		// cannot supply an audience) are assigned this value server-side, and an
		// operator asking who they are must not be refused by the very policy
		// that protects their console.
		return true, nil
	}
	if policy == policySelf {
		return false, nil
	}

	tenantID, err := strconv.ParseInt(claims.TenantID, 10, 64)
	if err != nil || tenantID <= 0 {
		// A verified token with an unparseable tenant claim cannot be scoped to
		// a tenant's audience catalogue, so there is nothing to compare against.
		return false, nil
	}
	return audSvc.AudienceInTenant(c.Request().Context(), tenantID, presented)
}

// realAudience returns the first audience entry that is a real audience
// identifier, and whether one was found.
//
// "Real" means scheme-bearing. The legacy token-type values #130 moved out of
// this claim are bare strings — "emc-auth-api", "emc-auth-m2m",
// "emc-auth-management", "emc-auth-agent" — with no "://", so testing for the
// scheme separates a migrated token from an un-migrated one without having to
// enumerate the legacy constants and without depending on the configurable
// AUDIENCE_SCHEME. auth.AudienceSelf ("api://emc-auth") is scheme-bearing and is
// therefore real, which is correct: it is this server's own audience.
//
// #131 mints exactly one audience per token (audienceAllowed enforces a single
// value, and Sign omits the claim entirely rather than writing aud: [""]), so
// the first real entry is the only one. Iterating rather than indexing [0]
// tolerates a legacy multi-value token without mistaking its token-type string
// for an identifier.
func realAudience(claims *auth.Claims) (string, bool) {
	for _, a := range claims.Audience {
		if strings.Contains(a, "://") {
			return a, true
		}
	}
	return "", false
}
