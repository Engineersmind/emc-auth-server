# EMC Auth Server — Rate Limiting Review & Proposed Changes

**Date:** 2026-08-25 · **Reviewed against:** commit `5c47bc8`
**Prepared for:** management review

Rate limiting is what stands between our login, token, and OAuth endpoints and credential-stuffing, brute-force, and denial-of-service traffic. This document records what we have today, the six gaps found in review, and a proposed sequence of changes.

**Overall assessment: the implementation is strong.** Eleven distinct limiters are in place across every authentication surface, and nearly every constant and key choice carries an inline comment explaining its threat model. This is not a remediation document — it is a hardening backlog. Nothing here is on fire.

**The one thing to escalate:** gap #1. Our two highest-volume abuse surfaces — `/auth/login` and `/auth/token` — do not increment the rate-limit metric. When someone is throttled there, **we have no dashboard signal and no alert**. We would learn about a credential-stuffing campaign from a customer, not from monitoring. It is a one-line-per-limiter fix.

---

## Summary table

| # | Item | Type | Severity | Effort |
|---|---|---|---|---|
| 1 | **Login and token 429s are invisible to monitoring** | **Observability Gap** | **High** | **Small** |
| 2 | No global fallback limiter — new routes get zero throttling | Security Gap | High | Medium |
| 3 | In-memory limits don't survive horizontal scaling | Architectural Debt | Medium *(High once we scale)* | Large |
| 4 | Redis outage silently removes all per-application quotas | Security Gap | Medium | Small |
| 5 | No aggregate per-tenant login cap (email-rotation attacks) | Security Gap | Medium | Medium |
| 6 | Shared `unknown-account` bucket for unparseable login bodies | Minor Gap | Low | Small |

**Recommended sequence:** #1 and #4 in the next sprint (both small, both close a blind spot). #2 next. #3 becomes mandatory before we run more than one application replica — see the note there.

---

## What we have today

Two independent engines.

| | In-memory limiter | Redis limiter |
|---|---|---|
| Location | [internal/api/middleware/ratelimit.go](../internal/api/middleware/ratelimit.go) | [internal/api/middleware/applimit.go](../internal/api/middleware/applimit.go) |
| Algorithm | Token bucket (`golang.org/x/time/rate`) | GCRA (`go-redis/redis_rate/v10`) |
| Scope | Per process | Global across replicas |
| Purpose | Pre-auth, public, and abuse-shaped endpoints | Tenant-configured per-application quotas |
| On dependency failure | No dependency | Fail-open |

### The eleven in-memory limiters

Defaults are `PerIPRate: 5`, `PerTenantRate: 10` ([ratelimit.go:42](../internal/api/middleware/ratelimit.go#L42)).

| Limiter | Bucket 1 | Bucket 2 | Applied to |
|---|---|---|---|
| `LoginRateLimiter` | 5/min per IP | 10/min per email | `POST /auth/login` |
| `TokenRateLimiter` | 5/min per IP | 10/min per `client_id` | `/auth/token`, `/apps/*`, forgot-password, invitations, mail-dispatching admin routes |
| `OTPRateLimiter` | 10/min per IP | 10/min per session token | `/auth/login/otp`, `/mfa/enroll`, `/mfa/email`, `/mfa/activate`, `/otp/resend` |
| `OAuthRateLimiter` | 5/min per IP | 10/min per `client_id` | `/oauth/:provider/login`, `/callback`, `/oauth/exchange` |
| `AuthorizeRateLimiter` | 30/min per IP | — | `GET /oauth/authorize` + hosted login pages |
| `OAuthTokenRateLimiter` | 120/min per `client_id` | — | `POST /oauth/token` |
| `RevokeRateLimiter` | 60/min per IP | — | `POST /oauth/revoke` |
| `JWKSRateLimiter` | 120/min per IP | — | JWKS + OIDC discovery |
| `UserInfoRateLimiter` | 60/min per subject | — | `/oauth/userinfo` |
| `AuditMaintenanceRateLimiter` | 10/min per tenant | — | Audit CSV export, chain verify, GDPR erase |
| `SigningKeyRotationRateLimiter` | 1 per 10 min, burst 2, per tenant | — | Signing key prepare/complete |

Each limiter owns a separate bucket store, so traffic classes cannot drain each other's budget. Idle buckets are evicted after 10 minutes by a single background goroutine.

### Per-application quotas (Redis)

Tenant-configurable, stored in `app_rate_limits` keyed on `(tenant_id, application_id)`. Defaults 60 req/min, burst 10. Config is cached in Redis for 60 seconds and invalidated on write. Managed through six admin endpoints (platform-scoped and tenant-scoped `GET`/`PUT`/`DELETE` `.../applications/:appID/rate-limit`).

Two middlewares with deliberately separate bucket namespaces — `app:` for JWT-authenticated API traffic, `appauth:` for pre-auth Basic-auth traffic. This split is a security control, not a detail: `client_id` is a public identifier read *before* the secret is verified, so a shared bucket would let anyone who knows a client_id drain that application's real API quota with bogus auth requests.

### Non-HTTP throttles

- **Account lockout** — 10 consecutive failures within 15 minutes blocks the account; self-service unblock link valid 1 hour.
- **OTP attempts** — 5 wrong codes per session, enforced in Redis.
- **OTP resends** — 3 per challenge.
- **Notification email** — per-recipient hourly cap.

### Response contract

All limiters return **429** with `Retry-After`. Body shape adapts to the caller: JSON for API routes, RFC 6749 §5.2 `slow_down` for OAuth token/revoke, and HTML for `/oauth/authorize` because that caller is a browser rendering a page. Only the Redis per-app limiter emits `X-RateLimit-Limit` / `X-RateLimit-Remaining`.

---

## 1. Login and token 429s are invisible to monitoring

**Type:** Observability Gap · **Severity: High** · **Effort: Small**

### What's happening

We have a Prometheus counter, `emc_auth_rate_limit_hits_total{limiter}`. Six limiters increment it. Five do not — including the two that matter most.

| Limiter | Emits metric? |
|---|---|
| `UserInfoRateLimiter` | Yes |
| `JWKSRateLimiter` | Yes |
| `SigningKeyRotationRateLimiter` | Yes |
| `AuthorizeRateLimiter` | Yes |
| `OAuthTokenRateLimiter` | Yes |
| `RevokeRateLimiter` | Yes |
| **`LoginRateLimiter`** | **No** |
| **`TokenRateLimiter`** | **No** |
| **`OTPRateLimiter`** | **No** |
| **`OAuthRateLimiter`** | **No** |
| `AuditMaintenanceRateLimiter` | No |
| `AppRateLimiter` / `AppClientRateLimiter` | No |

### Why it matters

A credential-stuffing campaign against `/auth/login` is exactly the event this metric exists to surface, and it is the one case where the metric stays flat. Today the limiter correctly blocks the traffic and we have no idea it happened. We cannot alert on it, chart it, or report it — and we cannot distinguish "limits are working" from "limits are never being reached", which is also the signal that tells us whether a threshold is set sensibly.

The same blind spot hides *legitimate* customers hitting limits. A tenant whose integration is being throttled shows up as a support ticket rather than a dashboard line.

### Recommendation

Add one `metrics.RateLimitHits.WithLabelValues(...).Inc()` call to each un-instrumented rejection path, using distinct labels (`login_ip`, `login_account`, `token_ip`, `token_client`, `otp_ip`, `otp_session`, `oauth_ip`, `oauth_client`, `audit_maint`, `app`, `app_client`).

Then add two alerts:

- Sustained 429 rate on `login_*` or `token_*` → possible credential stuffing.
- Sustained 429 rate on `app` for a single tenant → that customer needs a quota increase.

**This is a few hours of work and it is the highest-value item in this document.**

---

## 2. No global fallback limiter

**Type:** Security Gap · **Severity: High** · **Effort: Medium**

### What's happening

Every limiter in the server is attached per route. There is no server-wide default. A new route added tomorrow with no explicit limiter is **completely unthrottled**.

This is not hypothetical — it is how we got here twice already. `JWKSRateLimiter` and `UserInfoRateLimiter` were both added retroactively, each after someone noticed a public endpoint was shipping with no limit at all. The code comments say so directly: *"a new public route inherits no throttling at all — every limiter in this server is attached per route and there is no global one."*

### Why it matters

The failure is silent and the review process doesn't reliably catch it. Nothing fails, no test breaks, no log line appears — the route simply has no ceiling until someone finds it. As the API surface grows, the chance that one slips through approaches certainty.

### Recommendation

1. Add a permissive server-wide limiter (suggested: 300/min per IP) as the outermost middleware. High enough never to affect legitimate traffic, low enough to stop an unbounded flood against a route we forgot.
2. Give it its own metric label so we can see when it — rather than a specific limiter — is doing the work. A rising global-limiter count is the signal that a route is missing its own limit.
3. Add a route-coverage test that enumerates registered routes and fails if a non-exempt route has no rate-limit middleware. This converts a silent gap into a build failure.

Item 3 is the durable fix; item 1 is the safety net while we get there.

---

## 3. In-memory limits don't survive horizontal scaling

**Type:** Architectural Debt · **Severity: Medium today, High once we scale** · **Effort: Large**

### What's happening

Nine of the eleven in-memory limiters hold their buckets in process memory. Behind a load balancer with N application instances, every stated limit becomes **N times larger** in practice — a request routed to instance B knows nothing about the budget already spent on instance A.

Our production deployment today is a **single container on a single EC2 host** ([infra/docker-compose.prod.yml](../infra/docker-compose.prod.yml)), so the limits are currently accurate as written.

### Why it matters

The exposure is entirely about *when we scale*, and the trap is that scaling out is normally a pure win requiring no application change. Here it silently multiplies every authentication rate limit. Adding a second instance for availability would quietly double the brute-force budget against every account — with no error, no warning, and no metric movement.

The original authors anticipated this. The code carries a marked integration point: *"NFR-04 Redis integration point: replace this in-memory store with a Redis-backed sliding window counter (INCR + EXPIRE with Lua) in Phase 7. The LoginRateLimiter function signature and behaviour contract remain the same — only the Allow() implementation changes."*

### Recommendation

We already run Redis, and we already use `redis_rate` for per-application quotas — so the dependency and the pattern both exist.

1. **Now:** record this as a hard prerequisite for horizontal scaling. Whoever adds a second replica must land this first. That decision must not be made by an infrastructure change alone.
2. **Then:** migrate the limiter store to Redis behind the existing interface, reusing `redis_rate` for consistency with the per-app limiter. Keep the in-memory path as a fallback for Redis outages (see #4).
3. Migrate the abuse-facing limiters first — login, token, OTP, OAuth — and leave the low-risk ones (JWKS, UserInfo) in memory if it saves time.

Sizing this as Large because it touches every limiter and needs careful testing around the fail-open behaviour. It does not need to happen this quarter, but it must happen before we scale out.

---

## 4. A Redis outage silently removes all per-application quotas

**Type:** Security Gap · **Severity: Medium** · **Effort: Small**

### What's happening

The per-application limiter fails **open**: if Redis errors, the request is allowed through. This is the right default — a Redis outage should not take down all authenticated traffic — and it is deliberately chosen and documented.

The problem is that we can't see it happening. Fail-open events are written to the log at `warn` level and counted nowhere. During a Redis incident, every tenant-configured quota stops being enforced and no metric moves.

The same applies to malformed-claim pass-throughs (`app_id` or `tenant_id` unparseable), which also fail open with a log line and no counter.

### Why it matters

"All customer quotas are currently unenforced" is a state we should know about within seconds, not discover in logs afterwards. It also compounds: on a Redis outage every request falls through to the database for its limit lookup, so the moment quotas stop being enforced is also the moment database load spikes. That is a plausible cascade, and right now it is invisible on both axes.

### Recommendation

1. Add a counter for fail-open events, labelled by cause (`redis_error`, `malformed_claim`), and alert on any sustained non-zero rate.
2. Consider a short-lived in-memory fallback bucket for when Redis is unavailable — degraded enforcement rather than none. Pairs naturally with #3.

Item 1 is small and should go in alongside #1.

---

## 5. No aggregate per-tenant login cap

**Type:** Security Gap · **Severity: Medium** · **Effort: Medium**

### What's happening

`LoginRateLimiter` applies two buckets: 5/min per IP, and 10/min per **email address**. There is no per-tenant bucket.

So an attacker with a list of valid email addresses for one customer, rotating across them, gets a fresh 10/min budget for every address. The only aggregate ceiling is the per-IP limit — and that is trivially defeated by a distributed source or a botnet.

This is a known, documented trade-off, not an oversight. The reason is real: `POST /auth/login` no longer takes a tenant slug, so at middleware time — before authentication — **there is no tenant identifier available to key on**. The code says so and explains that a genuine per-tenant bucket would have to live in the service layer, after candidate resolution.

### Why it matters

This is the shape of a real credential-stuffing attack: many accounts, few attempts each, spread across addresses. Our current per-account limit is well tuned against brute-forcing *one* account and structurally blind to spraying *many*. Because of gap #1, we would also not see it in metrics.

### Recommendation

1. Add a per-tenant login counter **in the service layer**, after `AuthService.Login` resolves the account to a tenant. Enforce a generous ceiling (e.g. 100 failed logins/min per tenant) — high enough to never affect a real customer, low enough to blunt a spray.
2. Emit a metric and alert on it. Even without enforcement, the *signal* is valuable, and it can ship first as detection-only.
3. Optionally feed it into the existing risk-scoring pipeline rather than hard-blocking, so a burst raises risk rather than locking out a whole tenant.

Recommend shipping step 2 first — detection-only is low risk and immediately useful. Enforcement can follow once we see real traffic shapes.

---

## 6. Shared bucket for unparseable login bodies

**Type:** Minor Gap · **Severity: Low** · **Effort: Small**

### What's happening

When a login request body can't be parsed as JSON, the per-account bucket falls back to the literal key `unknown-account`. All such requests from all callers share one 10/min bucket.

The fallback itself is correct and intentional — without it, sending a malformed body would bypass the per-account limit entirely, which is worse.

### Why it matters

Barely. One client sending broken JSON can consume the shared bucket and cause 429s for another client also sending broken JSON. Both are already bounded by the per-IP limit, and neither is a working request. Noted for completeness.

### Recommendation

Key the fallback on the client IP (`unknown-account:<ip>`) instead of a single global constant. That preserves the anti-bypass property while isolating callers from each other. Small, safe, no downside — worth doing whenever the file is next touched, but not worth scheduling on its own.

---

## Proposed sequence

**Next sprint — small, high value:**

- #1 Instrument the un-instrumented limiters, add two alerts.
- #4 Add fail-open counter and alert.
- #6 Fix the fallback key while in the file.
- #5 step 2 — per-tenant login counter, detection only.

**Following sprint:**

- #2 Global fallback limiter plus route-coverage test.
- #5 steps 1 and 3 — enforcement and risk-pipeline integration, informed by the data #5 step 2 gives us.

**Prerequisite, not scheduled:**

- #3 Redis-backed distributed limiters. **Must land before we run more than one application replica.** Recommend recording this as a gate on the scaling work rather than a backlog item, since the scaling change would otherwise appear safe.

The first block is roughly a few days of work and closes every monitoring blind spot in the system. That is the highest-leverage thing we can do here: most of what follows is easier to size correctly once we can actually see rate-limit traffic.
