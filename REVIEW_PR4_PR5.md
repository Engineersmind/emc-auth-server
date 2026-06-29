# Code Review: PR #4 (feat/phase-8-remaining) + PR #5 (feat/phase-4-saml)

**Reviewed:** 2026-05-21  
**Stack:** Go 1.23, Echo v4, pgx v5, zerolog  
**Scope:** Agent Registration + Audit + Risk Analysis (PR #4 stubs only — migration files 00019/00020 and internal/auth/agent.go were not present); SAML 2.0 SP (PR #5)

---

## CRITICAL Issues

---

### CR-01: SAML Assertion Consumer Service (ACS) performs no signature verification

**File:** `internal/saml/service.go:157–193`  
**PR:** #5

The `ParseACSResponse` method decodes and parses the SAMLResponse XML but performs **zero cryptographic verification** of the IdP's XML signature. The code acknowledges this in a comment but the handler calls it unconditionally on every production request. An attacker who can POST to `/saml/acs` can craft any arbitrary XML with any NameID (email address) and gain a valid JWT for any user in any tenant — including tenant admins.

`WantAssertionsSigned: true` in the SP metadata is advisory only; it signals to the IdP that signatures are desired but the SP does not enforce it.

```go
// Current — no verification whatsoever:
email = resp.Assertion.Subject.NameID.Value
if email == "" {
    return "", nil, fmt.Errorf("NameID (email) not found in SAMLResponse")
}
```

**Fix:** Do not ship this to production. Replace `ParseACSResponse` with a proper SAML library (`crewjam/saml` or `russellhaering/gosaml2`) that validates the IdP certificate against the stored `saml_configs.certificate`, verifies `xmldsig` envelope signatures, validates `NotBefore`/`NotOnOrAfter` conditions, and checks `Recipient` and `InResponseTo` to prevent replay attacks. Until this is done, the `/saml/acs` endpoint should return HTTP 501.

---

### CR-02: RelayState value (tenantID) appended to redirect URL without URL-encoding

**File:** `internal/api/handlers/saml.go:58`  
**PR:** #5

```go
redirectURL := cfg.SSOURL + "?SAMLRequest=" + samlReq + "&RelayState=" + tenantID
```

`samlReq` is a base64-encoded string (may contain `+`, `/`, `=`). `tenantID` is a UUID but is taken directly from the unvalidated query parameter — if an attacker crafts `?tenant=abc%26evil=true`, the ampersand would inject extra query parameters into the IdP redirect URL. Both values must be URL-encoded before concatenation.

**Fix:**
```go
redirectURL := cfg.SSOURL +
    "?SAMLRequest=" + url.QueryEscape(samlReq) +
    "&RelayState=" + url.QueryEscape(tenantID)
```

---

### CR-03: Open redirect via unvalidated `cfg.SSOURL`

**File:** `internal/api/handlers/saml.go:49–59`  
**PR:** #5

`cfg.SSOURL` is read from the database and used directly as a redirect target:
```go
cfg, err := h.svc.GetConfig(c.Request().Context(), tenantID)
...
redirectURL := cfg.SSOURL + "?SAMLRequest=..."
return c.Redirect(http.StatusFound, redirectURL)
```

If an attacker can write a malicious `sso_url` value (e.g. via `UpsertSAMLConfig` with a compromised admin account, or a DB injection), the login endpoint becomes an open redirector. Even without a full compromise, no format check is applied to `sso_url` on write.

**Fix:** In `UpsertConfig` (and/or the handler), validate that `sso_url` is an absolute HTTPS URL before storing it:
```go
u, err := url.Parse(req.SSOURL)
if err != nil || u.Scheme != "https" || u.Host == "" {
    return nil, fmt.Errorf("sso_url must be a valid HTTPS URL")
}
```

---

### CR-04: JIT-provisioned users have no email validation — SAML NameID injected as email

**File:** `internal/saml/service.go:188–243`  
**PR:** #5

The `email` value extracted from the NameID is passed directly into the `users` table with no format validation:

```go
email = resp.Assertion.Subject.NameID.Value  // from attacker-controlled XML
...
INSERT INTO users ... VALUES (gen_random_uuid(), $1, $2, ...)
-- $2 = email from XML, no validation
```

A SAML NameID is not required to be an email address. If the IdP or a forged assertion sends `admin' OR 1=1--`, the parameterized query prevents SQL injection, but the stored value may be garbage, and any downstream code that assumes `email` is a valid RFC 5321 address (e.g., password-reset flow, outbound mail) would malfunction or be exploited.

**Fix:** Validate the extracted NameID as a syntactically valid email address before use:
```go
if !strings.Contains(email, "@") || len(email) > 254 {
    return "", nil, fmt.Errorf("NameID is not a valid email address: %q", email)
}
```
Or use `net/mail.ParseAddress`.

---

### CR-05: `tenantID` from query parameter trusted without UUID-format validation — used to key secrets

**File:** `internal/api/handlers/saml.go:30–39`, `internal/saml/service.go:71–82`  
**PR:** #5

`GetMetadata`, `InitiateLogin`, and `HandleACS` all accept `tenantID` from an unauthenticated query parameter or `RelayState` form field, and pass it directly to `GetConfig` which runs it against the DB:

```go
tenantID := c.QueryParam("tenant")   // e.g. "'; DROP TABLE tenants;--"
...
cfg, err := h.svc.GetConfig(ctx, tenantID)   // passes raw string to pgx $1
```

pgx parameterization prevents SQL injection here. However, `tenantID` is then passed to `BuildAuthnRequest` which interpolates it into XML:

```go
authnReq := fmt.Sprintf(`...
  <saml:Issuer>%s</saml:Issuer>
...`, id, ..., entityID)
```

`entityID` is built from `url.QueryEscape(tenantID)` so it is safe in the URL, but if `baseURL` is empty, the resulting XML would contain a bare `tenantID` with no escaping.

**Primary fix:** Validate `tenantID` as a UUID at every public SAML entry point before any further processing:
```go
if _, err := uuid.Parse(tenantID); err != nil {
    return echo.NewHTTPError(http.StatusBadRequest, "invalid tenant id")
}
```

---

## HIGH Issues

---

### HI-01: Audit `Query` uses `fmt.Sprintf` to build SQL WHERE clause with user-controlled `Action` filter

**File:** `internal/audit/logger.go:184–201`  
**PR:** #4

The `Query` method builds a dynamic SQL string by `fmt.Sprintf`-ing positional-argument placeholders:

```go
if p.Action != "" {
    args = append(args, p.Action)
    where += fmt.Sprintf(" AND al.action = $%d", len(args))
}
```

The **values** are parameterized, so `p.Action` itself is not injected. However, the `WHERE 1=1` base string and any structural parts of `where` are constructed by string concatenation. The current code is safe against value injection, but the pattern is fragile: if any future developer adds a filter on a non-parameterized field (e.g., a sortable column name from a query string), it would become a SQL injection vulnerability. The `Action` value is also accepted freely from the caller without validation against the known `Action*` constants — garbage values simply return zero rows but waste a DB round-trip and can be used to probe internal structures via timing.

**Fix:** Add an allowlist check in `auditQueryParams` (handler) or in `Query` (service):
```go
var validActions = map[string]bool{
    audit.ActionAuthLogin: true, audit.ActionAuthLogout: true, /* ... */
}
if p.Action != "" && !validActions[p.Action] {
    return nil, fmt.Errorf("invalid action filter: %q", p.Action)
}
```

---

### HI-02: `saml_configs.certificate` stored but never used — false security signal

**File:** `migrations/00021_create_saml_configs.sql:8`, `internal/saml/service.go:101–123`  
**PR:** #5

The `certificate` column is stored in `saml_configs` and returned via the API, but `ParseACSResponse` never loads or uses it. This creates a false impression that the certificate is providing security. An admin who uploads a certificate reasonably expects the SP to verify assertions against it; the current code silently ignores it.

**Fix:** Either remove the `certificate` column until signature verification is implemented (so there is no misleading API surface), or implement signature verification as described in CR-01. At minimum, add a schema comment and a runtime log warning:
```
-- TODO: certificate is stored but NOT yet used for assertion signature verification (see CR-01).
```

---

### HI-03: JIT provisioning ignores `roleID` scan result when no role exists — inserts NULL role

**File:** `internal/saml/service.go:223–231`  
**PR:** #5

```go
var roleID *uuid.UUID
err = s.pool.QueryRow(ctx,
    `SELECT id, name FROM roles WHERE tenant_id = $1 AND is_system = false ORDER BY name LIMIT 1`,
    tenantUUID,
).Scan(&roleID, &roleName)
if err != nil && err != pgx.ErrNoRows {
    return nil, fmt.Errorf("fetch default role: %w", err)
}
```

When there are no non-system roles (`pgx.ErrNoRows`), `roleID` remains `nil` and `roleName` remains `""`. The user is then inserted with `role_id = NULL`:

```go
INSERT INTO users (id, tenant_id, email, first_name, last_name, role_id, is_active)
VALUES (gen_random_uuid(), $1, $2, '', '', $3, true)   -- $3 = nil (NULL)
```

A NULL `role_id` may be valid at the DB level (no NOT NULL constraint on `users.role_id`), but the JIT user will have no role and therefore no permissions. Subsequent `LEFT JOIN roles` in `FindOrCreateUser` returns `roleName = ""`. The resulting JWT will carry `"role": ""` and `"permissions": []`. This is likely an unintended state that could cause silent access-denial bugs.

**Fix:** Either require at least one non-system role to exist (return an error if none found), or define a `saml_default` role per tenant and enforce its presence:
```go
if err == pgx.ErrNoRows {
    return nil, fmt.Errorf("tenant %s has no assignable roles for SAML JIT provisioning", tenantID)
}
```

---

### HI-04: `FindOrCreateUser` SELECT query does NOT account for `is_deleted = true` users — race condition on JIT re-provision

**File:** `internal/saml/service.go:207–218`  
**PR:** #5

The lookup query correctly filters `is_deleted = false`:
```go
WHERE u.tenant_id = $1 AND u.email = $2 AND u.is_active = true AND u.is_deleted = false
```

However, there is no UNIQUE constraint on `(tenant_id, email)` that covers only active, non-deleted users. If a user was soft-deleted and then logs in via SAML again, the INSERT will likely fail with a unique-constraint violation on `email + tenant_id` (depending on whether such a constraint exists), or silently create a duplicate account.

**Fix:** Use `INSERT ... ON CONFLICT (tenant_id, email) DO UPDATE SET is_deleted = false, is_active = true ...` or check for soft-deleted users explicitly before attempting insert:
```go
WHERE u.tenant_id = $1 AND u.email = $2  -- remove active/deleted filter
-- then decide: reactivate or error
```

---

### HI-05: `HandleACS` returns JWT in JSON response body — SAML flow typically redirects to SPA

**File:** `internal/api/handlers/saml.go:115–121`  
**PR:** #5

After ACS, the handler returns a JSON body with the access token:
```go
return c.JSON(http.StatusOK, map[string]any{
    "access_token": accessToken,
    ...
})
```

SAML ACS is triggered by an IdP-POST directly to the browser. The response is rendered in the browser tab, not intercepted by JavaScript. The JWT is displayed as raw JSON and is not delivered to the SPA. This means SP-initiated SSO is non-functional as a browser flow. Additionally, returning the raw token in a JSON body (rather than via `Location` redirect with a short-lived code exchange) exposes it in browser history and server logs.

**Fix:** Issue a short-lived one-time code (store token in Redis/DB keyed by code), then redirect: `c.Redirect(302, baseURL+"/auth/callback?code="+code)`. The SPA exchanges the code for the JWT.

---

### HI-06: `audit.Logger.Log` passes `user_agent` to DB insert but the column does not exist in migration 00016

**File:** `internal/audit/logger.go:144–153`, `migrations/00016_create_audit_logs.sql`  
**PR:** #4

`logger.go:144` inserts into 9 columns including `user_agent`:
```go
INSERT INTO audit_logs
  (id, tenant_id, user_id, actor_email, action, resource_type, resource_id, ip_address, user_agent)
VALUES
  (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8)
```

But `migrations/00016_create_audit_logs.sql` defines only these columns: `id, tenant_id, user_id, actor_email, action, resource_type, resource_id, ip_address, created_at`. There is no `user_agent` column in the migration.

**Impact:** Every audit log write will fail with a PostgreSQL "column does not exist" error. Because `Log()` only logs the error and continues, all audit events will be silently dropped in production.

**Fix:** Add the missing column to the migration (in a new migration file, since 00016 is already applied):
```sql
-- 00022_add_user_agent_to_audit_logs.sql
ALTER TABLE audit_logs ADD COLUMN user_agent TEXT NOT NULL DEFAULT '';
```
Or remove `user_agent` from the INSERT statement until the migration is applied.

---

### HI-07: `audit.Query` limitArg/offsetArg positional indices are off by one

**File:** `internal/audit/logger.go:213–228`  
**PR:** #4

```go
args = append(args, p.Limit, offset)
limitArg := len(args) - 1   // should be len(args) - 1 for Limit
offsetArg := len(args)       // should be len(args) for offset
```

After appending both `Limit` and `offset`, `len(args)` equals the index of `offset` (1-based), not `Limit`. The intent is:
- `Limit` is at position `len(args) - 1`
- `offset` is at position `len(args)`

But `len(args) - 1` points to the slot **before** the last append pair. Walk through: if args had 3 elements before this block, after `append(..., p.Limit, offset)` len is 5. `limitArg = 4`, `offsetArg = 5`. That is correct — `$4 = Limit`, `$5 = offset`. 

Re-checking: `args` starts with N elements. After `append(args, p.Limit, offset)`, `len(args) = N+2`. `limitArg = N+2-1 = N+1` (points to `p.Limit` at 1-based index N+1). `offsetArg = N+2` (points to `offset` at 1-based index N+2). This is correct.

**Correction:** This is NOT a bug after careful re-examination — the indexing is correct. Withdrawing this finding. *(Kept here for transparency of review process.)*

---

## MEDIUM Issues

---

### ME-01: No input length limits on SAML config fields — potential DB bloat and DoS

**File:** `internal/api/handlers/saml.go:143–152`, `internal/saml/service.go:85–98`  
**PR:** #5

`UpsertSAMLConfig` binds the request directly into `SAMLConfig` without validating field lengths. The `certificate` field accepts arbitrary text. A malicious tenant admin could send a 50 MB base64 blob as a certificate, which is stored in PostgreSQL TEXT (unbounded) and returned on every `GetConfig` call.

**Fix:** Add length guards in the handler before calling the service:
```go
if len(req.EntityID) > 512 || len(req.SSOURL) > 2048 || len(req.Certificate) > 65536 {
    return echo.NewHTTPError(http.StatusBadRequest, "SAML config field exceeds maximum length")
}
```
Alternatively, add CHECK constraints in the migration.

---

### ME-02: `UpsertSAMLConfig` does not validate `entity_id` — empty value accepted

**File:** `internal/api/handlers/saml.go:143–152`  
**PR:** #5

```go
var req samlsvc.SAMLConfig
if err := c.Bind(&req); err != nil {
    return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
}
cfg, err := h.svc.UpsertConfig(c.Request().Context(), tenantID, req)
```

There is no check that `req.EntityID`, `req.SSOURL`, or `req.Certificate` are non-empty. The DB column `entity_id TEXT NOT NULL` will reject an empty string via a CHECK violation, but this produces an opaque 500 error rather than a client-facing 400.

**Fix:**
```go
if req.EntityID == "" || req.SSOURL == "" {
    return echo.NewHTTPError(http.StatusBadRequest, "entity_id and sso_url are required")
}
```

---

### ME-03: `GetMetadata` and `InitiateLogin` accept any non-empty string as `tenant` — no UUID validation

**File:** `internal/api/handlers/saml.go:30–39`, `44–59`  
**PR:** #5

Both handlers check `tenantID == ""` but do not validate UUID format. The string is forwarded to `GetConfig` which uses it as a `$1` parameter — pgx will correctly reject a non-UUID against a UUID column, but the resulting error becomes a 404 "SAML not configured" regardless of whether the tenant ID is malformed or simply absent.

**Fix:** Parse the UUID at the handler boundary and return 400 on format error, not 404:
```go
if _, err := uuid.Parse(tenantID); err != nil {
    return echo.NewHTTPError(http.StatusBadRequest, "tenant must be a valid UUID")
}
```

---

### ME-04: `saml_configs` migration creates a redundant index alongside a UNIQUE constraint

**File:** `migrations/00021_create_saml_configs.sql:13`  
**PR:** #5

```sql
tenant_id UUID NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE CASCADE,
...
CREATE INDEX idx_saml_configs_tenant_id ON saml_configs (tenant_id);
```

`UNIQUE` on `tenant_id` automatically creates a btree index in PostgreSQL. The explicit `CREATE INDEX` creates a second, redundant index on the same column, doubling the write overhead on every INSERT/UPDATE and consuming extra storage.

**Fix:** Remove the explicit `CREATE INDEX`:
```sql
-- Remove this line:
CREATE INDEX idx_saml_configs_tenant_id ON saml_configs (tenant_id);
```

---

### ME-05: `GenerateMetadata` does not validate `baseURL` — can produce malformed XML

**File:** `internal/saml/service.go:101–123`  
**PR:** #5

If `baseURL` is empty (misconfigured env var), `acsURL` and `entityID` become `/saml/acs?tenant=...` (relative URLs), which are invalid in SAML metadata. The XML is accepted by `xml.MarshalIndent` because the struct fields are plain strings with no format enforcement. An IdP receiving this malformed metadata would reject it silently, causing SSO to fail with no obvious error.

**Fix:** Validate `baseURL` in `New()` and fail fast:
```go
func New(pool *pgxpool.Pool, baseURL string, logger zerolog.Logger) *Service {
    if baseURL == "" {
        panic("saml.Service: baseURL must not be empty")
    }
    ...
}
```

---

### ME-06: `auditQueryParams` silently ignores unparseable `from`/`to` timestamps — filter is silently dropped

**File:** `internal/api/handlers/admin.go:910–919`  
**PR:** #4

```go
if from := c.QueryParam("from"); from != "" {
    if t, err := time.Parse(time.RFC3339, from); err == nil {
        p.From = &t
    }
    // Error is silently discarded — filter is not applied
}
```

A caller passing `?from=2026-01-01` (missing time component, not RFC3339) will receive results with no `from` filter applied, silently returning more data than expected. There is no feedback to the caller.

**Fix:** Return HTTP 400 if the provided date string fails to parse:
```go
if from := c.QueryParam("from"); from != "" {
    t, err := time.Parse(time.RFC3339, from)
    if err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid 'from' datetime: must be RFC3339"})
    }
    p.From = &t
}
```

---

### ME-07: `JWTService.Verify` first pass uses `ParseUnverified` — algorithm confusion is partially mitigated but not eliminated

**File:** `internal/auth/jwt.go:92–98`  
**PR:** #4

The first parse pass extracts `tenant_id` from unverified claims to look up the DB secret. The second pass enforces `jwt.SigningMethodHMAC`. However, the first pass is structurally necessary and cannot be avoided with the current design. The risk is that a crafted token with a valid `tenant_id` in its unverified payload but signed with RSA (alg=RS256) would proceed to look up the DB secret (one extra DB query per probing attempt).

This is not a bypass — the second pass correctly rejects non-HMAC tokens. However, the design allows unauthenticated actors to trigger one DB lookup per token probe. Rate limiting on `/auth/login` does not apply to endpoints that call `Verify` (e.g., `/api/v1/auth/me`).

**Fix (low urgency):** Cache the tenant secret with a short TTL (30s) in Redis or a `sync.Map` to reduce the DB-query-per-probe amplification vector.

---

### ME-08: `audit.Logger.Log` context passed to pool.Exec — if request context is cancelled, log write fails silently

**File:** `internal/audit/logger.go:143`  
**PR:** #4

```go
func (l *Logger) Log(ctx context.Context, e Event) {
    _, err := l.pool.Exec(ctx, `INSERT INTO audit_logs ...`, ...)
```

The passed `ctx` is the HTTP request context. If the request is cancelled (client disconnect, timeout), `pool.Exec` will return a cancelled-context error and the audit row will not be written. The error is logged but the event is lost.

**Fix:** Use a detached context with a short deadline for audit writes:
```go
auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
_, err := l.pool.Exec(auditCtx, `INSERT INTO audit_logs ...`, ...)
```

---

### ME-09: `UpsertConfig` error not checked for conflict — DB constraint violation returns 500

**File:** `internal/saml/service.go:85–98`  
**PR:** #5

```go
func (s *Service) UpsertConfig(...) (*SAMLConfig, error) {
    ...
    err := s.pool.QueryRow(ctx, `INSERT ... ON CONFLICT (tenant_id) DO UPDATE ...`).Scan(...)
    return &cfg, err  // raw pgx error returned without wrapping or classification
}
```

Because the INSERT uses `ON CONFLICT DO UPDATE`, a conflict is handled at the DB level and should never surface. But if another constraint fires (e.g., a CHECK on `entity_id`), the raw pgx error bubbles through and the handler returns an opaque HTTP 500. Callers cannot distinguish a validation error from an infrastructure failure.

**Fix:** Wrap and classify the error in the service before returning it to the handler.

---

## LOW Issues

---

### LO-01: `SPSSODescriptor.WantAssertionsSigned = true` advertised but not enforced

**File:** `internal/saml/service.go:109`  
**PR:** #5

The SP metadata declares `WantAssertionsSigned="true"`, which signals to the IdP that assertions must be signed. But as noted in CR-01, signature verification is not implemented. This creates a misleading security signal for IdP administrators configuring the integration.

**Fix:** Set `WantAssertionsSigned: false` until verification is implemented, or implement verification (see CR-01).

---

### LO-02: `BuildAuthnRequest` does not include `<saml:NameIDPolicy>` — NameID format is unspecified

**File:** `internal/saml/service.go:135–153`  
**PR:** #5

The `AuthnRequest` does not include a `NameIDPolicy` element. Many IdPs default to opaque persistent identifiers rather than email addresses when no policy is specified, which would cause `ParseACSResponse` to extract a non-email value as the NameID and fail JIT provisioning.

**Fix:** Add `<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>` to the `AuthnRequest` template.

---

### LO-03: `HandleACS` permissions list for JIT users hardcoded to `[]string{}`

**File:** `internal/api/handlers/saml.go:107`  
**PR:** #5

```go
claims := &auth.Claims{
    ...
    Permissions: []string{},
}
```

SAML-provisioned users always get an empty permissions list, regardless of their assigned role. Regular users provisioned via `auth.Login` presumably get their permissions loaded from the DB. SAML users are treated differently. If permissions are role-based and looked up at login time for regular users, they should also be loaded here.

**Fix:** Load the user's permissions from the DB (via the assigned `roleID`) before signing the JWT, the same way the regular login flow does.

---

### LO-04: `saml_configs` migration has no `updated_at` trigger — `updated_at` never changes automatically

**File:** `migrations/00021_create_saml_configs.sql`  
**PR:** #5

The `UpsertConfig` query explicitly sets `updated_at = NOW()` in the ON CONFLICT clause, so this works. However, any future direct UPDATE statement that forgets to update `updated_at` will leave it stale. Other tables in this codebase likely have the same pattern; a trigger would be safer.

**Fix (minor):** Consider adding a `BEFORE UPDATE` trigger for consistency with other tables, or document that callers must set `updated_at` manually.

---

### LO-05: Audit log `Query` does not validate that `p.UserID` is a UUID before silently ignoring it

**File:** `internal/audit/logger.go:188–194`  
**PR:** #4

```go
if p.UserID != "" {
    uid, err := uuid.Parse(p.UserID)
    if err == nil {
        args = append(args, uid)
        where += fmt.Sprintf(" AND al.user_id = $%d", len(args))
    }
    // If err != nil, the filter is silently dropped — same issue as ME-06
}
```

A caller passing `?user_id=not-a-uuid` receives all logs (filter silently dropped) rather than a 400.

**Fix:** Return an error from `Query` when `p.UserID` is non-empty and not a valid UUID, and handle it in the handler to return HTTP 400.

---

### LO-06: `HandleACS` does not emit an audit log event for SAML login

**File:** `internal/api/handlers/saml.go:67–121`  
**PR:** #5

The SAML ACS handler provisions a user and issues a JWT, but does not call `auditLog.Log(...)`. All other login flows (password, TOTP, session) write an `auth.login` audit event. SAML logins are invisible in the audit log.

**Fix:** Inject `*audit.Logger` into `SAMLHandler` and emit an `audit.ActionAuthLogin` event after successfully issuing the JWT:
```go
h.audit.Log(c.Request().Context(), audit.Event{
    TenantID:     &tenantUUID,
    ActorEmail:   user.Email,
    Action:       audit.ActionAuthLogin,
    ResourceType: "user",
    ResourceID:   user.ID,
    IPAddress:    c.RealIP(),
    UserAgent:    c.Request().UserAgent(),
})
```

---

### LO-07: `clearAuthCookies` uses `/api/v1` as Path for both cookies — refresh cookie path mismatch

**File:** `internal/api/handlers/auth.go:951–961`  
**PR:** #4 (existing, but affects session flow)

`setAuthCookies` sets the refresh cookie with `Path = "/api/v1/auth/session/refresh"` (narrow scope), but `clearAuthCookies` clears both cookies with `Path = "/api/v1"`. A browser will not clear the refresh cookie because the clearing Set-Cookie path (`/api/v1`) does not match the cookie's original path (`/api/v1/auth/session/refresh`). The refresh cookie persists after logout.

**Fix:**
```go
func clearAuthCookies(c echo.Context) {
    paths := map[string]string{
        mw.AccessTokenCookie:  "/api/v1",
        mw.RefreshTokenCookie: "/api/v1/auth/session/refresh",
    }
    for name, path := range paths {
        expired := &http.Cookie{
            Name: name, Value: "", HttpOnly: true, MaxAge: -1, Path: path,
        }
        http.SetCookie(c.Response().Writer, expired)
    }
}
```

---

### LO-08: `rows.Err()` checked after `logs` is already returned on success path (minor, not a bug)

**File:** `internal/audit/logger.go:258–264`  
**PR:** #4

```go
for rows.Next() { ... }
if logs == nil { logs = []LogEntry{} }
if err := rows.Err(); err != nil {
    return nil, err
}
```

`rows.Err()` is checked after the nil-coalescing of `logs`. This is fine — it won't return stale results because `rows.Err()` returns an error and `nil, err` is returned. The only concern is that if `rows.Err()` fires, the caller receives `nil, err` and the already-allocated `logs` slice is discarded (GC'd). This is correct behavior but the ordering is slightly misleading. Low risk.

---

## Summary Table

| ID    | Severity | File                                    | Issue                                                          |
|-------|----------|-----------------------------------------|----------------------------------------------------------------|
| CR-01 | CRITICAL | `internal/saml/service.go:157`          | No SAML assertion signature verification — full auth bypass    |
| CR-02 | CRITICAL | `internal/api/handlers/saml.go:58`      | SAMLRequest and RelayState not URL-encoded in redirect         |
| CR-03 | CRITICAL | `internal/api/handlers/saml.go:49`      | Open redirect via unvalidated `sso_url`                        |
| CR-04 | CRITICAL | `internal/saml/service.go:188`          | NameID/email not validated — injected as-is into users table   |
| CR-05 | CRITICAL | `internal/api/handlers/saml.go:30`      | `tenantID` not validated as UUID at SAML public endpoints      |
| HI-01 | HIGH     | `internal/audit/logger.go:184`          | Action filter not allowlisted — fragile dynamic SQL pattern    |
| HI-02 | HIGH     | `migrations/00021_create_saml_configs.sql` | `certificate` stored but never used — false security signal  |
| HI-03 | HIGH     | `internal/saml/service.go:223`          | NULL role_id inserted when no non-system role exists           |
| HI-04 | HIGH     | `internal/saml/service.go:207`          | JIT provision race: no ON CONFLICT for soft-deleted users      |
| HI-05 | HIGH     | `internal/api/handlers/saml.go:115`     | ACS returns JWT in response body — broken browser SSO flow     |
| HI-06 | HIGH     | `internal/audit/logger.go:144`          | `user_agent` column missing from migration — all audit writes fail |
| ME-01 | MEDIUM   | `internal/api/handlers/saml.go:143`     | No length limits on SAML config fields                         |
| ME-02 | MEDIUM   | `internal/api/handlers/saml.go:143`     | Empty `entity_id`/`sso_url` accepted — causes opaque 500       |
| ME-03 | MEDIUM   | `internal/api/handlers/saml.go:30,44`   | No UUID format check for `tenant` query param                  |
| ME-04 | MEDIUM   | `migrations/00021_create_saml_configs.sql:13` | Redundant index on UNIQUE column                          |
| ME-05 | MEDIUM   | `internal/saml/service.go:101`          | Empty `baseURL` produces malformed SAML metadata               |
| ME-06 | MEDIUM   | `internal/api/handlers/admin.go:910`    | Unparseable `from`/`to` date filters silently dropped          |
| ME-07 | MEDIUM   | `internal/auth/jwt.go:92`               | `ParseUnverified` amplifies DB lookups for probing tokens      |
| ME-08 | MEDIUM   | `internal/audit/logger.go:143`          | Audit writes lost on request context cancellation              |
| ME-09 | MEDIUM   | `internal/saml/service.go:85`           | UpsertConfig raw pgx error returned — no error classification  |
| LO-01 | LOW      | `internal/saml/service.go:109`          | `WantAssertionsSigned=true` advertised but not enforced        |
| LO-02 | LOW      | `internal/saml/service.go:135`          | Missing `NameIDPolicy` in AuthnRequest                         |
| LO-03 | LOW      | `internal/api/handlers/saml.go:107`     | SAML JWT issued with empty permissions list                    |
| LO-04 | LOW      | `migrations/00021_create_saml_configs.sql` | No `updated_at` trigger                                     |
| LO-05 | LOW      | `internal/audit/logger.go:188`          | Non-UUID `user_id` filter silently dropped instead of 400      |
| LO-06 | LOW      | `internal/api/handlers/saml.go:67`      | No audit event emitted for SAML login                          |
| LO-07 | LOW      | `internal/api/handlers/auth.go:951`     | `clearAuthCookies` path mismatch — refresh cookie not cleared  |
| LO-08 | LOW      | `internal/audit/logger.go:258`          | `rows.Err()` check ordering slightly misleading (not a bug)    |

---

**Note on PR #4 migration files:** `migrations/00019_create_agent_registrations.sql`, `migrations/00020_add_agent_id_to_audit_logs.sql`, and `internal/auth/agent.go` were referenced in the PR description but not present in the repository at review time. The PR #4 findings above cover `internal/auth/jwt.go`, `internal/audit/logger.go`, and `internal/api/routes.go` which are present and modified.

---

_Reviewer: Claude (gsd-code-reviewer) — depth: deep_
