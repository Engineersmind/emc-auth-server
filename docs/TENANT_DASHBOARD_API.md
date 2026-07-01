# Tenant Dashboard API Reference

> Branch: `feat/issue-51-tenant-dashboard-apis`  
> Issue: [#51](https://github.com/Engineersmind/emc-auth-server/issues/51)

**Base URL:** `http(s)://<host>/api/v1`  
**All endpoints require:** `Authorization: Bearer <token>`  
**Tenant management endpoints additionally require:** `tenant:manage` permission (super-admin only)

---

## Schema Changes

Migration `00040_tenants_dashboard_fields.sql` added five new columns to the `tenants` table.  
The migration runs **automatically on server startup** — no manual CLI step needed.

| Column | Type | Nullable | Default | Purpose |
|---|---|---|---|---|
| `display_name` | TEXT | yes | — | Human-friendly label shown in the UI |
| `domain` | TEXT | yes | — | Canonical domain e.g. `acme.com` |
| `region` | TEXT | yes | — | Deployment region; indexed for filtering |
| `description` | TEXT | yes | — | Free-text tenant description |
| `plan` | TEXT | no | `'free'` | Subscription tier: `free` / `pro` / `enterprise` |

---

## Shared Response Shape — `TenantResult`

Every endpoint that returns a single tenant uses this exact shape:

```json
{
  "id": "42",
  "name": "Acme Corp",
  "slug": "acme",
  "display_name": "Acme Corporation",
  "domain": "acme.com",
  "region": "us-east",
  "description": "Primary production tenant",
  "plan": "pro",
  "is_active": true,
  "cors_origins": ["https://app.acme.com"],
  "created_at": "2025-01-15T10:00:00Z",
  "updated_at": "2026-06-30T08:42:00Z"
}
```

| Field | Type | Notes |
|---|---|---|
| `id` | string | Numeric but always a string — do not cast to int |
| `display_name` | string \| null | `null` when not set |
| `domain` | string \| null | `null` when not set |
| `region` | string \| null | `null` when not set |
| `description` | string \| null | `null` when not set |
| `plan` | string | Always present; defaults to `"free"` |
| `cors_origins` | string[] | Always an array, never null |
| `created_at` / `updated_at` | string | ISO 8601 UTC |

---

## Endpoints

---

### GET `/api/v1/tenants/stats`

<!-- Frontend use: Dashboard home page — populates the four top stat cards
     (Total Tenants, Active Tenants, Applications, Users) and their
     month-over-month growth/decline badges. Call once on page load. -->

**What it does:** Returns system-wide aggregate counts with month-over-month percentage deltas.  
**Permission:** `tenant:manage`

**Request**
```http
GET /api/v1/tenants/stats
Authorization: Bearer <token>
```

No query params. No body.

**Response `200`**
```json
{
  "total_tenants": 142,
  "active_tenants": 138,
  "total_applications": 24,
  "total_users": 1850,
  "delta": {
    "total_tenants_pct": 8.6,
    "active_tenants_pct": 4.2,
    "total_applications_pct": 12.5,
    "total_users_pct": 3.1
  }
}
```

| Field | Notes |
|---|---|
| `delta.*_pct` | Change vs prior calendar month. Positive = growth, negative = decline. `100.0` when prior was 0 and current > 0. `0.0` when both are 0. |
| `total_applications` | Non-deleted OAuth clients |
| `total_users` | Non-deleted users across all tenants |

**Errors**
| Status | Body | Cause |
|---|---|---|
| `401` | `{"error":"…"}` | Missing / invalid token |
| `403` | `{"error":"…"}` | Missing `tenant:manage` permission |
| `500` | `{"error":"failed to retrieve dashboard stats"}` | DB error |

---

### GET `/api/v1/tenants/check-slug`

<!-- Frontend use: Create-tenant form — real-time slug availability indicator.
     Fire on a 300 ms debounce as the user types in the slug field.
     Show a green tick when available=true, red cross when false.
     Always call before submitting the create form. -->

**What it does:** Checks whether a slug is available before creating a tenant. Always returns `200`.  
**Permission:** `tenant:manage`

**Request**
```http
GET /api/v1/tenants/check-slug?slug=acme
Authorization: Bearer <token>
```

| Query param | Required | Description |
|---|---|---|
| `slug` | yes | Slug string to check |

**Response `200`**
```json
{ "slug": "acme", "available": true }
```

`available: false` → slug already taken.

**Errors**
| Status | Body | Cause |
|---|---|---|
| `400` | `{"error":"slug is required"}` | `slug` param omitted |
| `500` | `{"error":"failed to check slug"}` | DB error |

---

### GET `/api/v1/tenants`

<!-- Frontend use: Tenant management table — primary data source for the list page.
     Wire the search input, status filter, region dropdown, and pagination controls
     directly to these query params. The `total` field drives the "X tenants found" label. -->

**What it does:** Returns a paginated, filterable list of tenants.  
**Permission:** `tenant:manage`

**Request**
```http
GET /api/v1/tenants?page=1&per_page=25&search=acme&status=active&region=us-east
Authorization: Bearer <token>
```

| Query param | Type | Default | Description |
|---|---|---|---|
| `page` | int | `1` | Page number, 1-based |
| `per_page` | int | `25` | Rows per page; max `100`. Alias: `limit` |
| `search` | string | — | Case-insensitive match on `name`, `display_name`, or `domain` |
| `status` | string | — | `active`, `inactive`, or `suspended` (suspended maps to inactive); omit for all |
| `region` | string | — | Exact match on `region`; omit for all |

**Response `200`**
```json
{
  "data": [
    {
      "id": "42",
      "name": "Acme Corp",
      "slug": "acme",
      "display_name": "Acme Corporation",
      "domain": "acme.com",
      "region": "us-east",
      "description": "Primary production tenant",
      "plan": "pro",
      "is_active": true,
      "cors_origins": ["https://app.acme.com"],
      "created_at": "2025-01-15T10:00:00Z",
      "updated_at": "2026-06-30T08:42:00Z"
    }
  ],
  "total": 142,
  "page": 1,
  "total_pages": 6,
  "per_page": 25
}
```

| Field | Notes |
|---|---|
| `data` | Array of TenantResult; always an array, never null |
| `total` | Total rows matching the active filters — use for "X results" label and pagination math |
| `total_pages` | At least `1` even when `total` is `0` |
| `per_page` | Actual page size applied (after clamping to max 100) |

**Errors**
| Status | Body | Cause |
|---|---|---|
| `401` | `{"error":"…"}` | Missing / invalid token |
| `403` | `{"error":"…"}` | Missing `tenant:manage` permission |
| `500` | `{"error":"failed to list tenants"}` | DB error |

---

### GET `/api/v1/tenants/:id`

<!-- Frontend use: Tenant detail / edit page — load the full tenant record when the user
     opens a specific tenant. Also call this to refresh the row after an activate or
     update operation to get the latest state. -->

**What it does:** Returns a single tenant by its numeric ID.  
**Permission:** `tenant:manage`

**Request**
```http
GET /api/v1/tenants/42
Authorization: Bearer <token>
```

**Response `200` → [TenantResult](#shared-response-shape--tenantresult)**

**Errors**
| Status | Body | Cause |
|---|---|---|
| `400` | `{"error":"invalid tenant id"}` | ID is not a valid integer |
| `404` | `{"error":"tenant not found"}` | No tenant with that ID |
| `500` | `{"error":"failed to get tenant"}` | DB error |

---

### POST `/api/v1/tenants`

<!-- Frontend use: Create-tenant modal / page — the form submit handler.
     On 201: store response.owner.temp_password somewhere safe to display once
     (e.g. a "copy to clipboard" dialog), close the modal, prepend
     response.tenant to the tenant list, and refresh the stats card totals.
     Pre-validate the slug via check-slug before calling this. -->

**What it does:** Creates a new tenant and automatically seeds inside it:
- **8 default permissions** (`users:read`, `users:write`, `roles:read`, `roles:write`, `permissions:read`, `permissions:write`, `apps:read`, `apps:write`)
- **`owner` system role** with all 8 permissions assigned
- **Owner user** with email `owner@emc.<slug>` and a randomly generated 12-char temp password

The `owner.temp_password` is returned **once only** in this response — it is never stored in plaintext. Hand it to the tenant owner so they can log in and change their password.  
**Permission:** `tenant:manage`

**Request**
```http
POST /api/v1/tenants
Authorization: Bearer <token>
Content-Type: application/json
```
```json
{
  "name": "Acme Corp",
  "slug": "acme",
  "display_name": "Acme Corporation",
  "domain": "acme.com",
  "region": "us-east",
  "description": "Primary production tenant",
  "plan": "pro"
}
```

| Field | Required | Notes |
|---|---|---|
| `name` | yes | Non-empty string |
| `slug` | yes | Non-empty; must be unique — pre-check with `/check-slug` |
| `display_name` | no | Stored as `NULL` if omitted or `""` |
| `domain` | no | Stored as `NULL` if omitted or `""` |
| `region` | no | Stored as `NULL` if omitted or `""` |
| `description` | no | Stored as `NULL` if omitted or `""` |
| `plan` | no | `free` / `pro` / `enterprise`; defaults to `free` if omitted |

**Response `201`**
```json
{
  "tenant": {
    "id": "42",
    "name": "Acme Corp",
    "slug": "acme",
    "display_name": "Acme Corporation",
    "domain": "acme.com",
    "region": "us-east",
    "description": "Primary production tenant",
    "plan": "pro",
    "is_active": true,
    "cors_origins": [],
    "created_at": "2026-07-01T12:00:00Z",
    "updated_at": "2026-07-01T12:00:00Z"
  },
  "owner": {
    "id": "7",
    "email": "owner@emc.acme",
    "temp_password": "Xk9mP2qLrZ8n",
    "role": "owner"
  }
}
```

| Field | Notes |
|---|---|
| `tenant` | Full TenantResult for the newly created tenant |
| `owner.id` | Numeric user ID (as string) of the seeded owner user |
| `owner.email` | Always `owner@emc.<slug>` |
| `owner.temp_password` | Plaintext password, **shown once only** — never stored; display to super-admin to hand off |
| `owner.role` | Always `"owner"` |

**Errors**
| Status | Body | Cause |
|---|---|---|
| `400` | `{"error":"name and slug are required"}` | `name` or `slug` is empty |
| `400` | `{"error":"plan must be one of: free, pro, enterprise"}` | Invalid plan value |
| `409` | `{"error":"slug already taken"}` | Slug already exists |
| `500` | `{"error":"failed to create tenant"}` | DB error |

---

### PUT `/api/v1/tenants/:id`

<!-- Frontend use: Edit-tenant form save button — called when the user submits
     changes on the tenant settings/detail page.
     On 200: replace the local tenant object in state with the returned TenantResult.
     Send "" for a nullable field to clear it in the database. -->

**What it does:** Updates editable fields on a tenant. `name` is the only required field.  
**Permission:** `tenant:manage`

**Request**
```http
PUT /api/v1/tenants/42
Authorization: Bearer <token>
Content-Type: application/json
```
```json
{
  "name": "Acme Corp",
  "display_name": "Acme Corporation",
  "domain": "acme.com",
  "region": "us-east",
  "description": "Updated description",
  "plan": "enterprise"
}
```

| Field | Required | Notes |
|---|---|---|
| `name` | yes | Non-empty string |
| `display_name` | no | Send `""` to clear (sets column to `NULL`) |
| `domain` | no | Send `""` to clear |
| `region` | no | Send `""` to clear |
| `description` | no | Send `""` to clear |
| `plan` | no | `free` / `pro` / `enterprise`; send `""` to leave unchanged |

**Response `200` → [TenantResult](#shared-response-shape--tenantresult)**

**Errors**
| Status | Body | Cause |
|---|---|---|
| `400` | `{"error":"invalid tenant id"}` | ID is not a valid integer |
| `400` | `{"error":"invalid request body"}` | Malformed JSON |
| `400` | `{"error":"name is required"}` | `name` is empty |
| `400` | `{"error":"plan must be one of: free, pro, enterprise"}` | Invalid non-empty plan |
| `404` | `{"error":"tenant not found"}` | No tenant with that ID |
| `500` | `{"error":"failed to update tenant"}` | DB error |

---

### PUT `/api/v1/tenants/:id/activate`

<!-- Frontend use: "Activate" button on inactive tenant rows/cards.
     On 200: flip the row/card to active state using the returned TenantResult.
     On 409: show an "Already active" toast and refresh the row — local state was stale. -->

**What it does:** Re-activates a previously deactivated tenant (`is_active = true`).  
**Permission:** `tenant:manage`

**Request**
```http
PUT /api/v1/tenants/42/activate
Authorization: Bearer <token>
```

No request body.

**Response `200` → [TenantResult](#shared-response-shape--tenantresult)**

**Errors**
| Status | Body | Cause |
|---|---|---|
| `400` | `{"error":"invalid tenant id"}` | ID is not a valid integer |
| `404` | `{"error":"tenant not found"}` | No tenant with that ID |
| `409` | `{"error":"tenant already active"}` | Tenant is already active |
| `500` | `{"error":"failed to activate tenant"}` | DB error |

---

### DELETE `/api/v1/tenants/:id`

<!-- Frontend use: "Deactivate" action on a tenant row/card. Soft-deactivates the tenant
     (is_active = false — record is never hard-deleted).
     On 204: remove the row from the active list or flip the status badge to inactive. -->

**What it does:** Soft-deactivates a tenant (`is_active = false`). The row is never hard-deleted.  
**Permission:** `tenant:manage`

**Request**
```http
DELETE /api/v1/tenants/42
Authorization: Bearer <token>
```

No request body.

**Response `204 No Content`** — empty body.

**Errors**
| Status | Body | Cause |
|---|---|---|
| `400` | `{"error":"invalid tenant id"}` | ID is not a valid integer |
| `404` | `{"error":"tenant not found"}` | No tenant with that ID |
| `500` | `{"error":"failed to deactivate tenant"}` | DB error |

---

### PUT `/api/v1/tenants/:id/cors-origins`

<!-- Frontend use: CORS origins editor on the tenant settings page.
     Replaces the full list on each save — not a patch. -->

**What it does:** Replaces the full CORS origin list for a tenant.  
**Permission:** `tenant:manage`

**Request**
```http
PUT /api/v1/tenants/42/cors-origins
Authorization: Bearer <token>
Content-Type: application/json
```
```json
{ "cors_origins": ["https://app.acme.com", "https://admin.acme.com"] }
```

**Response `200` → [TenantResult](#shared-response-shape--tenantresult)**

---

## Cross-Tenant Management Endpoints

<!-- Frontend use: Super-admin panel — manage permissions, roles, and users inside any
     tenant without switching context. :tid is the target tenant's numeric ID. -->

All require `Authorization: Bearer <token>` and `tenant:manage` permission.

### Permissions

#### GET `/api/v1/tenants/:tid/permissions`
**What it does:** Lists all permissions for the target tenant.

```http
GET /api/v1/tenants/42/permissions
Authorization: Bearer <token>
```

**Response `200`**
```json
[{ "id": "1", "name": "users:read", "description": "Read users" }]
```

---

#### POST `/api/v1/tenants/:tid/permissions`
**What it does:** Creates a permission in the target tenant.

```http
POST /api/v1/tenants/42/permissions
Authorization: Bearer <token>
Content-Type: application/json
```
```json
{ "name": "reports:view", "description": "View reports" }
```

**Response `201`** — permission object | **`409`** → name already exists

---

#### DELETE `/api/v1/tenants/:tid/permissions/:pid`
**What it does:** Deletes a permission from the target tenant.

```http
DELETE /api/v1/tenants/42/permissions/7
Authorization: Bearer <token>
```

**Response `200`** `{"message":"permission deleted"}` | **`404`** → not found

---

### Roles

#### GET `/api/v1/tenants/:tid/roles`
**What it does:** Lists all roles (with permissions) for the target tenant.

```http
GET /api/v1/tenants/42/roles
Authorization: Bearer <token>
```

**Response `200`**
```json
[{ "id": "3", "name": "editor", "permissions": [{ "id": "1", "name": "users:read" }] }]
```

---

#### POST `/api/v1/tenants/:tid/roles`
**What it does:** Creates a role in the target tenant, optionally assigning permissions.

```http
POST /api/v1/tenants/42/roles
Authorization: Bearer <token>
Content-Type: application/json
```
```json
{ "name": "editor", "permission_ids": [1, 2] }
```

**Response `201`** — role object | **`409`** → name already exists

---

#### PUT `/api/v1/tenants/:tid/roles/:rid/permissions`
**What it does:** Replaces the full permission set on a role (complete replacement, not a patch).

```http
PUT /api/v1/tenants/42/roles/3/permissions
Authorization: Bearer <token>
Content-Type: application/json
```
```json
{ "permission_ids": [1, 3, 5] }
```

**Response `200`** `{"message":"permissions updated"}`

---

#### DELETE `/api/v1/tenants/:tid/roles/:rid`
**What it does:** Deletes a role from the target tenant.

```http
DELETE /api/v1/tenants/42/roles/3
Authorization: Bearer <token>
```

**Response `200`** `{"message":"role deleted"}` | **`404`** → not found

---

### Users

#### GET `/api/v1/tenants/:tid/users`
**What it does:** Returns a paginated user list for the target tenant.

```http
GET /api/v1/tenants/42/users?page=1&limit=20&search=john
Authorization: Bearer <token>
```

| Param | Default | Description |
|---|---|---|
| `page` | `1` | Page number |
| `limit` | `20` | Rows per page |
| `search` | — | Match on email or name |

**Response `200`** — array of user objects

---

#### POST `/api/v1/tenants/:tid/users`
**What it does:** Creates a new user inside the target tenant.

```http
POST /api/v1/tenants/42/users
Authorization: Bearer <token>
Content-Type: application/json
```
```json
{ "email": "user@acme.com", "password": "StrongPass1!", "first_name": "John", "last_name": "Doe" }
```

**Response `201`** — user object | **`409`** → email already registered

---

#### DELETE `/api/v1/tenants/:tid/users/:uid`
**What it does:** Soft-deletes a user (`is_deleted = true` — record is never hard-deleted).

```http
DELETE /api/v1/tenants/42/users/99
Authorization: Bearer <token>
```

**Response `200`** `{"message":"user deleted"}` | **`404`** → not found

---

## Stats Endpoints

#### GET `/api/v1/stats`

<!-- Frontend use: Per-tenant activity widget — shows counts for the caller's own tenant only. -->

**What it does:** Audit-log activity counts for the **caller's own tenant**.  
**Permission:** `admin:access`

```http
GET /api/v1/stats
Authorization: Bearer <token>
```

---

#### GET `/api/v1/stats/system`

<!-- Frontend use: Global activity overview panel — super-admins only. -->

**What it does:** Audit-log activity counts across **all tenants**.  
**Permission:** `tenant:manage`

```http
GET /api/v1/stats/system
Authorization: Bearer <token>
```

---

## Auth Endpoints — Updated in This Branch

No logic changes — only Swagger annotations were added. Behavior is unchanged.

### `X-Tenant-Slug` header

Read by middleware before the handler runs — **cannot be in the request body**.

```http
X-Tenant-Slug: acme
```

| Endpoint | When header is omitted |
|---|---|
| `POST /api/v1/auth/register` | Returns `400 Bad Request` |
| `POST /api/v1/auth/forgot-password` | Returns `400 Bad Request` |
| `POST /api/v1/auth/login` | Defaults to tenant `emc` |
| `POST /api/v1/auth/session` | Defaults to tenant `emc` |

### GET `/api/v1/auth/my-activity`

<!-- Frontend use: "My activity" section on the user's own profile page —
     login history, password changes, 2FA events. -->

Returns the authenticated user's own audit log entries. Supports `?page` and `?limit`.

### POST `/api/v1/auth/management-token`

<!-- Frontend use: Server-to-server / tooling — exchange an API key for a short-lived
     management JWT to call admin endpoints programmatically. -->

Exchanges an API key for a short-lived management JWT (15 minutes).

```http
POST /api/v1/auth/management-token
X-API-Key: emck_<your-api-key>
```

**Response `200`**
```json
{ "access_token": "<jwt>", "expires_in": 900, "token_type": "Bearer" }
```

Use as `Authorization: Bearer <jwt>` on subsequent admin calls.

---

## Swagger UI

```
http://localhost:<PORT>/swagger/index.html
```

---

## Frontend Integration Checklist

- [ ] **Tenant list** — response key is `data` (not `tenants`); pagination uses `per_page` (not `limit`)
- [ ] **List query params** — send `per_page` for page size; `status` accepts `active`, `inactive`, `suspended`
- [ ] **Stats cards** — `GET /api/v1/tenants/stats`; map `total_tenants`, `active_tenants`, `total_applications`, `total_users` + `delta.*_pct` badges
- [ ] **Slug field** — debounce → `GET /api/v1/tenants/check-slug?slug=<value>` → show tick/cross
- [ ] **Tenant detail page** — `GET /api/v1/tenants/:id`; all five new fields available
- [ ] **Create form** — `display_name`, `domain`, `region`, `description`, `plan` (dropdown: free / pro / enterprise)
- [ ] **Edit form** — same fields; send `""` to clear a nullable field
- [ ] **Activate button** — `PUT /api/v1/tenants/:id/activate` (no body); handle `409` = already active, refresh row
- [ ] **Deactivate button** — `DELETE /api/v1/tenants/:id` (no body); expect **`204`**, no response body
- [ ] **Nullable fields** — `display_name`, `domain`, `region`, `description` arrive as `null`; render as empty string
- [ ] **`id` is always a string** — do not parse it as a number
