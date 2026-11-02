# EMC Auth — Organizations Integration Guide

For engineers integrating an application (for example **PDFfillr**) with EMC Auth
so that each customer organisation has its own members and roles.

After reading this you can:

1. let a new user sign up and verify their email,
2. let that verified user create their organisation and become its admin,
3. let them invite their team with roles,
4. sign users in to an organisation and enforce their roles in your API.

> Background and design: [`ORGANIZATIONS.md`](ORGANIZATIONS.md). Live, clickable
> reference: Swagger UI at `{EMC_URL}/swagger/index.html`.

---

## Contents

1. [How the pieces fit](#1-how-the-pieces-fit)
2. [One-time setup](#2-one-time-setup)
3. [Conventions: base URL, headers, errors](#3-conventions)
4. [The end-to-end flow](#4-the-end-to-end-flow)
5. [API reference — end-user endpoints](#5-api-reference--end-user-endpoints)
6. [API reference — backend management endpoints](#6-api-reference--backend-management-endpoints)
7. [API reference — tokens](#7-api-reference--tokens)
8. [Enforcing access in your API](#8-enforcing-access-in-your-api)
9. [Error codes](#9-error-codes)
10. [Go-live checklist](#10-go-live-checklist)

---

## 1. How the pieces fit

| Party | What it does | Talks to EMC with |
|---|---|---|
| **Your frontend** (browser / mobile) | Sign-up form, sign-in, "create organisation", "invite team", `/join` page | Your backend, and EMC's end-user endpoints |
| **Your backend** | Holds the client secret. Creates organisations, adds members, sends invitations, enforces the rules | **Application credentials** (`Authorization: Basic`) |
| **EMC Auth** | Accounts, passwords, email verification, organisations, memberships, tokens | — |

Golden rule: **anything that creates organisations or grants roles goes through
your backend.** The client secret never reaches a browser or mobile app.

---

## 2. One-time setup

Done once by an EMC administrator in the console for your application.

| Setting | Value | Why |
|---|---|---|
| Application type | `web` (or `m2m`) | Gives you a `client_id` + `client_secret`. Public apps cannot call the management APIs. |
| Default role | `member` | Every new signup gets it. Application-wide, so keep it minimal. |
| Organisation roles | e.g. `org-admin`, `approver`, `viewer` | Granted per organisation. Define their permissions in **Roles & Permissions**. |
| Organization mode | **Optional** | A brand-new user has no organisation yet. **Required** would refuse their sign-in. |
| Redirect URIs | include `https://app.yourproduct.com/...` | The origin of your invitation page must be registered for EMC to email links to it. |
| Server | `ORGANIZATIONS_ENABLED=true` | Without it every organisation endpoint answers 404. |

Suggested roles for a PDFfillr-style product:

| Role | Scope | Permissions |
|---|---|---|
| `member` (default) | application-wide | `profile:read` |
| `org-admin` | per organisation | `org:manage`, `team:invite`, `team:manage`, `docs:approve`, `docs:read` |
| `approver` | per organisation | `docs:approve`, `docs:read` |
| `viewer` | per organisation | `docs:read` |

> Give the creator **`org-admin` inside their organisation**, never an
> application-wide admin role. An application-wide role applies in every
> organisation the user ever joins.

You will receive from the console (application **Overview → Token validation**):

| Value | Example |
|---|---|
| `EMC_URL` | `https://auth.example.com` |
| `client_id` | `emc_3f1a…` |
| `client_secret` | `sk_…` (shown once at creation or rotation) |
| `issuer` | `https://auth.example.com/tenants/acme-tenant` |
| `audience` | `api://acme-tenant/pdffillr` |
| `jwks_uri` | `https://auth.example.com/tenants/acme-tenant/.well-known/jwks.json` |

---

## 3. Conventions

### 3.1 Base URL

All paths below are relative to `EMC_URL`, e.g. `https://auth.example.com/api/v1/auth/apps/login`.

### 3.2 The three ways a request is authenticated

| Code | Header | Used by | Used for |
|---|---|---|---|
| **APP** | `Authorization: Basic base64(client_id:client_secret)` | Your **backend only** | Register, login, all organisation management, introspection |
| **USER** | `Authorization: Bearer <access_token>` | Frontend or backend, on behalf of a signed-in user | "My organisations", userinfo, accepting an invitation as an existing user |
| **NONE** | — | Anyone holding a one-time token | Invitation preview/accept for a new account, organisation selection, switching (the refresh token in the body is the credential) |

Building the Basic header:

```js
const basic = 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64')
```

```bash
curl -u "$CLIENT_ID:$CLIENT_SECRET" ...   # curl builds it for you
```

### 3.3 Request headers

| Header | Value | When |
|---|---|---|
| `Authorization` | see 3.2 | always, except NONE endpoints |
| `Content-Type` | `application/json` | every request with a body, except `/oauth/introspect` |
| `Content-Type` | `application/x-www-form-urlencoded` | `/oauth/introspect` only (OAuth standard) |
| `Accept` | `application/json` | recommended |

Credentials are **only** accepted in the `Authorization` header — never in the
JSON body or the query string.

### 3.4 Response format

**Success** — JSON object (or `204 No Content` with an empty body for deletes).

**Error** — always this shape:

```json
{
  "error": "organization_slug_taken",
  "message": "An organization with this slug already exists in this application."
}
```

| Field | Use it to |
|---|---|
| `error` | **Branch in code.** Stable machine code. See [§9](#9-error-codes). |
| `message` | **Show or log.** Human sentence; wording may change. |

Some responses add extra fields (e.g. `selection_token` on a 409 selection, or
`users_without_membership`).

A few older endpoints (register, and the credential check on every `/auth/apps/*`
call) still return a sentence in `error` with no `message`, for example a missing
header:

```json
{ "error": "Authorization: Basic base64(client_id:client_secret) header is required" }
```

So branch on the **HTTP status first**, then on `error` where this guide lists a code.

### 3.5 Identifiers

| Thing | Format | Example |
|---|---|---|
| Organisation id | `org_` + 20 letters/digits | `org_7Kq2xV9pLm3RtY8wB4nZ` |
| Organisation slug | lowercase letters, digits, `-`; 1–63 chars; not starting/ending with `-` | `northbeam` |
| Invitation id | `inv_` + 20 letters/digits | `inv_Zp41QmS8bT2xWc7yNa0K` |
| User id | numeric, as a string in paths and tokens | `5821` |

Wherever a path has `{org}`, you may pass **either the id or the slug**.

### 3.6 Rate limits

Too many requests answer **`429`** with a `Retry-After: <seconds>` header. Wait
that long and retry. Use exponential back-off in batch jobs.

### 3.7 Pagination

List endpoints take `limit` (default 25, max 100), `offset` (default 0) and
`search`, and return:

```json
{ "items": [ ... ], "total": 42, "limit": 25, "offset": 0 }
```

---

## 4. The end-to-end flow

```
 ┌─────────┐        ┌──────────────┐        ┌──────────┐
 │ Browser │        │ Your backend │        │ EMC Auth │
 └────┬────┘        └──────┬───────┘        └────┬─────┘
 1    │ sign-up form ─────▶│ POST /auth/apps/register (APP) ─▶│  user gets `member`,
      │                    │◀──────────────── 201 {user_id} ──│  verification email sent
 2    │ clicks email link ───────────────────────────────────▶│  email_verified = true
 3    │ sign-in ──────────▶│ POST /auth/apps/login (APP) ────▶│
      │◀── tokens (no org) │◀───────────────────── 200 tokens ─│
 4    │ "Create org" ─────▶│ check verified: GET /oauth/userinfo (USER)
      │                    │ POST /auth/apps/organizations (APP)
      │                    │ PUT  …/members/{uid} {roles:[org-admin]} (APP)
 5    │ POST /auth/apps/switch-organization {refresh_token, organization} ─▶│
      │◀──────────────────────── tokens with org_id + org-admin ──────────│
 6    │ "Invite team" ────▶│ check org_id + team:invite
      │                    │ POST …/organizations/{org}/invitations (APP) ─▶│ emails team
 7    │ teammate on /join ─────── preview + accept (NONE) ───────────────▶│ account + membership
 8    │ teammate sign-in {organization} ──────────────────────────────────▶│ token scoped to org
```

### Step 1 — Sign up

Your backend calls [`POST /api/v1/auth/apps/register`](#51-register). **Store the
returned `user_id`** against your own user record. EMC emails a verification link.

### Step 2 — Verify email

The user clicks the link in the email. Nothing for you to call. If they lost it:
[`POST /api/v1/auth/resend-verification`](#52-resend-verification-email).

### Step 3 — First sign-in

[`POST /api/v1/auth/apps/login`](#53-sign-in) without `organization`. The token has
no `org_id`, so your frontend shows **"Create your organisation"**.

### Step 4 — Create the organisation (your backend)

Your own endpoint, e.g. `POST /api/workspaces`, does:

1. Verify the user's JWT ([§8](#8-enforcing-access-in-your-api)).
2. Require a verified email: [`GET /oauth/userinfo`](#73-userinfo) → `email_verified: true`.
   The access token itself does not carry this flag.
3. Apply your business rule (e.g. one owned organisation per user):
   [`GET /api/v1/auth/apps/users/{uid}/organizations`](#615-list-a-users-organisations).
4. [`POST /api/v1/auth/apps/organizations`](#61-create-an-organisation).
5. [`PUT /api/v1/auth/apps/organizations/{org}/members/{uid}`](#67-add-a-member) with `{"roles":["org-admin"]}`.

```ts
export async function createWorkspace(req, res) {
  const claims = await verifyEmcJwt(req.headers.authorization)          // §8

  const info = await fetch(`${EMC_URL}/oauth/userinfo`, {
    headers: { Authorization: req.headers.authorization },
  }).then((r) => r.json())
  if (!info.email_verified) return res.status(403).json({ error: 'email_not_verified' })

  const mine = await emc('GET', `/users/${claims.user_id}/organizations`)
  if (mine.some((m) => m.roles.includes('org-admin')))
    return res.status(409).json({ error: 'already_has_workspace' })

  const org = await ensureOrganization(toSlug(req.body.name), req.body.name)
  await emc('PUT', `/organizations/${org.id}/members/${claims.user_id}`, { roles: ['org-admin'] })
  return res.status(201).json({ organization: org })
}
```

### Step 5 — Move the user into the organisation

Frontend calls [`POST /api/v1/auth/apps/switch-organization`](#55-switch-organisation)
with its refresh token and the new organisation id. The new token carries
`org_id`, `org_roles: ["org-admin"]` and the admin's `org_permissions`. No password.

### Step 6 — Invite the team (your backend)

Your own endpoint, e.g. `POST /api/orgs/:orgId/invitations`, does:

1. Verify the JWT; require `org_id === :orgId` and `team:invite` in `org_permissions`.
2. Refuse roles above the inviter's own (an `approver` must not invite an `org-admin`).
3. For each email: [`POST /api/v1/auth/apps/organizations/{org}/invitations`](#612-create-an-invitation).

```ts
const GRANTABLE = { 'org-admin': ['org-admin', 'approver', 'viewer'] }

export async function inviteTeam(req, res) {
  const c = await verifyEmcJwt(req.headers.authorization)
  if (c.org_id !== req.params.orgId) return res.status(403).end()
  if (!c.org_permissions?.includes('team:invite')) return res.status(403).end()

  const allowed = new Set(c.org_roles.flatMap((r) => GRANTABLE[r] ?? []))
  if (!req.body.roles.every((r) => allowed.has(r)))
    return res.status(403).json({ error: 'role_not_grantable' })

  const invited = []
  for (const email of req.body.emails) {
    const inv = await withRetry(() =>
      emc('POST', `/organizations/${c.org_id}/invitations`, {
        email, roles: req.body.roles,
        invitation_url: 'https://app.yourproduct.com/join',
        send_email: true,
      }),
    )
    invited.push({ id: inv.id, email: inv.email })
  }
  return res.status(201).json({ invited })
}
```

### Step 7 — The teammate accepts (your `/join` page)

The email link opens `https://app.yourproduct.com/join?invitation=<token>&organization=<org_id>`.

1. [`GET …/invitations/preview?token=`](#56-preview-an-invitation) — show "Join Northbeam as approver".
2. If `account_exists` is `false`: collect a password →
   [`POST …/invitations/accept`](#57-accept-an-invitation) (new account, created **already verified**).
3. If `account_exists` is `true`: sign them in first, then accept with their own
   `Authorization: Bearer` token.

### Step 8 — Teammate signs in to the organisation

[`POST /api/v1/auth/apps/login`](#53-sign-in) with `"organization": "<id or slug>"`.
If they belong to several organisations and do not name one, show a picker from
[`GET /api/v1/auth/apps/me/organizations`](#58-my-organisations).

---

## 5. API reference — end-user endpoints

### 5.1 Register

Creates an account in your application. The user gets the default role and a
verification email. **Does not sign them in.**

```
POST /api/v1/auth/apps/register
```

| Header | Value |
|---|---|
| `Authorization` | `Basic base64(client_id:client_secret)` — **APP** |
| `Content-Type` | `application/json` |

Request:

```json
{
  "email": "ravi@northbeam.com",
  "password": "S3cure-passphrase",
  "first_name": "Ravi",
  "last_name": "Menon"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `email` | string | yes | |
| `password` | string | yes | at least 8 characters |
| `first_name`, `last_name` | string | no | |

Response `201 Created`:

```json
{
  "user_id": 5821,
  "tenant_id": 7,
  "email": "ravi@northbeam.com",
  "role": "member",
  "application_id": 31
}
```

| Status | `error` | Meaning |
|---|---|---|
| 400 | — | missing/invalid fields, or missing `Authorization` header |
| 401 | — | invalid client credentials |
| 409 | `email_already_registered` | account exists. The id is **not** returned; invite them instead ([§6.12](#612-create-an-invitation)). |
| 428 | `captcha_required` | only if a CAPTCHA policy is enabled for the application |

### 5.2 Resend verification email

```
POST /api/v1/auth/resend-verification
```

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |

Request: `{ "email": "ravi@northbeam.com" }` — Response `200`, the same whether or
not the account exists:

```json
{ "message": "if the account exists and is unverified, a verification email has been sent" }
```

### 5.3 Sign in

```
POST /api/v1/auth/apps/login
```

| Header | Value |
|---|---|
| `Authorization` | `Basic …` — **APP** (call from your backend) |
| `Content-Type` | `application/json` |

Request:

```json
{
  "email": "ravi@northbeam.com",
  "password": "S3cure-passphrase",
  "organization": "northbeam",
  "remember_me": false
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `email`, `password` | string | yes | |
| `organization` | string | no | organisation id or slug. Omit for a session without an organisation (Optional mode). |
| `remember_me` | boolean | no | longer idle timeout, if the session policy allows |

Response `200 OK` — tokens:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "8c1f0b6e5a...",
  "token_type": "Bearer",
  "expires_in": 900,
  "expires_at": 1793613344
}
```

Other successful outcomes:

| Status | Body | What to do |
|---|---|---|
| `200` | `{ "requires_otp": true, "otp_session_token": "...", "methods": ["totp"], "expires_in": 300, "email_code_sent": false }` | MFA: collect the code, `POST /api/v1/auth/login/otp` `{ "otp_session_token", "code" }` |
| `409` | see below | choose an organisation |

`409 organization_selection_required` — mode is Required and the user belongs to several organisations:

```json
{
  "error": "organization_selection_required",
  "message": "Choose which organization to sign in to.",
  "selection_token": "3a9c...e1",
  "expires_in": 300,
  "organizations": [
    { "id": "org_7Kq2xV9pLm3RtY8wB4nZ", "slug": "northbeam", "display_name": "Northbeam" },
    { "id": "org_GlobexGlobexGlob02", "slug": "globex", "display_name": "Globex" }
  ]
}
```

| Status | `error` | Meaning |
|---|---|---|
| 401 | `invalid_credentials` | wrong email or password (deliberately the same for both) |
| 403 | `organization_access_denied` | not a member, suspended, or no such organisation |
| 503 | `organization_unavailable` | membership could not be checked; retry |
| 429 | — | rate limited; honour `Retry-After` |

### 5.4 Finish sign-in by choosing an organisation

```
POST /api/v1/auth/apps/login/organization
```

| Header | Value |
|---|---|
| `Content-Type` | `application/json` — **NONE** (the selection token is the credential) |

Request:

```json
{ "selection_token": "3a9c...e1", "organization": "org_7Kq2xV9pLm3RtY8wB4nZ" }
```

Response `200` — tokens (same as 5.3).

| Status | `error` | Meaning |
|---|---|---|
| 400 | `organization_selection_invalid` | expired (5 minutes) or already used — sign in again |
| 403 | `organization_access_denied` | that organisation was not one of the choices |

### 5.5 Switch organisation

Moves a signed-in user to another organisation, or out of organisations, without
a password. Creates a **new** session; the current one is left alone.

```
POST /api/v1/auth/apps/switch-organization
```

| Header | Value |
|---|---|
| `Content-Type` | `application/json` — **NONE** (refresh token in body is the credential) |

Request — into an organisation:

```json
{ "refresh_token": "8c1f0b6e5a...", "organization": "org_7Kq2xV9pLm3RtY8wB4nZ" }
```

Request — out of organisations (Optional mode only):

```json
{ "refresh_token": "8c1f0b6e5a...", "personal": true }
```

Response `200` — tokens (same as 5.3). The refresh token must be in the body;
cookies are not accepted here.

| Status | `error` | Meaning |
|---|---|---|
| 400 | `invalid_request` | send exactly one of `organization` or `personal` |
| 400 | `organizations_not_enabled` | the application's mode is Off |
| 401 | `session_terminated` | refresh token invalid or expired — sign in again |
| 403 | `organization_access_denied` | not a member; or `personal` while mode is Required |

### 5.6 Preview an invitation

```
GET /api/v1/auth/apps/organizations/invitations/preview?token=<invitation token>
```

**NONE.** Response `200`:

```json
{
  "organization": { "id": "org_7Kq2xV9pLm3RtY8wB4nZ", "slug": "northbeam", "display_name": "Northbeam" },
  "email": "asha@northbeam.com",
  "roles": ["approver"],
  "expires_at": "2026-11-09T10:00:00Z",
  "account_exists": false
}
```

| Status | `error` | Meaning |
|---|---|---|
| 400 | `invalid_invitation` | unknown, expired, used, revoked, or the organisation was deactivated |

### 5.7 Accept an invitation

```
POST /api/v1/auth/apps/organizations/invitations/accept
```

**New account** — `account_exists: false`. **NONE**:

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |

```json
{
  "token": "<invitation token>",
  "password": "An0ther-passphrase",
  "first_name": "Asha",
  "last_name": "K"
}
```

**Existing account** — `account_exists: true`. Sign the user in first, then:

| Header | Value |
|---|---|
| `Authorization` | `Bearer <the invitee's own access token>` — **USER** |
| `Content-Type` | `application/json` |

```json
{ "token": "<invitation token>" }
```

Response `200`:

```json
{
  "user_id": "5904",
  "organization": { "id": "org_7Kq2xV9pLm3RtY8wB4nZ", "slug": "northbeam", "display_name": "Northbeam" },
  "roles": ["approver"],
  "account_created": true
}
```

A new account created here is **already email-verified**. Sign in afterwards with
`organization` set.

| Status | `error` | Meaning |
|---|---|---|
| 400 | `invalid_invitation` | invalid token, **or** the signed-in account is not the invited email |
| 400 | `invalid_request` | password shorter than 8 characters |
| 401 | `session_terminated` | the bearer token is invalid or revoked |
| 409 | `account_exists` | an account exists for this email — sign in and accept with the bearer token |

### 5.8 My organisations

```
GET /api/v1/auth/apps/me/organizations
```

| Header | Value |
|---|---|
| `Authorization` | `Bearer <access_token>` — **USER** |

Response `200`:

```json
{
  "current": "org_7Kq2xV9pLm3RtY8wB4nZ",
  "organizations": [
    {
      "organization": { "id": "org_7Kq2xV9pLm3RtY8wB4nZ", "slug": "northbeam", "display_name": "Northbeam" },
      "status": "active",
      "roles": ["org-admin"],
      "joined_at": "2026-11-02T10:05:00Z"
    }
  ]
}
```

`current` is the organisation the presented token is signed in to (absent if none).
Only organisations the user can sign in to are listed.

### 5.9 Refresh tokens

```
POST /api/v1/auth/refresh
```

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |

Request: `{ "refresh_token": "8c1f0b6e5a..." }` — Response `200`: tokens (same as 5.3).
The organisation is kept, and the membership is **re-checked on every refresh**.

| Status | `error` / `code` | Meaning |
|---|---|---|
| 401 | `session_terminated` / `refresh_token_invalid` | sign in again (also returned after removal from the organisation) |
| 409 | `concurrent_refresh` | another tab already refreshed; use its result |

### 5.10 Sign out

```
POST /api/v1/auth/logout      { "refresh_token": "8c1f0b6e5a..." }
```

---

## 6. API reference — backend management endpoints

**Every endpoint in this section:**

| Header | Value |
|---|---|
| `Authorization` | `Basic base64(client_id:client_secret)` — **APP**, backend only |
| `Content-Type` | `application/json` (when there is a body) |

Base path: **`/api/v1/auth/apps`**. All endpoints only ever see **your**
application's organisations and users; anything else answers 404.

Common errors for this section:

| Status | `error` | Meaning |
|---|---|---|
| 400 | `invalid_request` | validation failed; `message` names the field |
| 400 | (sentence) | `Authorization` header missing or not Basic — see §3.4 |
| 401 | `invalid_client` | wrong client credentials |
| 404 | `not_found` | organisations are switched off on the EMC server |
| 404 | `organization_not_found` | no such organisation in your application |
| 429 | — | rate limited |

### Organisation object

```json
{
  "id": "org_7Kq2xV9pLm3RtY8wB4nZ",
  "slug": "northbeam",
  "display_name": "Northbeam",
  "metadata": { "customer_id": "c_1042" },
  "is_active": true,
  "member_count": 3,
  "created_at": "2026-11-02T10:00:00Z",
  "updated_at": "2026-11-02T10:00:00Z"
}
```

### Member object

```json
{
  "user_id": "5821",
  "email": "ravi@northbeam.com",
  "first_name": "Ravi",
  "last_name": "Menon",
  "status": "active",
  "roles": ["org-admin"],
  "joined_at": "2026-11-02T10:05:00Z"
}
```

`status` is `active` or `suspended`. `roles` are organisation roles only.

### 6.1 Create an organisation

```
POST /api/v1/auth/apps/organizations
```

```json
{ "slug": "northbeam", "display_name": "Northbeam", "metadata": { "customer_id": "c_1042" } }
```

| Field | Type | Required | Rules |
|---|---|---|---|
| `slug` | string | yes | lowercase letters, digits, `-`; 1–63; **permanent** (appears in tokens as `org_name`) |
| `display_name` | string | yes | 1–200 characters; can be changed later |
| `metadata` | object | no | your own data; JSON object up to 4 KB |

Response `201`: organisation object.

| Status | `error` | Meaning |
|---|---|---|
| 409 | `organization_slug_taken` | fetch it with 6.3 instead (idempotent create) |
| 409 | `limit_reached` | 10,000 organisations per application |

### 6.2 List organisations

```
GET /api/v1/auth/apps/organizations?search=north&limit=25&offset=0
```

Response `200`: `{ "items": [organisation, …], "total": 1, "limit": 25, "offset": 0 }`

### 6.3 Get an organisation

```
GET /api/v1/auth/apps/organizations/{org}
```

Response `200`: organisation object.

### 6.4 Update an organisation

```
PATCH /api/v1/auth/apps/organizations/{org}
```

```json
{ "display_name": "Northbeam Ltd", "metadata": { "plan": "team" }, "is_active": false }
```

Every field is optional. `is_active: false` suspends the organisation: nobody can
sign in to it and everyone in it is signed out. Response `200`: organisation object.

### 6.5 Delete an organisation

```
DELETE /api/v1/auth/apps/organizations/{org}
```

Response `204`. Soft delete: sign-in stops, sessions are revoked, pending
invitations are closed, history is kept.

### 6.6 List members

```
GET /api/v1/auth/apps/organizations/{org}/members?search=asha&limit=25&offset=0
```

Response `200`: `{ "items": [member, …], "total": 3, "limit": 25, "offset": 0 }`

### 6.7 Add a member

Adds an existing user of your application. **Idempotent.**

```
PUT /api/v1/auth/apps/organizations/{org}/members/{uid}
```

```json
{ "roles": ["org-admin"] }
```

Body optional. Response: member object — **`201`** if added, **`200`** if they
were already a member (any extra roles are added).

| Status | `error` | Meaning |
|---|---|---|
| 404 | `user_not_found` | no such user in your application |
| 400 | `invalid_request` | a role does not exist in your application or is a system role |
| 409 | `limit_reached` | 5,000 members per organisation |

### 6.8 Get a member

```
GET /api/v1/auth/apps/organizations/{org}/members/{uid}
```

Response `200`: member object. `404 member_not_found` if not a member.

### 6.9 Suspend or reactivate a member

```
PATCH /api/v1/auth/apps/organizations/{org}/members/{uid}
```

```json
{ "status": "suspended" }
```

`suspended` keeps the membership and roles but signs them out of this
organisation and blocks sign-in to it. `active` restores it. Response `200`: member object.

### 6.10 Remove a member

```
DELETE /api/v1/auth/apps/organizations/{org}/members/{uid}
```

Response `204`. Membership and its roles are deleted and the user is signed out of
this organisation. Their account and other organisations are untouched.

### 6.11 Set a member's organisation roles

```
POST /api/v1/auth/apps/organizations/{org}/members/{uid}/roles
```

```json
{ "roles": ["approver", "viewer"], "mode": "replace" }
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `roles` | string[] | yes | role names of your application |
| `mode` | string | no | `add` (default) keeps existing roles; `replace` sets exactly this list |

Response `200`:

```json
{ "user_id": "5904", "roles": ["approver", "viewer"], "assigned": ["viewer"], "removed": ["org-admin"] }
```

The member's access tokens are invalidated; the new roles apply at their next refresh.
Limit: 20 roles per member per organisation.

Remove one role:

```
DELETE /api/v1/auth/apps/organizations/{org}/members/{uid}/roles/{role}
```

Response `200`: same shape as above.

### 6.12 Create an invitation

```
POST /api/v1/auth/apps/organizations/{org}/invitations
```

```json
{
  "email": "asha@northbeam.com",
  "roles": ["approver"],
  "invitation_url": "https://app.yourproduct.com/join",
  "send_email": true,
  "expires_in_hours": 168,
  "inviter_name": "Ravi Menon"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `email` | string | yes | |
| `roles` | string[] | no | organisation roles granted on acceptance |
| `invitation_url` | string | if `send_email` | your accept page; must be on a registered redirect URI origin. EMC appends `?invitation=<token>&organization=<org_id>` |
| `send_email` | boolean | no | `true`: EMC sends your application's branded invitation email. `false`: you send it using `token` |
| `expires_in_hours` | integer | no | 1–720, default 72 |
| `inviter_name` | string | no | shown in the email |

Response `201`:

```json
{
  "id": "inv_Zp41QmS8bT2xWc7yNa0K",
  "organization_id": "org_7Kq2xV9pLm3RtY8wB4nZ",
  "email": "asha@northbeam.com",
  "roles": ["approver"],
  "status": "pending",
  "expires_at": "2026-11-09T10:00:00Z",
  "created_at": "2026-11-02T10:00:00Z",
  "token": "f3b9c2...7a",
  "invitation_url": "https://app.yourproduct.com/join?invitation=f3b9c2...7a&organization=org_7Kq2xV9pLm3RtY8wB4nZ",
  "email_sent": true
}
```

> `token` is returned **only here, only once**. EMC stores its hash. Inviting the
> same email again replaces the pending invitation.

### 6.13 List invitations

```
GET /api/v1/auth/apps/organizations/{org}/invitations?include_closed=true
```

Response `200`: array of invitation objects (no `token`). `status` is
`pending`, `accepted`, `revoked` or `expired`. Without `include_closed`, only pending ones.

### 6.14 Revoke an invitation

```
DELETE /api/v1/auth/apps/organizations/{org}/invitations/{inv}
```

Response `204`. `404 invitation_not_found` if it is not pending.

### 6.15 List a user's organisations

```
GET /api/v1/auth/apps/users/{uid}/organizations
```

Response `200`: array of memberships, including suspended ones:

```json
[
  {
    "organization": { "id": "org_7Kq2xV9pLm3RtY8wB4nZ", "slug": "northbeam", "display_name": "Northbeam" },
    "status": "active",
    "roles": ["org-admin"],
    "joined_at": "2026-11-02T10:05:00Z"
  }
]
```

---

## 7. API reference — tokens

### 7.1 Access token claims

A token signed in to an organisation (JWT payload):

```json
{
  "iss": "https://auth.example.com/tenants/acme-tenant",
  "aud": ["api://acme-tenant/pdffillr"],
  "sub": "5821",
  "exp": 1793614244,
  "iat": 1793613344,
  "sid": "88412",
  "gty": "password",

  "user_id": "5821",
  "tenant_id": "7",
  "app_id": "31",
  "email": "ravi@northbeam.com",
  "role": "member",
  "roles": ["member"],
  "permissions": ["profile:read"],

  "org_id": "org_7Kq2xV9pLm3RtY8wB4nZ",
  "org_name": "northbeam",
  "org_roles": ["org-admin"],
  "org_permissions": ["docs:approve", "docs:read", "org:manage", "team:invite", "team:manage"]
}
```

| Claim | Meaning |
|---|---|
| `roles`, `permissions` | **application-wide** grants (same in every organisation) |
| `org_id` | the organisation this session is in. Absent = no organisation |
| `org_name` | its slug, for display/logs only — never authorise on it |
| `org_roles`, `org_permissions` | grants **inside `org_id` only**. Absent if the member has no organisation role |
| `exp` | access tokens live 15 minutes by default |

### 7.2 Verifying tokens in your backend

Use any standard JWT library:

| Check | Value |
|---|---|
| Algorithm | `RS256` |
| Keys | `{EMC_URL}/tenants/{tenant-slug}/.well-known/jwks.json` (cache; keys rotate) |
| `iss` | your tenant issuer (from the console) |
| `aud` | your application's audience (from the console) |
| `exp` | not expired |

Discovery document: `{EMC_URL}/tenants/{tenant-slug}/.well-known/openid-configuration`.

### 7.3 Userinfo

```
GET /oauth/userinfo
```

| Header | Value |
|---|---|
| `Authorization` | `Bearer <access_token>` — **USER** |

Response `200`:

```json
{
  "sub": "5821",
  "email": "ravi@northbeam.com",
  "email_verified": true,
  "name": "Ravi Menon",
  "given_name": "Ravi",
  "family_name": "Menon",
  "updated_at": 1793610000,
  "org_id": "org_7Kq2xV9pLm3RtY8wB4nZ",
  "org_name": "northbeam"
}
```

Use it to check **`email_verified`** before letting a user create an organisation.

### 7.4 Introspection — the live check

A JWT stays valid until it expires. Before an action that must reflect a removal
**immediately** (approve, reveal, send), ask EMC.

```
POST /oauth/introspect
```

| Header | Value |
|---|---|
| `Authorization` | `Basic base64(client_id:client_secret)` — **APP** (confidential clients only) |
| `Content-Type` | `application/x-www-form-urlencoded` |

Body:

```
token=eyJhbGciOiJSUzI1NiIs...&token_type_hint=access_token
```

Response `200` — active:

```json
{
  "active": true,
  "client_id": "emc_3f1a...",
  "username": "ravi@northbeam.com",
  "token_type": "access_token",
  "sub": "5821",
  "exp": 1793614244,
  "iat": 1793613344,
  "sid": "88412",
  "app_id": "31",
  "org_id": "org_7Kq2xV9pLm3RtY8wB4nZ",
  "org_roles": ["org-admin"],
  "org_permissions": ["docs:approve", "docs:read", "org:manage", "team:invite", "team:manage"]
}
```

Response `200` — anything else (expired, revoked, user disabled, member removed or
suspended, another application's token):

```json
{ "active": false }
```

`401 invalid_client` for bad client credentials.

---

## 8. Enforcing access in your API

Every route that touches an organisation's data must check **both**:

1. the token's `org_id` equals the organisation in the request, and
2. `org_permissions` contains the permission the action needs.

```ts
import { createRemoteJWKSet, jwtVerify } from 'jose'

const JWKS = createRemoteJWKSet(new URL(`${EMC_URL}/tenants/${TENANT_SLUG}/.well-known/jwks.json`))

export async function verifyEmcJwt(authorization?: string) {
  const token = authorization?.replace(/^Bearer\s+/i, '')
  if (!token) throw Object.assign(new Error('unauthorized'), { status: 401 })
  const { payload } = await jwtVerify(token, JWKS, { issuer: ISSUER, audience: AUDIENCE })
  return payload as Record<string, any>
}

export const requireOrgPermission = (permission: string) => async (req, res, next) => {
  try {
    const c = await verifyEmcJwt(req.headers.authorization)
    if (c.org_id !== req.params.orgId) return res.status(403).json({ error: 'wrong_organization' })
    if (!c.org_permissions?.includes(permission)) return res.status(403).json({ error: 'forbidden' })
    req.auth = c
    next()
  } catch {
    res.status(401).json({ error: 'unauthorized' })
  }
}

// usage
app.post('/api/orgs/:orgId/documents/:id/approve', requireOrgPermission('docs:approve'), approve)
```

Shared helper for backend calls to EMC:

```ts
const BASIC = 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64')

export async function emc(method: string, path: string, body?: unknown) {
  const res = await fetch(`${EMC_URL}/api/v1/auth/apps${path}`, {
    method,
    headers: { Authorization: BASIC, 'Content-Type': 'application/json', Accept: 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const data = res.status === 204 ? null : await res.json()
  if (!res.ok) throw Object.assign(new Error(data?.message ?? res.statusText), {
    status: res.status, code: data?.error, data, retryAfter: res.headers.get('retry-after'),
  })
  return data
}

export async function ensureOrganization(slug: string, name: string) {
  try {
    return await emc('POST', '/organizations', { slug, display_name: name })
  } catch (e: any) {
    if (e.code === 'organization_slug_taken') return emc('GET', `/organizations/${slug}`)
    throw e
  }
}

export async function withRetry<T>(fn: () => Promise<T>, attempts = 5): Promise<T> {
  for (let i = 1; ; i++) {
    try {
      return await fn()
    } catch (e: any) {
      if (e.status !== 429 || i === attempts) throw e
      const wait = Number(e.retryAfter) > 0 ? Number(e.retryAfter) * 1000 : 1000 * 2 ** i
      await new Promise((r) => setTimeout(r, wait))
    }
  }
}
```

Rules your backend owns:

| Rule | How |
|---|---|
| Email verified before creating an organisation | `GET /oauth/userinfo` → `email_verified` |
| Inviters cannot grant roles above their own | map of grantable roles per organisation role |
| Never remove or demote the **last** `org-admin` | check the member list first |
| Sensitive actions use live state | `POST /oauth/introspect` |
| Client secret never leaves the backend | all `/api/v1/auth/apps/*` management calls are server-side |

---

## 9. Error codes

| `error` | Status | Where | Meaning / what to do |
|---|---|---|---|
| `invalid_request` | 400 | management, switch, accept | a field failed validation; `message` says which |
| `invalid_credentials` | 401 | login | wrong email or password |
| `invalid_client` | 401 | management, introspect | wrong client credentials |
| `session_terminated` | 401 | refresh, switch, accept | sign the user in again |
| `organization_access_denied` | 403 | login, select, switch | not a member, suspended, or no such organisation |
| `organization_selection_required` | 409 | login | show `organizations`, then call 5.4 |
| `organization_selection_invalid` | 400 | select | expired or used selection token |
| `organization_unavailable` | 503 | login, select, switch | temporary; retry |
| `organizations_not_enabled` | 400 | switch | the application's mode is Off |
| `not_found` | 404 | management | organisations are switched off on the server |
| `organization_not_found` | 404 | management | no such organisation in your application |
| `user_not_found` | 404 | management | no such user in your application |
| `member_not_found` | 404 | management | user is not a member |
| `invitation_not_found` | 404 | revoke | not pending |
| `invalid_invitation` | 400 | preview, accept | invalid/expired, or wrong account |
| `organization_slug_taken` | 409 | create | fetch the existing one |
| `account_exists` | 409 | accept | sign in and accept with the bearer token |
| `email_already_registered` | 409 | register | invite the person instead |
| `limit_reached` | 409 | create, add, roles | a limit was hit |
| `captcha_required` | 428 | register, login | only when a CAPTCHA policy is enabled |
| — | 429 | anywhere | wait `Retry-After` seconds |

Limits: 10,000 organisations per application · 5,000 members per organisation ·
20 organisation roles per member · 4 KB metadata · invitations 1–720 hours.

---

## 10. Go-live checklist

- [ ] Application is `web` (confidential); client secret stored only in the backend's secret store.
- [ ] Roles defined; default role is a minimal application-wide role.
- [ ] Organization mode is **Optional** (users without an organisation must still be able to sign in).
- [ ] Invitation page origin is in the application's redirect URIs.
- [ ] Your user record stores the EMC `user_id`; your customer record stores the organisation `id`.
- [ ] Organisation creation requires `email_verified: true`.
- [ ] Every organisation route checks `org_id` **then** `org_permissions`.
- [ ] Inviters cannot grant roles above their own; the last admin cannot be removed.
- [ ] Frontend handles `409 organization_selection_required` and `403 organization_access_denied`.
- [ ] Batch jobs are idempotent and retry `429` with back-off.
- [ ] Sensitive actions call `/oauth/introspect`.
- [ ] Tested end to end in staging: sign up → verify → create org → switch → invite → accept → teammate sign-in → remove → access lost.
