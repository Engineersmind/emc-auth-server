# Organizations

Organizations let one person hold **different roles in different customer
organisations** of the same application — Admin at Acme, Viewer at Globex —
which application-wide roles cannot express.

The feature is **opt-in twice** and changes nothing until both are on:

| Switch | Where | Default |
|---|---|---|
| `ORGANIZATIONS_ENABLED` | deployment environment | `false` |
| `organizations_mode` | per application (`off`, `optional`, `required`) | `off` |

While either is off, every login, refresh and token for the application is
exactly what it was before this feature existed.

> **Integrating an application?** Start with the step-by-step guide, which has
> every header, request and response:
> [`ORGANIZATIONS_INTEGRATION.md`](ORGANIZATIONS_INTEGRATION.md).

---

## 1. Modes

| Mode | Behaviour |
|---|---|
| `off` | Today's behaviour. An `organization` parameter on sign-in is ignored (counted in `emc_auth_organization_param_ignored_total`). |
| `optional` | Sign-in without an organisation gives today's token. Sign-in with one adds the `org_*` claims. Users can switch between organisations, or out of them, without a password. |
| `required` | Every end-user session is inside exactly one organisation. One membership is selected automatically; several ask the user to choose; none refuses sign-in after the password and MFA checks. |

Organisations apply only to the application's **own** users (`users.application_id`).
Tenant-level users signing in through the application are never affected.

Change the mode from the console, or:

```http
PUT /api/v1/tenants/{tid}/applications/{appID}/organization-settings
{ "organizations_mode": "required", "force": false }
```

* Moving to `required` answers **409 `organizations_mode_unmet`** while any active
  user belongs to no organisation, unless `force: true`. Organisation-less
  sessions are revoked.
* Moving to `off` revokes every organisation session; users sign in again and
  receive a plain token.

---

## 2. Token contract

| Claim | No organisation | Inside an organisation |
|---|---|---|
| `user_id`, `tenant_id`, `app_id`, `email` | unchanged | unchanged |
| `role`, `roles`, `permissions` | unchanged (application-wide) | unchanged (application-wide) |
| `org_id` | absent | public id, e.g. `org_7Kq2xV9pLm3RtY8wB4nZ` |
| `org_name` | absent | the organisation's immutable slug |
| `org_roles` | absent | roles held in this organisation (absent if none) |
| `org_permissions` | absent | permissions from `org_roles` |

**Rule for resource servers:** to act on an organisation's data, check that
`org_id` equals the organisation in the request, then check `org_permissions`.
Use `permissions` only for application-wide actions.

One organisation per token, so token size never grows with memberships.

---

## 3. Signing in

### Password

```http
POST /api/v1/auth/apps/login
Authorization: Basic base64(client_id:client_secret)
{ "email": "sarah@acme.com", "password": "…", "organization": "acme" }
```

`organization` accepts the public id or the slug. The outcomes, identical for
every sign-in method (password, MFA completion, magic link, passkey, social):

| Status | `error` | Meaning |
|---|---|---|
| 200 | — | Tokens. |
| 409 | `organization_selection_required` | `required` mode, several memberships. Body carries `selection_token` (single use, 5 min) and `organizations`. |
| 403 | `organization_access_denied` | Unknown, deleted, suspended, other application's, or not a member — one answer for all. |
| 503 | `organization_unavailable` | Membership could not be read; no token was issued. |

Finish a selection:

```http
POST /api/v1/auth/apps/login/organization
{ "selection_token": "…", "organization": "org_…" }
```

### Hosted login (OAuth / OIDC)

Add `organization=<id or slug>` to `/oauth/authorize`. In `required` mode with
several memberships EMC shows its own picker. The chosen organisation travels
on the authorization code and is re-checked at `/oauth/token`. A refused
organisation redirects with `error=access_denied`.

### Switching

```http
POST /api/v1/auth/apps/switch-organization
{ "refresh_token": "…", "organization": "globex" }      // or { "refresh_token": "…", "personal": true }
```

Creates a **new** session with the original `auth_time` and absolute deadline —
switching can never extend a session. The previous session is left alone, so
two tabs can be in two organisations. The refresh token is accepted in the body
only.

`GET /api/v1/auth/apps/me/organizations` lists where the user can switch to.

---

## 4. Managing organisations

Two equivalent surfaces:

* **Application backend** — `Authorization: Basic` client credentials, under
  `/api/v1/auth/apps/organizations`. Server-side only: the secret grants
  authority over every organisation of the application.
* **Admin console** — bearer token, under
  `/api/v1/tenants/{tid}/applications/{appID}/organizations`
  (`users:read` / `users:write`).

| Operation | Method and path (relative) |
|---|---|
| Create / list | `POST` / `GET ""` |
| Get / update / delete | `GET` / `PATCH` / `DELETE /{org}` |
| Members | `GET /{org}/members` |
| Add member (idempotent) | `PUT /{org}/members/{uid}` `{ "roles": [...] }` |
| Suspend / reactivate | `PATCH /{org}/members/{uid}` `{ "status": "suspended" }` |
| Remove member | `DELETE /{org}/members/{uid}` |
| Organisation roles | `POST /{org}/members/{uid}/roles` `{ "roles": [...], "mode": "add" \| "replace" }` |
| Remove one role | `DELETE /{org}/members/{uid}/roles/{role}` |
| Invitations | `POST` / `GET /{org}/invitations`, `DELETE /{org}/invitations/{inv}` |
| A user's memberships | `GET /users/{uid}/organizations` (sibling of the organisations path) |

Organisation roles are the application's own roles; system roles and other
applications' roles are refused. Organisations can be created and populated
while the application is still `off`, so memberships can be backfilled before
sign-in depends on them.

---

## 5. Invitations

```http
POST …/organizations/acme/invitations
{ "email": "new@acme.com", "roles": ["org-admin"],
  "invitation_url": "https://app.example.com/join", "send_email": true }
```

* The raw `token` is returned **once**; only its hash is stored.
* `invitation_url` must be on one of the application's registered redirect URI
  origins; EMC appends `invitation=<token>&organization=<org_id>`.
* `send_email` uses the application's branded `user_invitation` template.
  Without it, the application sends its own email using the token.
* Re-inviting the same address replaces the pending invitation. Default
  lifetime 72 hours (`expires_in_hours`, 1–720).

The invitee's client:

```http
GET  /api/v1/auth/apps/organizations/invitations/preview?token=…
POST /api/v1/auth/apps/organizations/invitations/accept
```

* **New account:** `{ "token", "password", "first_name", "last_name" }` creates a
  verified account, the membership and its roles in one transaction.
* **Existing account:** send the invitee's own access token as
  `Authorization: Bearer`; it must be the invited email in the same application.
  Creating a second account for an existing address answers 409.

---

## 6. Revocation and live checks

| Event | Effect |
|---|---|
| Member removed or suspended, organisation deactivated or deleted | Every session bound to it is revoked immediately; refresh fails. |
| Organisation role changed | The member's access tokens are invalidated; the next refresh carries the new roles. |
| Mode changed | See section 1. |

A resource server that verifies JWTs locally sees a change only when the token
expires (15 minutes by default). For decisions that cannot wait, call
**RFC 7662 introspection** with the application's client credentials:

```http
POST /oauth/introspect
Authorization: Basic base64(client_id:client_secret)
token=<access or refresh token>
```

`{"active": false}` for anything revoked, expired, issued to another
application, or whose user or membership is no longer active. Confidential
clients only. Advertised as `introspection_endpoint` in discovery.

---

## 7. Operations

* **Migrations** `00100`–`00104` are additive: new tables, nullable columns and
  partial indexes built `CONCURRENTLY`. Old and new instances can run side by
  side during a rolling deploy.
* **Audit events:** `organization.created/updated/deleted/mode_changed`,
  `organization.member_added/member_updated/member_removed`,
  `organization.member_roles_assigned/member_role_revoked`,
  `organization.invitation_sent/invitation_accepted/invitation_revoked`,
  `organization.selected/switched/login_denied` — with `audit_logs.organization_id`.
* **Metrics:** `emc_auth_organization_mints_total{outcome}`,
  `emc_auth_organization_param_ignored_total`,
  `emc_auth_organization_switches_total{outcome}`. All read zero while every
  application is `off` — check this after deploying the feature dark.
* **Limits:** 10 000 organisations per application, 5 000 members per
  organisation, 20 organisation roles per member, 4 KB metadata.

### Rollout

1. Deploy with `ORGANIZATIONS_ENABLED=false`. Confirm tokens and error rates are unchanged.
2. Enable in staging; set the pilot application to `optional`; run end-to-end tests.
3. Enable in production — every application is still `off`.
4. Pilot application to `optional`; backfill organisations and memberships.
5. Pilot application to `required` once the settings endpoint stops answering 409.

### Rollback

| Scope | Action |
|---|---|
| One application | `organizations_mode` → `off` (no deploy) |
| Whole feature | `ORGANIZATIONS_ENABLED=false` + restart |
| Code | Revert; the additive schema is harmless to the previous release |
| Schema (last resort) | `goose down` to the version before `00100`, after the code revert |
