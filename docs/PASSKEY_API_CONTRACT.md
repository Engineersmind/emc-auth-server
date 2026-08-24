# Passkey (WebAuthn) API contract — issue #112

**Authoritative for the backend as built on `feat/EM-SubhamDas/issue-112-webauthn-passkey`.**
Supersedes `WEBAUTHN_API_CONTRACT_ACTUAL.md`, which documents the spike's
`/auth/webauthn/*` paths — those no longer exist.

Hand this file to whoever builds the frontend. It is the whole contract: paths,
bodies, error codes, and the browser-side traps that make passkeys fail silently.

---

## 1. What changed from the spike

| | Spike | Now |
|---|---|---|
| Register | `POST /auth/webauthn/register/begin` · `/finish` | `POST /auth/passkey/register/begin` · `/complete` |
| Login | `POST /auth/webauthn/login/begin` · `/finish` | `POST /auth/passkey/login/begin` · `/complete` |
| Cookie login | `POST /auth/webauthn/session` | `POST /auth/passkey/session` |
| List | `GET /auth/webauthn/credentials` | `GET /auth/me/passkeys` |
| Rename | *did not exist* | `PATCH /auth/me/passkeys/:id` |
| Remove | `DELETE /auth/webauthn/credentials/:id` | `DELETE /auth/me/passkeys/:id` |

"passkey" is the product word a user reads; "WebAuthn" is the protocol word and
stays in the implementation. Management lives under `/auth/me/` beside
`/auth/me/sessions` because these are the caller's own resources, scoped by the
ids in their token and never by a path parameter.

---

## 2. Enabling the feature

Two independent gates, and **both** are required:

1. **Deployment** — `WEBAUTHN_RP_ID` and `WEBAUTHN_ORIGINS` must be set. Without
   them the routes are never registered and every path 404s.
2. **Tenant** — a `passkey_policies` row must allow it. **The platform default is
   off.** A registered route still answers `403 passkeys_disabled` until a tenant
   says yes.

Gate 2 exists because a passkey sign-in deliberately skips the MFA gate: a
verified passkey plus a user-verification gesture already is two factors.
Enabling passkeys therefore changes a tenant's effective authentication policy,
and that is not a decision the platform makes on their behalf.

```
PUT /api/v1/passkey-policy
{ "allow_passkeys": true }
```

---

## 3. End-user endpoints

### 3.1 Registration

```
POST /api/v1/auth/passkey/register/begin        (authenticated)
POST /api/v1/auth/passkey/register/complete     (authenticated)
      ?ceremony_token=<t>&name=<label>
```

`begin` → `200`:

```json
{
  "ceremony_token": "opaque-server-side-pointer",
  "publicKey": { "challenge": "...", "rp": {...}, "user": {...},
                 "pubKeyCredParams": [...], "authenticatorSelection": {...},
                 "excludeCredentials": [...], "extensions": {"credProps": true} }
}
```

Pass `publicKey` **untouched** to `navigator.credentials.create()`. Send the
resulting credential as the **raw request body** of `complete`, with
`ceremony_token` and `name` as **query parameters**.

> **Why query parameters and not body fields.** The WebAuthn library verifies the
> signature over the exact request-body bytes. The body belongs entirely to the
> protocol; anything of ours travels beside it. Wrapping the credential in an
> envelope and re-serialising works right up until it silently does not.

`complete` → `201`:

```json
{
  "id": "42",
  "name": "MacBook Pro",
  "rp_id": "auth.example.com",
  "synced": true,
  "synced_label": "Synced across your devices",
  "authenticator_name": "Apple Passwords",
  "aaguid": "fbfc3007-154e-4ecc-8c0b-6e020557d7bd",
  "created_at": "2026-08-21T10:00:00Z",
  "last_used_at": null
}
```

`authenticator_name` comes from an embedded FIDO Alliance–derived registry (385
models). It is empty for authenticators we do not recognise — a normal answer,
not an error. **It is a display label only**: it arrives in an unattested
response and must never gate anything in the UI beyond which icon to draw.

`synced_label` is the phrase to show the user. It is the fact that matters to
them: a device-bound passkey (Windows Hello) dies with the laptop, a synced one
does not.

If `name` is omitted the server labels the credential from the authenticator
model, falling back to `"Passkey"`. Still prompt the user — "What device is
this?" — because they can tell four devices apart and the model name cannot.

### 3.2 Passwordless sign-in

```
POST /api/v1/auth/passkey/login/begin       (public, NO parameters at all)
POST /api/v1/auth/passkey/login/complete    (public)  → tokens in the body
POST /api/v1/auth/passkey/session           (public)  → HttpOnly cookies
      ?ceremony_token=<t>
```

`login/begin` takes **no email and no login hint**. That is what makes it
useless as an account-enumeration oracle, and it is also what conditional
mediation requires — the page calls `get()` before the user has typed anything.
`allowCredentials` comes back empty; the authenticator identifies the user.

**Use `/session` for the browser and `/login/complete` for API clients.** Not a
preference: JavaScript cannot write an HttpOnly cookie, and an API client cannot
use cookies, so the two callers never want a choice. `/session` also enforces
CSRF by origin and refuses application-scoped accounts, which cannot have
cookies.

Note the load shape: `login/begin` is hit **once per login-page view by every
visitor**, passkey or not.

### 3.3 Management

```
GET    /api/v1/auth/me/passkeys        → [StoredCredential]
PATCH  /api/v1/auth/me/passkeys/:id    {"name": "New label"}  → StoredCredential
DELETE /api/v1/auth/me/passkeys/:id    → 204
```

The list is **not** filtered by relying party: a passkey the user registered on
another of the tenant's surfaces is still theirs to see and revoke. Ceremony
lookups filter by RP; management does not.

---

## 4. Error codes

Every error body is `{"error": "<sentence for the user>", "code": "<stable key>"}`.

| Code | HTTP | Meaning | What the UI should do |
|---|---|---|---|
| `passkeys_disabled` | 403 | Tenant has not enabled passkeys | Hide the passkey UI entirely |
| `passwordless_disabled` | 403 | Passkeys allowed, but not as a standalone sign-in | Hide the sign-in button; keep Settings |
| `origin_not_allowed` | 403 | This origin is not on the policy allow-list | Hide the UI; this is a config error, tell the operator |
| `not_configured` | 501 | Deployment has no relying party at all | Hide the UI |
| `challenge_expired` | 400/401 | Challenge TTL (120s) elapsed, or already used | **On login: show nothing.** Silently re-arm |
| `webauthn_failed` | 401 | Any sign-in failure | One generic message. Offer the password form |
| `verification_failed` | 400 | Registration could not be verified | "Could not verify. Try again." |
| `already_registered` | 409 | This device already has a passkey here | "This device already has a passkey." |
| `not_discoverable` | 400 | Authenticator made a non-resident key | Suggest a different authenticator |
| `too_many_passkeys` | 409 | At the per-account ceiling (default 10) | "Remove one before adding another." |
| `last_factor` | 409 | Removing this leaves no way to sign in | "Set a password or add another passkey first." |
| `invalid_name` | 400 | Name empty or over 64 characters | Inline field error |
| `not_found` | 404 | No such passkey **for this caller** | Refresh the list |

**`challenge_expired` on login must be silent.** A tab left open past the TTL is
the user doing nothing wrong and nothing they can act on. Re-arm; never show an
error.

**Every other sign-in failure returns exactly `webauthn_failed`** — bad
signature, wrong origin, unknown credential, missing gesture, a cloned
authenticator. They are indistinguishable on purpose. Do not try to infer more.

---

## 5. Frontend traps — each of these fails SILENTLY

Every one of these cost real debugging time. None is obvious from the spec.

1. **`autocomplete="username webauthn"` is mandatory** on the username input.
   Without the `webauthn` token the browser will not offer passkeys in that
   field and the whole autofill feature does nothing, with no error anywhere.

2. **One `navigator.credentials` request per page.** The conditional `get()`
   stays pending by design; calling `create()` while it is outstanding fails with
   *"A request is already pending."* Abort before, re-arm after — **including on
   the failure path**, or a cancelled registration leaves autofill silently dead
   for the rest of the page's life.

3. **The modal button is the guaranteed path; autofill is progressive
   enhancement.** Conditional-mediation autofill did not surface on Edge 151 /
   Windows 11 over `http://localhost` even though
   `isConditionalMediationAvailable()` returned true. Ship the "Sign in with a
   passkey" button as primary. Layer autofill on top, and when it is unavailable
   or silent, nothing is broken.

4. **`NotAllowedError` is not an error.** The user cancelled, or the prompt timed
   out. Show no error state — they made a choice.

5. **`SecurityError` means origin mismatch.** The page's origin is not on the
   allow-list, or the RP ID is not a registrable suffix of it. A configuration
   problem, not a user problem.

6. **No matching credential must fall through to the password form** with no
   error message.

7. **In dev, RP ID `localhost` covers every port**, so `:8080` and `:5173` are
   the same relying party and share credentials. This is a localhost-only
   artefact and the opposite of production. Conclude nothing about cross-surface
   behaviour from it.

---

## 6. Admin endpoints

```
GET    /api/v1/passkey-policy                              (tenant from JWT)
PUT    /api/v1/passkey-policy
GET    /api/v1/tenants/:tid/passkey-policy
PUT    /api/v1/tenants/:tid/passkey-policy
GET    /api/v1/applications/:appID/passkey-policy
PUT    /api/v1/applications/:appID/passkey-policy
DELETE /api/v1/applications/:appID/passkey-policy          (revert to inherit)

GET    /api/v1/users/:uid/passkeys
DELETE /api/v1/users/:uid/passkeys/:pid
```
Plus the canonical `/tenants/:tid/...` and `/tenants/:tid/applications/:appID/...`
variants. Policy routes carry `apps:*` (this is application configuration); the
user-credential routes carry `users:*` (this is somebody's credential).

There is deliberately **no route for the platform-default row**: it is the
fallback every other scope inherits from, so letting one tenant's administrator
edit it would change the default for all of them.

`PUT` body — every field optional, omitted means "leave as is":

```json
{
  "allow_passkeys": true,
  "allow_passwordless": true,
  "require_user_verification": true,
  "rp_id": "insurance.acme.com",
  "rp_display_name": "Acme Insurance",
  "origins": ["https://insurance.acme.com"],
  "max_credentials_per_user": 10
}
```

Sending `rp_id: ""` reverts to the server's relying party. `origins` may only be
set together with `rp_id` — origins without one would look configured while the
ceremony ran under a different RP, creating credentials the browser then never
offers.

The response reports the row **and** what the scope resolves to:

```json
{
  "scope": "tenant", "exists": true,
  "allow_passkeys": true, "rp_id": "", "origins": [],
  "effective": { "allow_passkeys": true, "rp_id": "auth.example.com",
                 "origins": ["https://auth.example.com"], "source": "tenant" }
}
```

`exists: false` means the scope inherits. `effective.source` says which row
answered — the first thing anyone needs when an RP ID is wrong.

**Admin removal skips the last-factor guard**, deliberately: support removing a
lost device is exactly the case that must not be blocked, because the
alternative is an account permanently reachable from a stolen laptop.

---

## 7. Audit events

| Action | Fires when |
|---|---|
| `auth.passkey_registered` | Credential stored; metadata carries the model and RP |
| `auth.passkey_login` | Sign-in succeeded; metadata carries `user_verified` |
| `auth.passkey_login_failed` | Any rejection. No user id — inherent, since only a verified assertion would have named them |
| `auth.passkey_renamed` | Label changed |
| `auth.passkey_removed` | Revoked; `by_admin: true` when support did it |
| `auth.passkey_clone_detected` | **See below** |
| `admin.passkey_policy_updated` | Policy write; metadata carries the effective result |

### `auth.passkey_clone_detected`

Fires when an assertion shows a credential's private key exists in more than one
place — a backup-eligibility flag that changed, or a signature counter that went
backwards. It is the only auth event in the system that implies key material was
extracted from an authenticator.

By the time the event is written, containment has **already happened**: the
credential is deactivated, every session for the account is revoked
(`revoked_reason = 'passkey_cloned'`), `token_version` is bumped, and an
account-wide denylist entry is written. An operator reading this event is
reading about action taken, not a decision they need to make.

The user is told only `webauthn_failed`. Telling a caller holding a copied key
that we noticed is free intelligence; the legitimate user learns from the
session-ended state and their passkey list.

Two honest notes on the detection:

- **The signature-counter control is inert for most real passkeys.** Apple and
  Google authenticators always report 0, so only a decrease from a non-zero
  stored value triggers. Backup-eligibility is the control that will actually
  fire.
- The checks run **before** library verification, and that ordering is
  load-bearing. `go-webauthn` validates the backup-eligibility flag itself and
  rejects a change with a generic bad request — if it gets there first, a cloned
  authenticator is indistinguishable from a bad signature and none of the
  containment above runs.

---

## 8. Known gaps

Not built in this change. Listed so nobody assumes otherwise.

| Gap | Consequence |
|---|---|
| **Enrolment prompt** (master plan P5) | Nobody is offered a passkey, so adoption is zero. Needs `passkey_enrolment: {offer, reason}` on the login response |
| **Second-factor mode** (P7) | Passwordless only. A tenant keeping passwords cannot use passkeys as a second factor today, even though `allow_passwordless: false` reserves the shape |
| **Account recovery** (P8) | A user whose only passkey is gone has no self-service route in. The last-factor guard prevents the worst case; it is not a recovery story |
| **Hosted login** (P12) | Passkeys do not work on `/oauth/authorize` at all |
| **Attestation verification** | We request `none` and operate no metadata service. `authenticator_name` is a label, not evidence |
| **HTTPS on a real domain** (blocker B1) | Android and macOS are untestable, RP-ID isolation ships unverified, and the autofill question in §5.3 stays open |
