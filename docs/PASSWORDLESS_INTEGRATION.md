# Passwordless sign-in and sign-up with email codes

A user types an email address and receives a 6-digit code. The right code signs
them in, or, when the application allows it, creates their account and signs them
in. No password is requested, stored or reset for that user.

This guide is for developers integrating an application and for the people who
administer one. The design and its reasoning are in
[docs/plans/passwordless-email-otp.md](plans/passwordless-email-otp.md).

> **Passwordless is opt-in and additive.** Password login is unchanged and is the
> default. An application with no passwordless policy behaves exactly as it did
> before this feature existed.

## Who builds the screens

The auth server provides the API only. **Your application builds its own sign-in
and sign-up screens** and calls the three endpoints below from its **backend**
(they take the application's client secret, so they cannot be called from a
browser). The hosted `/oauth/authorize` page is unchanged and has no email-code
option.

## Modes

Each application is in one of three modes, set per application (or inherited from
the tenant or platform):

| Mode | Settings | What users see |
|---|---|---|
| **Password only** (default) | no policy, or `email_otp_enabled=false` | Today's flow, unchanged |
| **Both** | `email_otp_enabled=true`, `password_enabled=true` | The user chooses password or code on each sign-in |
| **Passwordless only** | `email_otp_enabled=true`, `password_enabled=false` | Codes only. The password flow is closed |

Stored passwords are **never deleted or changed** by any mode change. Closing the
password flow stops it being read; reopening it makes every stored password work
again.

## Flow

```
your backend                         auth server                      user's inbox
     │  POST /passwordless/start {email}  │                                 │
     │ ─────────────────────────────────► │  stores a challenge, mails code │
     │ ◄───────────────────────────────── │ ──────────────────────────────► │
     │   200 { challenge_id, ... }        │                                 │
     │                                    │                                 │
     │  (user types the code)             │                                 │
     │  POST /passwordless/verify         │                                 │
     │      { challenge_id, code }        │                                 │
     │ ─────────────────────────────────► │  proves the code, signs in or up│
     │ ◄───────────────────────────────── │                                 │
     │   200 tokens | OTP challenge | 409 │                                 │
```

All requests carry `Authorization: Basic base64(client_id:client_secret)`. A
backend that forwards its users' addresses should send `X-EMC-Forwarded-For` so
rate limits apply per person rather than per server.

### `POST /api/v1/auth/apps/passwordless/start`

```json
{ "email": "ada@example.com", "first_name": "Ada", "last_name": "Lovelace",
  "persistent": false, "captcha_id": "…", "captcha_answer": "…" }
```

`first_name`, `last_name`, `persistent` and the captcha fields are optional.
Response, **identical for every address**:

```json
{ "challenge_id": "…64 hex characters…", "expires_in": 300, "resend_after": 30, "code_length": 6 }
```

The response is the same whether or not the address is registered, whether or not
sign-up is allowed, and whether the address is blocked or throttled. Do not try to
infer any of that from it. Mail is sent asynchronously, so a mail outage is not
visible here either.

### `POST /api/v1/auth/apps/passwordless/resend`

```json
{ "challenge_id": "…" }
```

Sends a fresh code on the same challenge; the previous code stops working.
Returns `{ "resend_after": 30, "resends_left": 2 }`. Failed attempts are **not**
reset, so resending cannot multiply guesses.

### `POST /api/v1/auth/apps/passwordless/verify`

```json
{ "challenge_id": "…", "code": "123456", "organization": "org_…", "roles": ["staff"] }
```

`organization` and `roles` are optional and mean exactly what they mean on
`/apps/login`. The response is one of:

| Status | Body | Meaning |
|---|---|---|
| 200 | token pair (`access_token`, `refresh_token`, …) | Signed in (and signed up, if the account was new) |
| 200 | `requires_otp: true` with `otp_session_token`, `methods` | A second factor is due. **`email` is never in `methods`** after an emailed first factor |
| 403 | `mfa_enrollment_required` | The application requires MFA and the user has none. Allowed methods exclude `email` |
| 409 | `organization_selection_required` | Multi-organization user: choose one and complete as for a password login |
| 400 | `invalid_or_expired_code` | See below |

**One uniform error.** A wrong, expired, already-used, unknown, burned or refused
code, an application that is not enabled, a deactivated account and sign-up being
off all return the same `400 invalid_or_expired_code`. Show one message ("that
code did not work, request a new one") and restart at the email step. Branching on
anything else would make your screen an account-enumeration oracle.

### Errors

| Status | `error` | When |
|---|---|---|
| 400 | `invalid_email` | The address is not valid (ASCII only; no IDN or homograph addresses) |
| 400 | `invalid_or_expired_code` | Any verification failure (above) |
| 401 | `invalid client credentials` | Wrong `client_id` or secret |
| 403 | `passwordless_disabled` | The application has not enabled email codes (this is configuration, so it is safe to reveal) |
| 404 | `not_found` | The feature is not enabled on this server |
| 428 | `captcha_required` / `captcha_invalid` | The scope's captcha policy protects passwordless start |
| 429 | `resend_cooldown`, `too_many_resends`, or a rate limit | Wait `Retry-After` seconds |
| 503 | `passwordless_unavailable` | The challenge store is unreachable. The same for every address |

## Tokens and sessions

* New `gty` (grant) value `email_otp`, and new `amr` value `email_otp`. After a
  second factor `amr` is `["email_otp","otp","mfa"]`. There is no registered
  RFC 8176 value for an emailed code (the same precedent as `link` for magic
  links). **Relying parties that validate `gty` or `amr` against a fixed
  allow-list must add `email_otp`**, or they will reject these tokens.
* An email code proves control of an inbox and is treated as a **single factor**.
  It must not be presented as NIST AAL2. Layer TOTP or a passkey on top where a
  higher assurance is required.
* The session is non-persistent unless the application's policy allows it **and**
  the user asked for it at `start`.
* Refresh, device list and revocation are unchanged.

## What happens at `verify`

| Situation | Result |
|---|---|
| Account exists, active | Signs in |
| Account exists, address **unverified**, has a password | Signs in, **ends any existing session** (an earlier registrant's), marks the address verified, keeps the stored password. See *Pre-hijack protection* |
| Account exists, address unverified, no password (an invited user) | Signs in, verifies the address, which counts as accepting the invitation |
| Account blocked, deactivated, soft-locked, or its tenant is switched off | `invalid_or_expired_code` |
| No account, sign-up on, domain permitted | Creates the account (default role, verified, **no password**), signs in |
| No account, sign-up off or domain refused | `invalid_or_expired_code` |

Accounts are created at `verify`, never at `start`, so an address can be neither
squatted nor used to fill the database with unverified rows.

## Pre-hijack protection

If someone registers `victim@example.com` with a password they know, then the real
owner later signs in by code, the owner's proof of inbox control is the first time
anyone has proved the address. At that moment every session on the account is
ended, the address is marked verified and the event is audited
(`auth.preverification_neutralized`). The stored password is **kept**:

* in a passwordless-only application the password flow is closed, so it is
  harmless;
* in *both* mode the stored password still works until the owner resets it through
  forgot-password. This is the same residual risk that exists without this feature.

## Limits and abuse controls

| Control | Default |
|---|---|
| Code length and lifetime | 6 digits, 5 minutes (configurable 5 to 15) |
| Wrong attempts per code | 5, then the code is destroyed |
| Failed verifications per address | 10 per hour across all its codes, then verification is refused for that address for 15 minutes (password login is unaffected) |
| Code requests per address | 5 per hour (configurable 1 to 10) |
| Resends | 3 per challenge, 30 seconds apart |
| Daily email budget | optional, per application |
| Latest request wins | A new `start` for the same address destroys the previous challenge |

Rate limits key on the **submitted address** and, for verify and resend, on the end
user's forwarded IP. They never key on whether the address exists. Code requests
use their **own** rate-limit bucket, so a flood of requests cannot exhaust the quota
that real password logins use.

Overrides per application are available through the per-user rate limit API using
the keys `passwordless_start` and `passwordless_verify`.

## Switching an application's mode

Recommended path: password only → **both** → passwordless only. In *both*, announce
the change and let integrators move. Watch the password sign-in figures in the
impact preview fall to about zero before closing the password flow.

When `password_enabled=false`:

* `POST /apps/login`, `POST /apps/register`, `POST /forgot-password` and
  `POST /reset-password` answer `403 password_auth_disabled` **before any lookup
  or hash**. These attempts do not count toward account lockout and are counted in
  the metric `emc_auth_password_auth_disabled_total{route}`.
* Reset links issued earlier stop working when redeemed (and are left unspent).
* Sessions that already exist keep working until they expire.
* **Integrator backends that send passwords to `/apps/login` stop working at the
  moment of the switch.** That is the main reason for the staged path.
* Stored passwords are untouched. Switching back makes them work again.

Switching to password only while active users have no stored password is refused
unless the administrator explicitly overrides, because those users could not sign
in.

## Administering it

Policy is set per platform, tenant and application; every field inherits unless
overridden, and platform values are ceilings. Everything below is under
`/api/v1/tenants/{tid}/…` (and the slug-less equivalents for the caller's own
tenant).

| Route | Purpose |
|---|---|
| `GET\|PUT\|DELETE …/applications/{appID}/passwordless-policy` | Read (stored row, effective values, source of each), replace, or reset overrides |
| `GET\|PUT\|DELETE …/passwordless-policy` | Tenant defaults (tenant owner) |
| `GET\|PUT /platform/passwordless-policy` | Platform defaults and ceilings (platform operator) |
| `POST …/passwordless-policy/impact` | Dry run: who a change affects |
| `GET …/passwordless-policy/history` and `POST …/history/{hid}/restore` | Append-only history; restore writes a new version |
| `GET …/applications/{appID}/passwordless/stats?window=24h\|7d\|30d` | Usage counters |
| `GET …/users/{uid}/auth-methods` | A user's sign-in methods |
| `POST …/users/{uid}/verify-email` | Mark an address verified |
| `POST …/users/{uid}/clear-passwordless-throttle` | Lift a verify block |
| `PUT …/users/{uid}/email` | Lost-mailbox recovery. Requires `reason`; revokes sessions and tells the previous address |

* `PUT` carries the `version` you read; a mismatch is `409 version_conflict` with the
  current policy, never a silent overwrite.
* Enabling email codes is refused where the application requires MFA (mode `required`,
  or `optional` with MFA role rules) and allows only the `email` method
  (`passwordless_mfa_conflict`), where the **Sign-in code** email
  template is disabled, and where no first factor would remain.
* Opening sign-up, closing the password flow, restoring a version and editing tenant
  defaults need a tenant owner or platform operator; an application administrator
  can change their own application otherwise.
* **New applications start with their email templates disabled.** Enable the
  `passwordless_code` template for the application (and check its sender) before
  turning email codes on. A test message can be sent with
  `POST …/email-settings/test` and `template_type: "passwordless_code"`: it is
  clearly marked as a test and never creates a challenge for any account.

## Deployment and configuration

| Variable | Default | Notes |
|---|---|---|
| `PASSWORDLESS_ENABLED` | `false` | While false, the three routes answer 404 and every application is password only, whatever the database says |
| `PASSWORDLESS_CODE_HMAC_KEY` | unset | Hex, at least 64 characters (`openssl rand -hex 32`). **Required in production and staging when the feature is on, and only then**, so an upgrade needs no new variable |
| `RATE_LIMIT_APP_USER_PASSWORDLESS_START` | `0` (built-in 5/min) | Per recipient |
| `RATE_LIMIT_APP_USER_PASSWORDLESS_VERIFY` | `0` (built-in 10/min) | Per end-user IP |

Codes are stored in Redis only, as an HMAC bound to the challenge id, never as
plain text and never in the database. Redis unavailable means passwordless fails
closed; nothing else is affected.

**Rollback.** Prefer, in order: turn off `signup_enabled`; turn email codes off for
an application; set `PASSWORDLESS_ENABLED=false` last. Turning the whole feature
off locks out users who were created without a password until it is turned back on
(while it is off, the password flow is reopened for users who have a stored
password). No password is ever touched.

## Observability

Metrics: `emc_auth_passwordless_start_total{result}`,
`…_verify_total{result}`, `…_created_total{result}`,
`…_email_send_failures_total`, `…_throttled_total{scope}`,
`…_preverification_neutralized_total`, `emc_auth_password_auth_disabled_total{route}`.

Audit: successful code sign-ins are ordinary `auth.login` events with
`auth_method="email_otp"` and failures are `auth.login_failed`, so login statistics
and risk signals keep working. Around them: `auth.passwordless_started`,
`auth.passwordless_resent`, `auth.passwordless_throttled`,
`user.created_passwordless`, `auth.preverification_neutralized`,
`admin.passwordless_policy_changed`, `admin.passwordless_throttle_cleared`,
`admin.user_email_verified`, `admin.user_email_changed`. Events carry an address
hash and the domain, never the address, the code or the challenge id.

Alert on the verify failure ratio, on send failures
(`…_email_send_failures_total`, the only place a mail outage is visible because
sending is asynchronous) and on throttle spikes.

## Residual risks

Email is a weak channel and the plan says so plainly:

* **Mailbox compromise** gives sign-in. Layer TOTP or a passkey for higher assurance.
* **Real-time phishing relay**: a user can be tricked into typing the code into an
  attacker's page. Email codes are not phishing-resistant; passkeys are.
* **Delivery**: a code that arrives after it expires, or not at all, is a support
  case. Keep SPF, DKIM and DMARC aligned on the sending domain.
* **Single factor**: not NIST AAL2.
