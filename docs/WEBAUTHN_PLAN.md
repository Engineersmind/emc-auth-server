# WebAuthn / Passkeys for end users — implementation plan

**Status:** plan only, nothing built. No `webauthn`, `passkey` or `fido` string
exists anywhere in the repo today (verified by repo-wide grep, 2026-08-20).

**Scope:** WebAuthn for **end users** of tenant applications. The target
experience, set by the owner 2026-08-20, is the mainstream consumer passkey UX:

> Sign in once with a password, get offered "create a passkey", accept. Next
> visit, the email field already offers the passkey — tap it, Face ID or
> fingerprint, and you are in. **No form filled, no password typed, no login
> button pressed.**

That is **passwordless sign-in with conditional-mediation autofill**, and it is
the deliverable — not a phase-2 nice-to-have. Three things follow and are
non-negotiable for this UX (§3.1):

1. Credentials must be **discoverable** (`residentKey: "required"`). A
   non-discoverable credential never appears in autofill. Ever.
2. **`userVerification: "required"`** — the biometric gesture *is* the second
   factor, so it has to be mandatory or passwordless is a downgrade.
3. **Conditional mediation** — moved from "out of scope" into the core.

Admin-console passkeys and enterprise attestation remain out of scope (§9).

---

## 1. What already exists that this must fit into

WebAuthn is not greenfield here. Five pieces of existing machinery decide most
of the design, and fighting any of them is how this goes wrong.

| Existing thing | Where | Why it constrains us |
|---|---|---|
| Per-application MFA policy | `application_mfa_settings` (00048/00049), `internal/auth/mfa.go` | `mode` ∈ {disabled, optional, required}, `allowed_methods` ⊆ {totp, email} with a CHECK constraint. WebAuthn is a third method — the constraint and every `methodAllowed` call site must learn it. |
| The pre-auth challenge session | `createOTPSession` / `loadOTPSession` / `bumpOTPAttempts` (`service.go`) | Already carries user, tenant, email, role, perms, `app_id`, `methods[]`, `persistent` in Redis under a single-use token with a 5-attempt budget. A WebAuthn assertion step is a new *verifier* against this same session — not a new session type. |
| `mfaGate` | `service.go:882` | The single fail-closed junction where every first factor (password, magic link) decides whether to challenge. WebAuthn-as-second-factor is a branch here and nowhere else. |
| Per-tenant issuer + per-tenant signing keys | #7a, #95 | Tokens minted after a WebAuthn ceremony are ordinary tokens. Nothing new — but `amr` must tell the truth (§5.5). |
| Hosted login | `handlers/templates/login.html`, `oauth_authorize.go` | Server-rendered, two pages (password → TOTP), one hidden `request` handle and nothing else. A passkey step is a third page in the same state machine, and it is the *only* place a browser is on **our** origin (§2). |

Two adjacent deferred items get partly paid off by this work: CLAUDE.md **#12**
(the dead `RateLimitHits` metric — the new ceremony limiters are the cheapest
place to wire it) and **#20** (the hosted login's missing enrolment page —
WebAuthn enrolment there is the same page shape TOTP needs).

---

## 2. The decision that shapes everything: what is the Relying Party?

A WebAuthn credential is permanently bound to an **RP ID** — a registrable
domain suffix of the origin that created it. A credential created with
`rp.id = auth.emc.com` is unusable, by browser enforcement, on
`insurance.acme.com`. That is not a policy we choose; it is the phishing
resistance.

We have **two live login patterns**, and they sit on opposite sides of that line:

**Pattern A — hosted login / OIDC.** Browser is on
`{APP_BASE_URL}/oauth/authorize`. Our origin. RP ID = our domain. One passkey
per user works across *every* tenant application that federates through hosted
login. This is the Auth0/Okta model.

**Pattern B — app-scoped API login** (`POST /auth/apps/login`, Basic app
credentials). The tenant's own frontend collects the password and calls our API
cross-origin. Browser is on `insurance.acme.com`. RP ID must be
`insurance.acme.com`, and the credential is usable *only* there. Per
`SPRINT_ISSUE_6_PLAN.md:97` this is the dominant integration pattern today.

### Recommendation: support both, store the RP ID on every credential row, never cross it

- Ship **Pattern A first**. It is the correct architecture (one passkey, works
  everywhere, we control the page, no tenant configuration to get wrong), and
  it is where the OIDC track is already heading.
- Add **Pattern B as explicit per-application opt-in**: the tenant configures
  `webauthn_rp_id` + `webauthn_origins[]` on their application, and we
  exact-match the ceremony origin against that list. Unconfigured, Pattern B is
  simply off — fail closed, the same instinct as `first_party` in 00067.
- `webauthn_credentials.rp_id` is **NOT NULL** and every lookup filters on it.
  A credential registered under one RP ID must never appear in another
  ceremony's `allowCredentials`, and the library's RP-ID-hash check stays
  enabled to enforce it a second time.

**Consequence to state plainly in the PR and in tenant docs:** a user who
registers a passkey on `insurance.acme.com` does not have a passkey on the
hosted login page, and vice versa. That is WebAuthn working correctly, not a
bug — but it *will* be reported as one. Both surfaces list credentials with
their RP ID so support can tell which is which.

---

## 3. Passwordless is the goal; second factor is the stepping stone

Two distinct features hide under "WebAuthn":

1. **WebAuthn as an MFA method** — password first, then an authenticator
   assertion instead of a 6-digit code. Reuses `mfaGate`, the OTP session, the
   attempt budget, the policy table, the admin reset path. Small, verifiable,
   nothing existing changes shape.
2. **Passkeys as the first factor** (passwordless + autofill) — the target UX.
   New login path, new enumeration surface, new account-recovery story, and it
   must count as *two* factors (possession of the key + UV) or it is a downgrade
   from password+TOTP.

We still build 1 before 2, but **not because it is the destination** — because
every verification control in §7 is identical between them, and a bug in a
second-factor path costs you a factor while the same bug in a passwordless path
is a full authentication bypass. 1 is where those controls get written and
reviewed under a password's protection. It is scaffolding, and it ships (it is
useful on its own), but 2 is the release the owner asked for.

Do **not** merge them into one PR.

### 3.1 What the target UX forces

These are not preferences. Each one is required by the UX in the header, and
each one is a decision that cannot be quietly changed later without breaking
existing credentials.

| Requirement | Why | Consequence if wrong |
|---|---|---|
| `residentKey: "required"` (discoverable) | Only discoverable credentials appear in browser autofill. The authenticator must be able to answer "which accounts do I hold for this site?" without being told a username. | Passkey registers fine, never appears in the email field, feature looks broken with no error anywhere. **Not retrofittable** — existing credentials would need re-registration. |
| `userVerification: "required"` | No password is involved, so the biometric/PIN gesture is the only proof it is the right human. | A passkey on an unlocked stolen laptop signs in with a click. Passwordless becomes weaker than password+TOTP. |
| `mediation: "conditional"` on the login page | This is the "it just offers itself in the email field" behaviour. Without it you get a modal the user must first click a button to summon. | Works, but it is "Sign in with a passkey" *button* UX, not the described UX. |
| A challenge fetched on **page load**, before the user types | Conditional mediation needs the challenge up front — the `get()` call is made while the page is idle, waiting. | No autofill. This is the one real operational cost; see §6.3. |
| `user.name` = email, `user.id` = opaque handle | The account picker displays `user.name`. An opaque `user.id` (§7.5) is still required — these are different fields and both matter. | Picker shows a meaningless blob, or the handle leaks PII. |

### 3.2 Platform support — Android Chrome, desktop Chrome, Edge, macOS

Owner requirement, 2026-08-20. **All four are fully supported**, including the
conditional-mediation autofill in §3.1. This is the mainstream configuration —
every one of these shipped passkey autofill in 2022–23, and none of them needs a
workaround.

| Platform | Passkeys | Autofill (conditional) | Where the credential lives | BE/BS | Sign counter |
|---|---|---|---|---|---|
| **Chrome, Android** | ✅ | ✅ Chrome 108+ | Google Password Manager, or any CredMan provider | **synced** (BE 1 / BS 1) | usually stays 0 |
| **Chrome, Windows** | ✅ | ✅ Chrome 108+ | Windows Hello (device-bound) *or* Google Password Manager (synced) | **either** | Hello increments |
| **Edge, Windows** | ✅ | ✅ Edge 108+ | Windows Hello / Microsoft Wallet | mostly device-bound | increments |
| **Safari, macOS** | ✅ | ✅ Safari 16+ (Ventura) | iCloud Keychain | **synced** (BE 1 / BS 1) | stays 0 |
| **Chrome, macOS** | ✅ | ✅ | iCloud Keychain (Chrome 118+) or GPM | synced | stays 0 |
| *Firefox* | ✅ | ⚠️ arrived much later | OS provider | varies | varies |
| *In-app browsers* (Instagram, Facebook, some WebViews) | ⚠️ unreliable | ❌ | — | — | — |

Third-party managers — 1Password, Bitwarden, Dashlane — act as passkey providers
on all of the above and need **no special handling**. Same ceremony, same code.

#### What this costs us — four consequences that are not obvious

1. **HTTPS on a real registrable domain is a hard prerequisite, not a
   deployment detail.** WebAuthn requires a secure context, and the RP ID must
   be a registrable domain — **an IP address will never work**, and
   `http://` only works for `localhost`. This promotes CLAUDE.md deferred **#1**
   (HTTPS in production) from "before real end users" to **blocking for PR 4**,
   and it means every Pattern B tenant needs their app on HTTPS with a real
   domain before they can enable passkeys at all. Put it in the tenant
   onboarding checklist.

2. **Cross-device QR is why users do not need to register everywhere.** Desktop
   Chrome and Edge show a QR code; the user scans it with their Android phone,
   Bluetooth proves proximity, and the assertion comes back over the hybrid
   transport. So an Android-only passkey still signs the user in on a Windows
   desktop. This substantially reduces the "register on every device" burden —
   and it is worth saying in the UI, because users do not expect it.

3. **Windows Hello credentials are device-bound (BE 0) and die with the
   laptop.** Android and macOS credentials sync (BE 1) and survive a lost
   device. So the same feature has two completely different recovery profiles
   depending on where the user enrolled, and §9's recovery guardrails are not
   optional on Windows. Surface it: the credential list should say "synced" vs
   "this device only", read straight off `backup_state`. This is the clearest
   payoff for storing BE/BS.

4. **The `transports` column earns its keep.** Returning stored transports in
   `allowCredentials` (second-factor flow, §6.2) is what makes the browser show
   the *right* affordance — "use Windows Hello" vs "scan with your phone" vs
   "insert your key" — instead of a generic chooser. Cheap to store, visibly
   better UX.

#### Non-negotiable: feature-detect and always keep the password fallback

The in-app-browser row is the real-world gap. A user opening the app from a link
inside Instagram or a WebView may get no WebAuthn at all. So:

```js
const canAutofill = await PublicKeyCredential.isConditionalMediationAvailable?.();
const hasPlatformAuth = await PublicKeyCredential
  .isUserVerifyingPlatformAuthenticatorAvailable?.();
```

Both are `undefined`-safe optional calls for a reason — on an unsupported
browser the *property itself* may not exist. If either is false, show the
password form and never mention passkeys. This is the same reasoning as §9's
recovery guardrail: passwordless is an offer, never the only door.

#### Dev-environment quirk worth knowing before it wastes an afternoon

`localhost` is the one origin exempt from the HTTPS rule, so local development
works — but **RP ID is `localhost` for both `:9090` (the server) and `:5173`
(the dashboard)**; the port is not part of the RP ID. Origins *are* port-specific
and must both be in the allow-list. Result: in dev, credentials are effectively
shared across every local port, which is fine locally and must never be the
shape of a production config. Test the RP-ID isolation controls (§7.9) against
real hostnames, not localhost, or the test proves nothing.

#### If a native Android or iOS app is ever in scope

Not in scope now (the requirement is browsers), but the constraint is worth
knowing because it is expensive to discover late: sharing passkeys with a native
app requires `/.well-known/assetlinks.json` (Android Digital Asset Links) or
`apple-app-site-association` (iOS), served over HTTPS **from the RP ID's
domain**. Under Pattern B that is the *tenant's* domain, not ours — so it is
their file to host, and our integration docs would have to tell them so.

---

## 4. Library

Use **`github.com/go-webauthn/webauthn`** (successor to `duo-labs/webauthn`,
the de-facto Go implementation). It handles CBOR/COSE key parsing, attestation
statement verification, and the ceremony validations that are tedious to get
right and catastrophic to get wrong.

- Hand-rolling CBOR/COSE attestation parsing is not a serious option for code
  on the authentication path.
- It brings `fxamacker/cbor` and `google/go-tpm` transitively. **Run
  `govulncheck` on the resulting `go.sum` before writing a line of feature
  code** — and note CLAUDE.md deferred **#7** (pgx v5.6.0 has a live reachable
  vuln) plus the standing note that the CI vulnerability gate is currently
  vacuous. Do not let a new dependency hide behind a gate that cannot fail.
- Wrap it. Our code talks to an `internal/auth/webauthn.go` service; the
  library's types do not leak into handlers, so replacing it later is a
  one-file change. Same containment as `secretbox.go` and `pkce.go`.

---

## 5. Schema

### 5.1 New table `webauthn_credentials` (migration `00071`)

```sql
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id               BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    user_id          BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id        BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    application_id   BIGINT REFERENCES oauth_clients(id) ON DELETE CASCADE,

    -- The ceremony scope. NOT NULL and part of every lookup: a credential
    -- created for one RP ID must never be offered in another RP's ceremony.
    rp_id            TEXT   NOT NULL,

    credential_id    BYTEA  NOT NULL,     -- raw; needed for allowCredentials
    public_key       BYTEA  NOT NULL,     -- COSE_Key
    aaguid           BYTEA,
    attestation_type TEXT   NOT NULL DEFAULT 'none',
    transports       TEXT[] NOT NULL DEFAULT '{}',

    sign_count       BIGINT NOT NULL DEFAULT 0,
    -- Backup Eligible / Backup State: BE says the credential *may* sync,
    -- BS says it currently is. BE is immutable for the life of the
    -- credential — a change means a cloned or swapped authenticator.
    backup_eligible  BOOLEAN NOT NULL DEFAULT false,
    backup_state     BOOLEAN NOT NULL DEFAULT false,
    uv_initialized   BOOLEAN NOT NULL DEFAULT false,

    name             TEXT   NOT NULL DEFAULT '',   -- user-facing label
    is_active        BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at     TIMESTAMPTZ,
    last_used_ip     INET
);

-- Globally unique: a credential ID identifies one authenticator credential,
-- and the same one must not be claimable by two accounts.
CREATE UNIQUE INDEX IF NOT EXISTS uq_webauthn_credential_id
    ON webauthn_credentials (credential_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_creds_user_rp
    ON webauthn_credentials (user_id, rp_id) WHERE is_active;
CREATE INDEX IF NOT EXISTS idx_webauthn_creds_tenant
    ON webauthn_credentials (tenant_id);
```

**Deliberate exception to non-negotiable #1 ("never store raw tokens"), to be
stated in the migration comment:** `credential_id` and `public_key` are stored
raw. They are not secrets — the public key is public by construction, and the
credential ID must be returned verbatim in `allowCredentials` for
non-discoverable authenticators to work at all. Hashing either would break the
protocol. WebAuthn stores nothing secret on our side; that is the point of the
scheme.

**Soft-delete:** `is_active = false` rather than DELETE, matching
non-negotiable #5's spirit — a removed passkey is audit-relevant. The admin
`ResetUserMFA` path must deactivate WebAuthn credentials too, or a lost-device
reset silently leaves a live factor behind.

### 5.2 Extend `application_mfa_settings` (same migration)

The 00048 comment explicitly invites this ("future per-app MFA options extend
this row"), and `magic_link_enabled` set the precedent that not-strictly-MFA
login config lives there.

```sql
ALTER TABLE application_mfa_settings
    ADD COLUMN IF NOT EXISTS webauthn_rp_id             TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS webauthn_origins           TEXT[]  NOT NULL DEFAULT '{}',
    -- 'required' by default: the biometric gesture IS the second factor in a
    -- passwordless sign-in. 'preferred' is offered for tenants who need to
    -- support older hardware keys as a SECOND factor only.
    ADD COLUMN IF NOT EXISTS webauthn_user_verification TEXT    NOT NULL DEFAULT 'required',
    ADD COLUMN IF NOT EXISTS webauthn_attestation       TEXT    NOT NULL DEFAULT 'none',
    -- Passwordless sign-in + autofill. Off by default so an application opts in
    -- deliberately, but this is the feature the whole design exists for.
    ADD COLUMN IF NOT EXISTS webauthn_passwordless      BOOLEAN NOT NULL DEFAULT false,
    -- Whether to show the "create a passkey?" prompt after a password login
    -- (§6.6). Separable from passwordless because a tenant may want to seed
    -- credentials before switching sign-in on.
    ADD COLUMN IF NOT EXISTS webauthn_prompt_enrolment  BOOLEAN NOT NULL DEFAULT false;

-- 'webauthn' joins the method set.
ALTER TABLE application_mfa_settings
    DROP CONSTRAINT IF EXISTS application_mfa_settings_methods_check;
ALTER TABLE application_mfa_settings
    ADD CONSTRAINT application_mfa_settings_methods_check
    CHECK (allowed_methods <@ ARRAY['totp','email','webauthn']::TEXT[]
           AND array_length(allowed_methods, 1) >= 1);
-- plus CHECKs: webauthn_user_verification IN ('discouraged','preferred','required')
--              webauthn_attestation       IN ('none','indirect','direct')
```

Empty `webauthn_rp_id` = Pattern B off for that application. The hosted-login
RP ID comes from config and is **not** tenant-configurable.

### 5.3 Config

Two new fields on `config.Config`: `WebAuthnRPID` and
`WebAuthnRPDisplayName`, defaulted from `APP_BASE_URL` and the server name. An
explicit override matters because `APP_BASE_URL` may carry a host that is not
the registrable domain you want the passkey labelled with — and the label is
what the user sees in their password manager forever.

### 5.4 Challenge state — Redis, never a cookie

One Redis key per ceremony: `webauthn:reg:{token}` / `webauthn:auth:{token}`,
TTL **120 s**, single-use, holding the challenge bytes, the user/tenant, the RP
ID, and the required UV. Deleted on first use, success or failure. This mirrors
`storePreAuthSession` exactly and should reuse it rather than invent a parallel
mechanism.

For the **second-factor** flow the challenge attaches to the *existing* OTP
session (`otpSessionKey(token)+":webauthn"`), so the 5-attempt budget and the
5-minute window already apply with no new code.

### 5.5 `amr` values

Add to `session.go` alongside `AMRPassword`/`AMROTP`:

```go
AMRWebAuthn  = "hwk"  // RFC 8176: proof-of-possession of a hardware key
AMRUserVerif = "user" // RFC 8176: user verification performed (biometric/PIN)
```

- Second factor: `["pwd", "hwk", "mfa"]`.
- Passwordless with UV: `["hwk", "user", "mfa"]` — the `mfa` claim is honest
  only when UV actually happened, so it must be driven by the UV flag on the
  assertion, not by configuration intent.
- Passwordless without UV: `["hwk"]` and **no** `mfa`. A relying party that
  cares can then tell the difference.

---

## 6. API surface

### 6.1 Self-service registration (JWT-authenticated)

New group `/api/v1/auth/webauthn`, under the same `jwtRenew, appRateLimit`
middleware as `otpGroup` (`routes.go:754`). Deliberately *not* under
`/auth/otp/` — a passkey is not a one-time password, and phase 5 makes it a
first factor.

| Method | Path | Purpose |
|---|---|---|
| POST | `/webauthn/register/begin` | policy-checked; returns `PublicKeyCredentialCreationOptions` with **`residentKey: "required"`**, `userVerification` from policy, `user.name` = email, `user.id` = opaque handle |
| POST | `/webauthn/register/finish` | verifies attestation, stores credential, accepts a `name` |
| GET | `/webauthn/credentials` | list (id, name, rp_id, aaguid, created_at, last_used_at) |
| PATCH | `/webauthn/credentials/:id` | rename |
| DELETE | `/webauthn/credentials/:id` | revoke — last-factor guard under `required` |

Registration mirrors `EnrollUser` (`mfa.go`) exactly: `mode == disabled` →
reject; `webauthn` not in `allowed_methods` → reject; **and registering while
another factor is already active must require proof of that factor**, the same
rule as `ErrTOTPReenrollProof`. A stolen access token must not be able to add a
passkey. This is the single most likely thing to be forgotten.

### 6.2 Second-factor login completion (pre-auth, no JWT)

| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/login/webauthn/begin` | `{otp_session_token}` → assertion options + `allowCredentials` |
| POST | `/auth/login/webauthn/finish` | `{otp_session_token, credential}` → token pair |
| POST | `/auth/login/mfa/webauthn/begin` \| `/finish` | forced-enrolment path, parallel to `/login/mfa/enroll` |

`mfaGate` gains `webauthn` in the offered `methods[]` when the user has an
active credential *for the ceremony's RP ID* and the policy permits it. Note
this makes `methods` RP-dependent for the first time — `mfaGate` needs the
ceremony RP ID threaded in, or it will offer `webauthn` on a surface where the
user has no usable credential and strand them.

Rate limiting: `mw.OTPRateLimiter(rlCfg)` on all four, same as `/login/otp`.

### 6.3 Passwordless sign-in with autofill — the headline feature

| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/webauthn/login/begin` | `{client_id}` → challenge + `rpId`, **`allowCredentials: []`** |
| POST | `/auth/webauthn/login/finish` | `{credential}` → token pair |

**No email is ever sent to `begin`.** With an empty `allowCredentials` the
authenticator identifies the user from its own discoverable credentials and
returns a `userHandle`, which we resolve to the account. The
account-enumeration problem does not get mitigated — it stops existing. This is
strictly better than what `/forgot-password` has to do (non-negotiable #6), and
it is why §3.1 makes `residentKey: "required"` mandatory.

Reject an `email` parameter on this endpoint outright. The moment it accepts one
it becomes a cleaner account oracle than any endpoint we have, and there is no
reason to accept one when every credential we issue is discoverable.

#### The operational cost nobody expects: `begin` is a page-load endpoint

Conditional mediation needs the challenge **before** the user interacts with
anything. The frontend calls `get({mediation: "conditional"})` while the page
sits idle, and that call needs options in hand. So:

> `POST /auth/webauthn/login/begin` is hit **once per login-page view, by every
> unauthenticated visitor, whether or not they own a passkey.**

That is a new traffic shape for us — every other unauthenticated endpoint is hit
only by someone actively trying to log in. Four consequences:

1. **It must be cheap.** No DB read at all on the happy path: mint random bytes,
   `SET` one Redis key, return. The `client_id` → RP-ID/origin resolution should
   be cached, not a per-request `oauth_clients` lookup.
2. **Rate limit by IP, not by account** — there is no account yet. `TokenRateLimiter`
   is the right shape; the per-account limiter is inapplicable.
3. **Challenge TTL vs. abandoned tabs.** A 120 s challenge and a user who leaves
   the login tab open for an hour means the conditional `get()` eventually
   resolves against a dead challenge. `finish` must return a *distinguishable*
   `challenge_expired` error so the frontend silently re-runs `begin` and
   re-arms, rather than showing the user a failure for something they did not do.
   **This is the single most likely source of "passkeys are flaky" reports.**
4. **It is an unauthenticated Redis-write endpoint.** Bounded by TTL and key
   size, but it is a memory-growth vector under flood: 120 s × request rate ×
   ~200 bytes. Worth a number in the PR description rather than a shrug.

#### `finish` — what makes this two factors

The token's `amr` must be driven by the **UV flag on the assertion**, never by
the options we sent (§7.8). One gesture on a device with biometrics genuinely is
two factors: possession of the authenticator + the biometric. Without UV it is
one, and the token must say so — otherwise passwordless is a downgrade from
password+TOTP wearing an upgrade's clothes.

With `webauthn_user_verification = 'required'` (the default), a missing UV flag
is a hard rejection, not a downgraded `amr`.

### 6.6 "Create a passkey?" after a password login (PR 3)

The prompt in the owner's description ("*it sometimes asks to create a
passkey*") is a **frontend** decision that needs one **server** signal, because
only the server knows the policy and the existing credentials.

Extend the login response (and `GET /auth/me`) with an additive hint:

```json
{
  "access_token": "…",
  "refresh_token": "…",
  "passkey_enrolment": {
    "offer": true,
    "reason": "no_credential_for_rp"
  }
}
```

`offer` is true only when **all** of: the app has `webauthn_prompt_enrolment`,
`webauthn` is in `allowed_methods`, the RP ID is resolvable for this surface,
and the user has **no active credential for that RP ID**. That last clause is
why this cannot be a pure frontend check — and it is the same RP-scoping trap as
§6.2: a user with a passkey for `insurance.acme.com` must not be nagged for one
again there, but *should* be offered one on the hosted login page.

Deliberately **not** included: a server-side "don't ask me again" flag. A
suppression table is a new stateful surface for a nag.

**Client-side snooze, in `sessionStorage` rather than `localStorage`.** Store a
`passkeySnoozedUntil` timestamp (~2 days) on "Maybe later". `sessionStorage` makes
the snooze per-tab and lets it die with the tab, which is deliberately a milder
suppression than a permanent opt-out — a user who dismisses once is not
dismissing forever, and we never have to build an un-dismiss UI. (Borrowed from a
reference implementation that had the same problem; it is the right shape.)

**The prompt is an offer, never a gate.** Every branch — accepted, cancelled,
errored, snoozed — must still land the user in the application, and the whole
block belongs inside a `try/catch` that swallows failures. A broken passkey
endpoint must never be able to block a login that has already succeeded. This is
the single most important thing to get right about the prompt, because the
failure mode is "nobody can sign in" in exchange for a feature nobody asked for
at that moment.

### 6.4 Hosted login (phase 6)

A `templates/webauthn.html` page plus `POST /oauth/authorize/webauthn/{begin,finish}`,
resuming the authorize request by its `request` handle exactly as
`/oauth/authorize/mfa` does. This is the only surface where Pattern A
registration can happen, so it also needs the enrolment page deferred item
**#20** describes.

### 6.5 Admin

- `GET/PUT /tenants/:tid/applications/:appID/mfa` — extend the existing
  `MFAPolicy` payload with the WebAuthn fields (additive; existing clients
  unaffected).
- `GET /tenants/:tid/applications/:appID/users/:uid/webauthn` — list a user's
  credentials, for support.
- `DELETE .../webauthn/:credID` — admin revoke (lost device).
- `ResetUserMFA` extended to deactivate WebAuthn credentials.
- `GetUserMFAStatus` / `TOTPStatus` gain a `webauthn` block; `MFAPolicy` stats
  gain `webauthn_enrolled_users`.

---

## 7. Security controls checklist

Every line here becomes a test in §8. This list is the real deliverable of the
plan; the endpoints are the easy part.

1. **Origin** — exact string match against the allow-list (hosted-login origin,
   or the application's `webauthn_origins`). No suffix matching, no wildcards.
2. **RP ID hash** — verify `authData.rpIdHash == SHA256(rp_id)`. The library
   does it; do not disable it, and assert it in a test so nobody later can.
3. **Challenge** — crypto-random ≥16 bytes, single-use, 120 s TTL, deleted
   before the verification result is known so a failed attempt cannot be
   retried against the same challenge.
4. **Type** — `clientDataJSON.type` is `webauthn.create` / `webauthn.get`
   respectively. Cross-type replay must fail.
5. **User handle** — an opaque per-user random ID, **not** the email and not the
   integer PK. It is stored on the authenticator and surfaced in some UIs; it
   must not leak PII and must not be enumerable.
6. **Sign count** — a non-zero counter that fails to increase means a cloned
   credential: reject and audit. Counter `0` on both sides is normal for many
   platform authenticators and must not be treated as an error.
7. **BE/BS** — `backup_eligible` is immutable; a change means a cloned or
   swapped authenticator → reject and audit. `backup_state` may flip freely and
   is informational (it tells support whether the passkey is synced).
8. **UV** — when policy says `required`, the UV flag on the assertion must be
   set. Never infer UV from the options we sent; only the authenticator's
   response is evidence.
9. **Tenant isolation** — every credential lookup filters `tenant_id` **and**
   `rp_id`. Non-negotiable #4: the tenant comes from the session/JWT, never the
   body.
10. **Credential uniqueness** — the unique index must surface as a clean 409,
    not a 500, when a user re-registers an already-registered authenticator
    (`excludeCredentials` should prevent it, but only in cooperating browsers).
11. **Last-factor guard** — under `mode = required`, removing the last active
    factor is refused (`ErrMFARequiredByPolicy`), counting WebAuthn credentials
    as factors.
12. **Rate limits** — `OTPRateLimiter` on ceremony endpoints, and **wire
    `metrics.RateLimitHits` while you are in there** (CLAUDE.md #12).
13. **Audit** — new events: `webauthn.credential_registered`,
    `webauthn.credential_revoked`, `webauthn.login_success`,
    `webauthn.login_failed`, `webauthn.clone_detected`. Fire-and-forget, per
    the existing philosophy.
14. **No client-parameterised trust** — RP ID, origins and UV requirement come
    from server-side config only. A body field that could change the RP ID is a
    phishing bypass.
15. **Discoverability is enforced, not requested.** `residentKey: "required"` in
    the options is a *request*; verify at `register/finish` that the credential
    actually came back discoverable (the `credProps.rk` extension where the
    browser provides it) and record it. A non-discoverable credential silently
    stored is a credential that will never autofill and will look like a bug for
    the life of the account. Reject it at registration with an actionable error.
16. **`/webauthn/login/begin` accepts no user identifier.** Not an email, not a
    `user_handle`, not a `login_hint`. Enforce it in the request struct so it
    cannot be added later by accident — this is what keeps the endpoint from
    being an enumeration oracle (§6.3).
17. **Expired-challenge errors are distinguishable but not informative.**
    `finish` returns a distinct `challenge_expired` code so the frontend can
    silently re-arm (§6.3), while every genuine verification failure returns one
    indistinguishable error. Do not let the retry affordance become a probe for
    which credentials exist.

---

## 8. Test plan

Gates match `make ci-local` (lint + gosec + tests) plus the sprint's existing
Postman gate.

**Unit / integration (Go), no browser:** build a **software authenticator**
fixture — generate an EC P-256 key in the test, assemble `authData` +
`clientDataJSON`, sign. That makes every item in §7 assertable without a
browser, which is the only way this gets real coverage. Build it in PR 1; every
later PR depends on it.

Mandatory negative tests, one per §7 item, plus:

- wrong-origin assertion → rejected
- replayed challenge → rejected
- credential from tenant A presented in tenant B's ceremony → rejected
- credential registered under RP ID X offered on RP ID Y → absent from
  `allowCredentials` **and** rejected if forced
- registration while another factor is active, without proof → rejected
- sign-count regression → rejected + audit row
- BE flip → rejected + audit row
- UV absent under `required` policy → rejected
- passwordless `begin` for an unknown email → indistinguishable from known

**Manual live checklist**, in the shape of `GOOGLE_LOGIN_TESTING.md`. The four
platforms in §3.2 are a **requirement**, so each is a required row, not a
sample. Each needs both ceremonies (register + sign in) *and* the autofill:

| # | Platform | Must verify |
|---|---|---|
| 1 | **Chrome, Android** | register via GPM; autofill offers it in the email field; `backup_state = true` recorded |
| 2 | **Chrome, Windows** | register via Windows Hello; autofill; **`backup_eligible = false`** recorded and shown as "this device only" |
| 3 | **Edge, Windows** | same as 2 — separate row because Edge has its own credential store |
| 4 | **Safari, macOS** | register via iCloud Keychain; autofill; sign counter stays 0 and is **not** treated as a regression (§7.6) |
| 5 | **Chrome, macOS** | iCloud Keychain from a non-Safari browser |
| 6 | **Cross-device QR** | desktop Chrome → scan with Android → assertion returns over hybrid transport |
| 7 | **No platform authenticator** | password form shown, passkeys never mentioned (§3.2 feature detection) |
| 8 | **Abandoned tab** | leave the login page open past the 120 s challenge TTL, then use the passkey → silent re-arm, no visible error (§6.3) |
| 9 | *(optional)* YubiKey | hardware key as a second factor under `userVerification: preferred` |

Rows 2 and 4 are the ones that catch real bugs: they are the two platforms whose
BE/BS and sign-counter behaviour differ most, and §7.6 / §7.7 are written
specifically for them.

**This checklist cannot run on `localhost`** for the RP-ID isolation items — see
§3.2's dev quirk. It needs a real HTTPS host, which makes deferred #1 a
prerequisite for signing off PR 4, not a deployment afterthought.

Run the Go suite with `-p 1` (deferred #8) and with `REDIS_URL` set — the sprint
file records that Redis tests silently skip without it.

**Postman:** a new folder. Note up front that the ceremonies **cannot** be
fully automated in Postman without a software-authenticator pre-request script.
Decide before starting whether to write that signer or to accept the manual
checklist as the gate, and say which in the PR — do not leave it ambiguous the
way the TOTP folder is.

---

## 9. Out of scope — state explicitly in each PR

- Admin-console (first-party dashboard) passkeys.
- Enterprise attestation and FIDO MDS blob validation. `attestation = none` is
  the default and the only mode with real coverage; `direct` is accepted and
  stored but the AAGUID is not checked against a metadata service.
- Device-bound passkey policy ("no synced credentials") — the BE/BS flags are
  stored, so this becomes a policy read later, not a schema change.
- ~~Conditional UI / autofill~~ — **now in scope and central** (§3.1, §6.3).

**Account recovery is no longer safely out of scope.** It was, while passkeys
were a second factor behind a password. Once passwordless is the primary path,
a user whose only credential is on a lost phone has *no* way in, and "contact an
admin" is the entire recovery story. Two mitigations belong in the passwordless
PR, not a later one:

1. **Never let passwordless be the only path** without the account also having a
   password or a second passkey. Offer, do not force: the login page keeps
   "sign in with a password instead" visible.
2. **Encourage a second credential.** After the first passkey registers, the
   §6.6 prompt should reappear once on a *different* device. A synced passkey
   (`backup_state = true`) already covers this — which is exactly what the BE/BS
   columns are for, and a good reason to surface "this passkey is synced" in the
   credential list.

A self-service recovery flow (emailed re-registration link, or recovery codes)
remains its own ticket, and it is the biggest real operational cost of passkeys.

---

## 10. Ticket breakdown

Six PRs. Each independently reviewable and independently revertible.

Reordered 2026-08-20 after the owner set passwordless + autofill as the target.
PR 4 (passwordless) is now the release the feature exists for; PRs 1–3 are the
route to it, and PR 5 was pulled forward because a tenant cannot enable any of
this without the admin controls.

| # | PR | Contents | Depends on |
|---|---|---|---|
| 1 | **Foundation** | `go-webauthn` + govulncheck, migration 00071, `internal/auth/webauthn.go` service, config fields, software-authenticator test fixture | — |
| 2 | **Registration** | §6.1 endpoints with `residentKey: "required"`, discoverability enforcement (§7.15), policy checks, re-registration proof, credential CRUD, audit events | 1 |
| 3 | **Second factor + the enrolment prompt** | `mfaGate` branch, §6.2 endpoints, §6.6 `passkey_enrolment` hint, forced-enrolment path, `amr`, `ResetUserMFA` extension, `RateLimitHits` wiring | 2 |
| 4 | **★ Passwordless + autofill** | §6.3 both endpoints, no-identifier enforcement, `challenge_expired` re-arm, UV-drives-`amr`, recovery guardrails (§9) | 3 |
| 5 | **Admin policy + status** | §6.5, `MFAPolicy` fields and stats, swagger | 2 |
| 6 | **Hosted login** | §6.4, `webauthn.html`, authorize-flow resume, and the #20 enrolment page | 4, plus #6/#7b/#8 merged |

**The demo app is not optional here.** The conditional-mediation frontend
(`isConditionalMediationAvailable`, the idle `get()`, the re-arm on
`challenge_expired`) is where this UX actually lives, and no Go test can prove it
works. `demo-tenant-app/` must gain a working passkey login as part of PR 4, or
PR 4 cannot be verified at all — see §8's manual checklist and §11.

**Hard prerequisite, not a PR.** The §3.2 platform requirement makes HTTPS on a
real domain blocking for PR 4's sign-off (CLAUDE.md deferred **#1**). PRs 1–3
can be built and tested on `localhost`; PR 4 cannot be *verified* there. Line
that up before PR 3 lands, or PR 4 stalls with nowhere to run.

**Sequencing against work in flight.** PRs 1–5 touch `internal/api/routes.go`,
`internal/metrics/metrics.go`, `internal/auth/service.go`, `mfa.go` and the
admin handlers — the same files as PR #107 (#6), the stacked #7b branch, PR #109
(#70) and #8. Start after **#8 merges**, or expect a rebase per PR. Nothing here
belongs in the W33 sprint: that ticket order is #7a → #6 → #7b → #8, and this
is a new track.

---

## 11. Frontend work required — flagged, not written

Per CLAUDE.md's frontend boundary, these are named here and not touched:

- **Tenant application frontends** (Pattern B): `navigator.credentials.create()`
  / `.get()`, base64url ⇄ `ArrayBuffer` helpers for every binary field
  (`challenge`, `user.id`, `credential.rawId`, `attestationObject`,
  `clientDataJSON`, `authenticatorData`, `signature`, `userHandle`), and a
  passkey management screen. The reference implementation belongs in
  `demo-tenant-app/`.
- **Admin SPA** (`ui/src/`): the WebAuthn fields on the application MFA policy
  page, and a per-user credential list with an admin revoke button.
- **Integration docs**: a WebAuthn section in the tenant integration guide
  covering §2's RP-ID constraint — specifically that passkeys do not travel
  between the tenant's own domain and the hosted login page, and that
  `webauthn_origins` is exact-match.

---

## 12. Decisions — resolved 2026-08-20 by the owner

The three open questions are closed by the target UX in the header. Recorded
here so they are not re-litigated.

| Question | Decision | Follows from |
|---|---|---|
| Passwordless in scope? | **Yes — it is the deliverable.** Second factor is scaffolding (§3). | The described UX is passwordless by definition: "instead of adding the email and password". |
| UV default | **`required`** (was `preferred`). | No password in the flow, so the gesture is the only proof of the human. §3.1. |
| Discoverable credentials | **`residentKey: "required"`**, enforced at registration (§7.15). | Non-discoverable credentials never autofill. Not retrofittable. |
| Conditional mediation | **In scope**, was §9 out-of-scope. | It *is* the "field offers it automatically" behaviour. |
| Pattern A or B first? | **Pattern B first** — see below. | The UX is on the tenant's own page. |

### Why the UX forces Pattern B first (this reverses §2's recommendation)

§2 recommends Pattern A (hosted login) as the better architecture, and it still
is. But the owner's description is "*when we login to any website*" — the login
form is **on the site the user visited**. That is Pattern B: browser on
`insurance.acme.com`, so RP ID is `insurance.acme.com`, and the autofill happens
in that page's email field.

Pattern A gives the same gesture, but only *after* a redirect to our domain —
the "Sign in with EMC" shape. It is a legitimate product, and it is where the
OIDC track is going, but it is **not** the experience described, and it is where
the live integrators are not.

So: **PRs 2–4 target Pattern B**, with per-application `webauthn_rp_id` +
`webauthn_origins` configured by the tenant. Pattern A follows in PR 6.

The §2 consequence still holds and now bites sooner: a passkey created on
`insurance.acme.com` will not appear on the hosted login page. With Pattern B
shipping first, most credentials in the system will be app-scoped, so the hosted
login page will look passkey-less to nearly everyone until PR 6. Say that in the
PR 4 description.

### Still genuinely open

1. **Which application is the pilot?** Pattern B needs one real tenant app with
   a known domain to configure `webauthn_rp_id` against, and a frontend team
   willing to write the conditional-mediation code. Without a named pilot, PR 4
   is unverifiable beyond `demo-tenant-app/`.
2. **Do we keep passwords at all for a passkey user?** §9's recovery guardrail
   says yes for now (offer, never force). Worth an explicit product call before
   PR 4, because "passwordless" that still has a password behind it is a
   different security claim from one that does not.
