> **STATUS UPDATE — 2026-08-21, issue #112.** This plan's §7 work items P1, P2,
> P3, P4 and P6 are now **implemented and tested** on branch
> `feat/EM-SubhamDas/issue-112-webauthn-passkey`, along with per-scope policy,
> the FIDO AAGUID registry, and clone containment. Blocker **B5 is cleared** —
> `govulncheck` reports zero vulnerabilities from the `go-webauthn`/`cbor`/
> `go-tpm` tree. **B1 (HTTPS on a real domain) still stands.** Still outstanding:
> **P5** (enrolment prompt), **P7** (second-factor mode), **P8** (account
> recovery), **P10–P12**.
>
> Two corrections this plan should carry forward:
>
> 1. **Control 7 (backup-eligibility immutability) was never triggerable because
>    `go-webauthn` rejects the change first**, with a generic bad request. Our
>    check ran after the library's and was dead code, so a cloned authenticator
>    was indistinguishable from a bad signature and none of the containment ran.
>    Fixed by parsing and checking before handing off to the library.
> 2. **Origin-based policy resolution cannot find a tenant that inherits the
>    server's origins**, which is the common single-RP deployment. Resolved by
>    making `login/begin` permissive-but-origin-bounded and `login/complete`
>    authoritative against the credential's own tenant.
>
> The live API contract is **`PASSKEY_API_CONTRACT.md`**; §4.3 of this file is
> out of date.

# Passkeys for end users — master plan

**Single source of truth for this track.** Written 2026-08-20 after the spike was
built and tested. Supersedes the scattered working notes listed in §12.

| | |
|---|---|
| Branch | `temp/webauthn-passkey-spike` (backend), `feature/em-subhamdas/EMC-000-webauthn-passkey-spike` (console) |
| State | Spike **proven working**, uncommitted, not mergeable |
| Verified on | Edge 151 / Windows 11, `localhost` |
| Library | `github.com/go-webauthn/webauthn v0.17.4` |
| Gates | `go build`, `go vet`, `golangci-lint` (0 issues), 4 unit tests — all green |

---

## 1. Executive summary — read this and nothing else if short of time

**What works, proven by live test:** a user registers a passkey with Windows
Hello and then signs in with **no password** — one button press and a biometric.
Two separate users did it; the server recorded both, minted real sessions, and
the token honestly carries `amr: ["hwk","user","mfa"]`.

**What does not work, and this changes the product promise:** the
"click the email field and it just offers your passkey" autofill UX — the thing
this feature was originally scoped around — **did not surface on Edge/Windows over
`http://localhost`**. The ceremony is fine; the browser simply declined to show
the credential in the field. See §3, which is the most important section in this
document.

**What is missing before any customer can use this:** per-application policy (no
tenant can switch it on or off), audit events, admin visibility and revoke, and
the enrolment prompt without which no user would ever create a passkey. Roughly
one week. §7 is the plan.

**The single biggest external blocker:** HTTPS on a real domain. It now gates
more than we thought — not just Android and macOS testing, but very likely the
autofill UX itself. §8.

---

## 2. Evidence — what was actually observed

Not claims. This is what the database and logs show after testing.

```
 id |        email         |   rp_id   | name  | discoverable | uv_capable | backup_eligible | backup_state | sign_count | last_used_at
  2 | carol@senie.local    | localhost | Win32 | t            | t          | t               | t            |          0 | 2026-08-20 14:07:57+00
  1 | alice@outreach.local | localhost | Win32 | t            | t          | t               | t            |          0 | 2026-08-20 12:07:32+00

 user_sessions: 263 | user 1871 | application_id NULL | "Edge on Windows" | 14:07:57
```

| Endpoint | Observed |
|---|---|
| `POST /webauthn/register/begin` | 200 — correct options: `rp.id=localhost`, `residentKey=required`, `userVerification=required`, `credProps=true` |
| `POST /webauthn/register/finish` | **201** — credential stored, `discoverable=t`, `uv_capable=t` |
| `POST /webauthn/login/begin` | 200 — challenge, `rpId=localhost`, `uv=required`, **no `allowCredentials`** (correct for discoverable) |
| `POST /webauthn/login/finish` | **200** via the modal flow — session created, `last_used_at` set |
| `POST /webauthn/session` | **Never exercised.** Built, compiles, untested live. |
| Conditional-mediation autofill | **Never produced an assertion.** `login/finish` appears in the logs only for the modal flow. |

Two independent users completing the flow is what makes this a proven mechanism
rather than a lucky single run.

---

## 3. The finding that changes the product promise

### 3.1 What happened

The plan was written around **conditional-mediation autofill**: the login page
arms a WebAuthn call on load, the browser decorates the email field with the
user's passkey, they tap it and confirm with a biometric. No form, no button.

On Edge 151 / Windows 11, serving the page from `http://localhost:8080`:

- `isConditionalMediationAvailable()` returned **true** — the browser says it
  supports the feature.
- The challenge was fetched and `navigator.credentials.get({mediation:
  'conditional'})` was armed successfully and stayed pending, which is correct
  behaviour.
- Edge's own credential manager listed the passkey: account
  `alice@outreach.local`, site **`https://localhost/`**.
- Clicking the email field offered **nothing**, repeatedly, with an empty field.
- The modal flow — the same ceremony, same endpoints, `mediation` left at its
  default — **worked first time.**

### 3.2 The likely cause, and how to confirm it

Edge stored the credential against the site `https://localhost/`. The page was
served from `http://localhost:8080`. For the **ceremony**, RP ID `localhost`
matches and the scheme is irrelevant, because `localhost` is exempt from the
secure-context requirement — which is exactly why registration and the modal
login both succeeded. But the **autofill layer** is the browser's password
manager, and it appears to match its stored *site* against the page origin
rather than against the WebAuthn RP ID. `https://localhost` and
`http://localhost:8080` are different origins, so it had nothing it considered
relevant to offer.

**This is a hypothesis with a cheap decisive test**, and it must be run before
any promise is made about the autofill UX:

```powershell
winget install FiloSottile.mkcert
mkcert -install
cd C:\projects\EMC_AUTH\demo-tenant-app
mkcert localhost
npx --yes serve -l 8443 --ssl-cert localhost.pem --ssl-key localhost-key.pem .
```

Add `https://localhost:8443` to `WEBAUTHN_ORIGINS` and `GLOBAL_CORS_ORIGINS`,
restart, **re-register the passkey** (a new origin means the old credential is
not offered), and try the field again.

- **Autofill now works** → cause confirmed. Autofill requires HTTPS in practice,
  not merely a secure context. Document it and move on.
- **Autofill still silent** → it is a platform/provider limitation on
  Edge+Windows, and §3.3 becomes permanent rather than provisional.

### 3.3 The product decision this forces

Two flows, both shipped, with honest language about each:

| Flow | Guarantee | UX |
|---|---|---|
| **Modal** — a "Sign in with a passkey" button, `mediation` default | **Works.** Proven on the target platform. | One button press, then a biometric. |
| **Autofill** — conditional mediation on the email field | **Best-effort.** Depends on browser, OS and where the passkey provider stored it. | Tap the field, pick, biometric. No button. |

**Ship the modal button as the primary, guaranteed path. Layer autofill on top as
progressive enhancement.** When conditional mediation is unavailable or silent,
the button is still there and nothing is broken.

I originally wrote conditional mediation into the plan as non-negotiable and
described the button flow as "not the UX that was asked for". That was wrong on
the evidence: the button flow is the only one that provably works on the stated
target platform, and a feature that works everywhere beats a nicer one that
works sometimes. What survives from the original framing is that
`residentKey: "required"` is still mandatory — see §5.1.

**How to describe it internally and to tenants:** "Sign in with your fingerprint
or face instead of a password — one tap." Not "no button". The button is real.

---

## 4. What was built

### 4.1 Files added

| File | Purpose |
|---|---|
| `migrations/00071_webauthn_credentials.sql` | `webauthn_credentials` + `webauthn_user_handles` |
| `internal/auth/webauthn.go` | Ceremonies and all verification controls; wraps the library so it can be swapped |
| `internal/api/handlers/webauthn.go` | Seven endpoints |
| `internal/auth/webauthn_test.go` | Four unit tests pinning the options that fail silently |
| `demo-tenant-app/passkey.html` | Working reference client (untracked, by request) |

### 4.2 Files changed

| File | Change |
|---|---|
| `internal/api/routes.go` | Service construction, route registration behind an `if webauthnSvc != nil` |
| `internal/auth/service.go` | `webauthnSvc` field, `LoginWebAuthn`, `WithWebAuthn` |
| `internal/auth/session.go` | `AMRWebAuthn = "hwk"`, `AMRUserVerif = "user"` |
| `internal/config/config.go` | Four `WEBAUTHN_*` fields |
| `cmd/server/main.go` | Pass-through to `RoutesConfig` |
| `docker-compose.yml` | Four `WEBAUTHN_*` vars + `localhost:8080` in `GLOBAL_CORS_ORIGINS` |
| `.env.example` | Documented the new vars |
| `go.mod` / `go.sum` | `go-webauthn v0.17.4` + transitive deps |

### 4.3 The API as it stands

```
POST   /api/v1/auth/webauthn/register/begin     cookie|bearer   -> {ceremony_token, publicKey}
POST   /api/v1/auth/webauthn/register/finish    cookie|bearer   -> 201 StoredCredential
         ?ceremony_token=<t>&name=<label>   body = raw attestation JSON
GET    /api/v1/auth/webauthn/credentials        cookie|bearer   -> [StoredCredential]
DELETE /api/v1/auth/webauthn/credentials/:id    cookie|bearer   -> 204
POST   /api/v1/auth/webauthn/login/begin        none            -> {ceremony_token, publicKey}
POST   /api/v1/auth/webauthn/login/finish       none            -> 200 tokens in body
         ?ceremony_token=<t>                body = raw assertion JSON
POST   /api/v1/auth/webauthn/session            none            -> 200 sets HttpOnly cookies
         ?ceremony_token=<t>                body = raw assertion JSON
```

**Why `ceremony_token` is a query parameter and not a body field.** The library
verifies the signature over the exact request-body bytes. The body therefore
belongs entirely to the protocol; anything of ours travels beside it. Most
reference implementations wrap the credential in an envelope and re-serialise,
which works until it silently does not.

**Why two login endpoints rather than one with a flag.** `/login/finish` returns
body tokens for API clients; `/session` sets HttpOnly cookies for browser
clients. This mirrors the split the codebase already made between `/auth/login`
and `/auth/session`. A browser cannot use body tokens (JavaScript cannot write an
HttpOnly cookie) and an API client cannot use cookies, so neither caller ever
wants a choice — they want different endpoints.

---

## 5. Flow documentation

### 5.1 Registration

```
Browser                              Server                          DB / Redis
   │ POST /register/begin ───────────►│ (bearer or session cookie)
   │                                  │ load-or-create opaque 64-byte user handle ──►
   │                                  │ load existing creds for THIS rp_id      ◄──
   │                                  │ BeginRegistration:
   │                                  │   residentKey        = required
   │                                  │   userVerification   = from policy
   │                                  │   excludeCredentials = existing
   │                                  │   extensions         = {credProps:true}
   │                                  │ store ceremony state, TTL 120s ────────────►
   │◄─ 200 {ceremony_token, publicKey}│
   │
   │ navigator.credentials.create()   → OS prompt (Windows Hello / Touch ID)
   │
   │ POST /register/finish ──────────►│ GETDEL ceremony state             ◄────────
   │   ?ceremony_token&name            │ reject if caller ≠ ceremony owner
   │   body = attestation              │ library verifies: origin, rpIdHash,
   │                                   │   type=webauthn.create, challenge,
   │                                   │   attestation signature, UV
   │                                   │ reject if credProps.rk == false
   │                                   │ INSERT credential ────────────────────────►
   │◄─ 201 {id,name,rp_id,synced,…}    │
```

`residentKey: required` is **not** negotiable even after §3. Discoverable
credentials are what let `login/begin` take no user identifier at all, which is
what removes the enumeration oracle — and that property holds for the modal flow
too, not just autofill.

### 5.2 Passwordless sign-in

```
Browser                              Server
   │ POST /login/begin ──────────────►│  NO parameters. No email, no hint.
   │◄─ 200 {ceremony_token, publicKey}│  allowCredentials omitted = discoverable
   │
   │ navigator.credentials.get(...)    → MODAL picker (works), or
   │                                     CONDITIONAL autofill (best-effort, §3)
   │
   │ POST /login/finish ─────────────►│ GETDEL ceremony state — challenge consumed
   │   or POST /session                │   BEFORE verification, so a failed attempt
   │   ?ceremony_token                 │   cannot retry the same challenge
   │   body = assertion                │ resolve user by credential_id + rp_id
   │                                   │ verify userHandle matches stored handle
   │                                   │ library: origin, rpIdHash, type, signature
   │                                   │ reject if backup_eligible changed  (clone)
   │                                   │ reject if sign_count regressed     (clone)
   │                                   │ reject if UV required and absent
   │                                   │ UPDATE sign_count, backup_state, last_used
   │                                   │ issueTokenPair — amr driven by the UV FLAG
   │◄─ 200 tokens, or cookies          │
```

### 5.3 `amr` semantics

| Situation | `amr` | Reasoning |
|---|---|---|
| Passkey + UV performed | `["hwk","user","mfa"]` | Possession of the authenticator **and** a biometric = two factors. Observed in testing. |
| Passkey, no UV | `["hwk"]`, **no `mfa`** | One factor. The token must not overstate it. |

Driven by the flag on the **assertion**, never by the options we sent. Only the
authenticator's response is evidence.

---

## 6. Security controls — status

| # | Control | Status |
|---|---|---|
| 1 | Origin exact-match against allow-list | ✅ library, server-config only |
| 2 | `rpIdHash == SHA256(rp_id)` | ✅ library |
| 3 | Challenge single-use, 120s, consumed by `GETDEL` before verification | ✅ tested (replay → `challenge_expired`) |
| 4 | `clientData.type` per ceremony | ✅ library |
| 5 | Opaque 64-byte user handle, not email, not PK | ✅ verified in DB |
| 6 | Sign-counter regression → reject | ✅ implemented. **Inert here**: platform authenticators report 0, so only a decrease from non-zero triggers. Correct, but means this control does nothing for most real credentials. |
| 7 | `backup_eligible` immutable → reject on change | ✅ implemented, not triggerable in testing |
| 8 | UV enforced when policy requires | ✅ implemented; live-verified only in the positive direction |
| 9 | Every lookup scoped by `tenant_id` + `rp_id` | ✅ |
| 10 | Duplicate credential → clean 409 | ✅ |
| 11 | Last-factor guard | ❌ **not built** — §7 |
| 12 | Rate limiting | ⚠️ `TokenRateLimiter` per IP on login. `RateLimitHits` metric still unwired. |
| 13 | Audit events | ❌ **not built** — §7. Every other auth path has them. |
| 14 | No client-parameterised trust (RP ID, origins, UV from config only) | ✅ |
| 15 | Discoverability enforced via `credProps`, not assumed | ✅ tri-state: explicit `false` rejects, absent logs |
| 16 | `login/begin` accepts no user identifier | ✅ enforced by having no parameters at all |
| 17 | `challenge_expired` distinguishable; all other failures identical | ✅ |

Controls 6 and 8 deserve honesty in review: both are implemented correctly and
neither was provably exercised. 6 cannot be, on this hardware.

---

## 7. Everything required for production

### 7.1 Blocks any customer use

| # | Work | Why it blocks |
|---|---|---|
| **P1** | **Per-application policy.** `webauthn` into `allowed_methods` + CHECK constraint; policy check in `RegisterBegin`; per-app `webauthn_rp_id`/`origins` overriding server config; `webauthn_passwordless` gating `LoginBegin`. | A tenant cannot enable, disable or scope the feature. Nothing ships without a customer-facing switch. Also forces the multi-RP path the single-RP spike sidesteps entirely. |
| **P2** | **Audit events** — `credential_registered`, `credential_revoked`, `login_success`, `login_failed`, `clone_detected`. Fire-and-forget. | A passkey sign-in currently leaves no trace. Every other auth path audits. Will not pass review. |
| **P3** | **Admin API** — list a user's credentials, admin revoke, extend `ResetUserMFA` to deactivate passkeys, `MFAPolicy` fields + `webauthn_enrolled_users`. | Support cannot help a lost-device user. **And `ResetUserMFA` is a live hole:** it clears TOTP and email MFA but leaves passkeys active, so a lost-device reset does not actually remove the factor. |
| **P4** | **Last-factor guard** (control 11). | Under `mode = required`, a user can currently remove their only factor. |

### 7.2 Required for the feature to be worth shipping

| # | Work | Why |
|---|---|---|
| **P5** | **Enrolment prompt** — `passkey_enrolment: {offer, reason}` on the login response, true only when the app allows it **and** the user has no credential *for that RP ID*. Client-side snooze in `sessionStorage`. Wrapped in try/catch: an offer, never a gate. | Without it nobody is offered a passkey, so nobody creates one and adoption is zero. A broken passkey endpoint must never block a login that already succeeded. |
| **P6** | **Rename endpoint** `PATCH /credentials/:id`. | Promised in the frontend handoff, never built. My omission. |
| **P7** | **Second-factor mode** — `mfaGate` branch, `/auth/login/webauthn/begin|finish` against the existing OTP session, forced-enrolment path. | Tenants who keep passwords cannot use passkeys at all today; only fully passwordless works. |

### 7.3 Required before external users

| # | Work | Why |
|---|---|---|
| **P8** | **Account recovery.** Minimum: never let a passkey be the only factor without a password or a second credential; keep "sign in with a password instead" visible; re-offer enrolment once on a different device. | A user whose only passkey is gone has no self-service route in. This is the largest real operational cost of passkeys. |
| **P9** | **Resolve §3** — run the HTTPS test, then decide the promise and write it into tenant docs. | We currently cannot honestly describe the UX. |
| **P10** | **Test Pattern C** — `/auth/webauthn/session` has never run. Console checks C1–C11. | An entire endpoint is unverified. |
| **P11** | **Test Pattern B** — app-scoped registration. Needs an `oauth_clients` row; the seed creates none. | The tenant-app pattern, i.e. EMC Insurance's pattern, is untested. |
| **P12** | **Hosted login** — `webauthn.html` + `/oauth/authorize/webauthn/*`. | Passkeys do not work on `/oauth/authorize` at all. Explicitly not next week. |

---

## 8. Blockers, ranked

**B1 — HTTPS on a real domain. The only true external blocker.**
Now gates more than first assessed:
- the §3 autofill question, which is the product promise itself;
- Android and macOS entirely — a phone cannot reach a laptop's `localhost`;
- RP-ID isolation, so two security controls ship unverified;
- cross-device QR.

Cheapest path that avoids deploying unmerged auth code to shared dev: a
Cloudflare or ngrok tunnel. Start it before writing more code — it is somebody
else's queue and it gates sign-off, not development.

**B2 — No tenant application to pilot against.** P11 needs a real app with a
known domain and a frontend willing to integrate. `demo-tenant-app/` is enough to
merge, not enough to call it live.

**B3 — Frontend ownership.** The console agent is working from
`WEBAUTHN_API_CONTRACT_ACTUAL.md`. It needs a real ticket reference; commitlint
rejects `EMC-000`.

**B4 — Merge queue.** P1–P7 touch `routes.go`, `service.go`, `mfa.go`,
`metrics.go` — the same files as #107, #7b, #109, #8. Start after **#8** merges or
budget a rebase per PR.

**B5 — `govulncheck` on the new dependency tree** has not been read. The CI
vulnerability gate cannot fail, so it will not tell you. `go-webauthn` pulls
`cbor`, `go-tpm`, `go-webauthn/x`.

---

## 9. Traps found by testing — worth keeping written down

Each of these cost time and none is obvious from a spec.

1. **One credentials request per page.** The conditional `get()` stays pending by
   design; calling `create()` while it is outstanding fails with *"A request is
   already pending."* Abort before, re-arm after — **on the failure path too**, or
   a cancelled registration leaves autofill silently dead forever.
2. **`autocomplete="username webauthn"` is mandatory** on the username input.
   Without the `webauthn` token the browser will not offer passkeys there and the
   feature does nothing, with no error.
3. **`challenge_expired` must be silent on login.** A tab left open past the TTL
   is the user doing nothing wrong. Re-arm; never show an error.
4. **Soft delete + a plain unique index permanently burns a credential ID.** A
   user who revoked a passkey could never re-enrol the same device. The index must
   be partial (`WHERE is_active`). Caught from a reference implementation's notes,
   not from first principles.
5. **`GLOBAL_CORS_ORIGINS` is separate from `WEBAUTHN_ORIGINS` on purpose** —
   CORS decides who reads our responses, the other decides who mints credentials
   against our RP. Both are exact-match including port. Both must list the demo
   origin.
6. **`docker-compose.yml` sets `environment:` explicitly**, so a variable absent
   there is invisible to the container no matter what `.env` says. Passkeys stayed
   disabled and the endpoints 404'd, which is indistinguishable from "my config
   was ignored".
7. **In dev, RP ID is `localhost` for every port**, so `:8080` and `:5173` are the
   same relying party and share credentials. A localhost-only artefact and the
   opposite of production. Do not conclude anything about cross-surface behaviour
   from it.
8. **The seed creates no `oauth_clients` row**, so the app-scoped login path
   cannot be tested on a fresh database, and `client_secret_hash` is a hash — a
   lost secret is unrecoverable, only re-creatable.

---

## 10. Corrections to earlier guidance in this track

Recorded so nobody works from the superseded version.

| Earlier claim | Correction |
|---|---|
| Conditional-mediation autofill is the deliverable; the button flow "is not the UX that was asked for" | Inverted. The button flow is the guaranteed path; autofill is progressive enhancement. §3. |
| `localhost` is sufficient to test the autofill UX on desktop | Sufficient for the ceremony, apparently not for Edge to surface the credential. §3.2. |
| Windows Hello passkeys are device-bound, so expect "This device only" | The observed credential came back `backup_eligible=t, backup_state=t` — synced. Better for recovery, and the label differs. |
| A rename endpoint exists | It does not. P6. |
| Cookie-mode finish is "day 4" work | Built early as `/auth/webauthn/session`. Still untested live (P10). |

---

## 11. Sequenced plan

**Before code:** B1 (start the HTTPS/tunnel request), B5 (`govulncheck`), and the
§3.2 mkcert test — which is 15 minutes and decides the product promise.

**Week 1, backend:** P1 → P2 → P3+P4 → P5 → P6, then P7 if time. Split as PRs so
each is independently revertible; P1 alone is a substantial PR because per-app RP
resolution changes every lookup.

**Week 1, frontend, in parallel:** console via the corrected contract — modal
button first (it works), autofill behind a feature check. Then P10's C1–C11.

**Week 2:** P7, P8, P11 with a named pilot, and the §9 traps written into tenant
integration docs.

**Not scheduled:** P12 (hosted login), enterprise attestation, FIDO MDS,
device-bound policy.

---

## 12. Working notes this document supersedes

Kept for detail; this file is authoritative where they disagree.

| File | Still useful for |
|---|---|
| `WEBAUTHN_PLAN.md` | Original design reasoning, RP-ID Pattern A/B/C analysis |
| `WEBAUTHN_FLOWS.md` | Pre-existing MFA/TOTP flows and how passkeys slot in |
| `WEBAUTHN_TEST_PROCEDURE.md` | A0–A11 and console C1–C11 test steps |
| `WEBAUTHN_DEMO_COMMANDS.md` | Copy-paste commands and the account-discovery SQL |
| `WEBAUTHN_API_CONTRACT_ACTUAL.md` | The live contract — hand to any frontend agent |
| `WEBAUTHN_FRONTEND_PROMPT.md` | Console handoff prompt. **Read with the contract file; it predates it** |
| `WEBAUTHN_PREREQUISITES.md` | Original ask list, mostly resolved |
| `WEBAUTHN_DEMO_RUNBOOK.md` | Superseded by `WEBAUTHN_DEMO_COMMANDS.md` |
