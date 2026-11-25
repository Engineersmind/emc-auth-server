# Social login — integrator guide (state + PKCE binding)

Applies to `GET /oauth/{provider}/login` and `POST /api/v1/auth/oauth/exchange`
(Google, GitHub). Added for issue #177.

## The flow

```
integrator FE ──► integrator BE ──► EMC auth server ──► Google/GitHub
                                          │
integrator callback ◄── 302 ?login_code=… ┘
integrator BE ── POST /api/v1/auth/oauth/exchange ──► tokens
```

The browser is sent to `/oauth/{provider}/login` and comes back to the
integrator's callback URL carrying a one-time `login_code`.

## Why you should bind the flow (login CSRF)

A `login_code` on its own proves "someone completed a sign-in", not "**this
browser** started it". An attacker can finish a Google sign-in in their own
browser, keep the callback URL, and trick a victim's browser into opening it.
If the app exchanges the code, the victim ends up signed in to the **attacker's
account**.

Both protections below are **optional**. Existing integrations that send
neither behave exactly as before. New integrations should use at least one;
using both is fine.

## Option 1 — `state` pass-through

1. Your backend generates an unguessable `state` and stores it in a cookie /
   server session bound to the user's browser.
2. Send it: `GET /oauth/google/login?client_id=…&redirect=…&state=<state>`
3. The callback arrives as `https://app/cb?state=<state>&login_code=…`
   (also on `?error=…` redirects). The value is returned **unchanged**.
4. Before exchanging, compare the returned `state` with the one in the user's
   cookie/session. Mismatch → discard the `login_code`.

Limits: at most 512 printable ASCII characters. Anything else → `400`.

## Option 2 — PKCE on the login_code

1. Backend generates a random `code_verifier` (43–128 chars of
   `A-Z a-z 0-9 - . _ ~`), keeps it in the user's session, and computes
   `code_challenge = BASE64URL(SHA256(code_verifier))` (no padding).
2. Send it: `GET /oauth/google/login?client_id=…&code_challenge=<c>&code_challenge_method=S256`
   (`code_challenge_method` may be omitted; only `S256` is accepted).
3. At exchange, include the verifier:

   ```json
   POST /api/v1/auth/oauth/exchange
   { "client_id": "…", "login_code": "…", "code_verifier": "<verifier>" }
   ```

Rules:

| Login sent `code_challenge` | Exchange sends `code_verifier` | Result |
|---|---|---|
| no  | no  | works (legacy behaviour) |
| yes | matching | works |
| yes | missing or wrong | `401 invalid or expired login code` — the code is **not** consumed, so a wrong guess cannot burn the real user's code |
| no  | yes | `401` (no downgrade) |

A malformed `code_challenge` (not 43 base64url chars), or a method other than
`S256`, is rejected at login start with `400`.

## Which one?

`state` is enough when your callback handler can read the user's cookie.
PKCE additionally means that even a leaked callback URL is useless without the
verifier, which never leaves your backend. Use PKCE when the callback lands on a
different origin than your session cookie, or when you want defence in depth.

## Implementation notes

- When `state` is echoed, the callback URL is rebuilt with standard query
  encoding, so any query parameters already present on your allow-listed
  `redirect` may be re-ordered or re-encoded. Compare individual query
  parameters (`state`, `login_code`), never the raw callback URL string.
- On the platform side, sending `state` (and ideally `code_challenge`) is not
  enough on its own: the callback handler must verify them, otherwise the
  login CSRF remains open in your application.

## Application MFA on social sign-in (`federated_mfa`, issue #194)

By default (`federated_mfa: "trust"`) a social sign-in is accepted as is: the
exchange returns the token pair and the application's MFA policy is not
applied. That is unchanged for every existing application.

An application can opt in with `federated_mfa: "enforce"`
(`PUT /api/v1/applications/{appID}/mfa`, see `APP_MFA_INTEGRATION.md` §2.3b).
The same application MFA gate as password login then runs at the exchange,
and **`POST /api/v1/auth/oauth/exchange` can answer with a challenge instead of
tokens** — for opted-in applications only:

| Status | Body | Meaning → next step |
|---|---|---|
| 200 | `access_token`, `refresh_token`, … | signed in (nothing due) |
| 200 | `requires_otp: true, otp_session_token, methods[], expires_in` | user has a second factor → `POST /api/v1/auth/login/otp` |
| 403 | `mfa_enrollment_required: true, enrollment_token, allowed_methods[], expires_in` | app requires MFA, user has none → `/api/v1/auth/login/mfa/enroll` or `/email`, then `/activate` |
| 503 | `error: "app_mfa_unavailable"` | a second factor is due but the server cannot run it; no tokens |

Notes:

- Branch on `requires_otp` / `mfa_enrollment_required`, exactly as for
  `/auth/apps/login`. Do not treat the 200 challenge as a token response.
- The `login_code` is consumed by the exchange whether tokens or a challenge
  come back; it cannot be exchanged again to skip the challenge.
- The completed session still carries `gty: "social"`; its `amr` adds
  `otp` and `mfa` to `fed`.
- The switch (`mfa_enabled`), `mode` and `allowed_methods` apply exactly as for
  password login. With `trust`, none of them apply to social sign-in.
- Enable `enforce` only after your callback handler understands the challenge
  responses above.
