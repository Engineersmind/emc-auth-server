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
