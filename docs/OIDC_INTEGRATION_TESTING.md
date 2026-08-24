# OIDC Integration Testing

How to satisfy yourself that the authorization-code + PKCE flow works before an
integrator such as EMC Insurance builds against it — and, just as important, what
to tell them about the places where this server is deliberately narrower than the
spec they will read.

Every command, response, and error string below was executed against merged
`master` (`ee2a9db`, issues **#7a → #6 → #7b** complete) on **2026-08-20**. Where
a result is a design decision rather than a bug it says so.

**Companion docs:** `GOOGLE_LOGIN_TESTING.md` (same shape, social login),
`CLIENT_CREDENTIALS_FLOW.md` (M2M consumers), `SPRINT_ISSUE_7B_PLAN.md` (why
discovery looks the way it does).

---

## 0. Why a manual checklist at all

The unit and integration suites already cover this flow, and CI is green. They
cannot answer the question an integrator actually asks, which is *"will my OIDC
library work against you?"* — because the tests and the server were written by the
same people, from the same reading of the spec. A shared misreading passes both.

Three tiers of evidence, in increasing strength:

| Tier | What it proves | Effort |
|---|---|---|
| 1. Manual walk (§2–§4) | The flow is correct and the error behaviour is sane | ~30 min |
| 2. A real OIDC **library** as the client (§5) | Their *class of client* interoperates | ~2 h |
| 3. OpenID Foundation conformance suite (§6) | Provable conformance, edge cases included | ~1 day |

`demo-tenant-app/` is **not** tier 2. It is two hand-written HTML files, so it
shares our assumptions — it can only confirm what we already believe.

---

## 1. Throwaway environment

Never run this against the dev database. `testhelper.CleanupTables` and the seed
path both truncate, and several test helpers share one database (see CLAUDE.md
deferred #8). Non-default ports, own database, own Redis DB index:

```bash
docker run -d --name emc-oidc-pg \
  -e POSTGRES_USER=emc_auth -e POSTGRES_PASSWORD=password -e POSTGRES_DB=emc_auth_oidc \
  -p 55433:5432 postgres:16-alpine
docker run -d --name emc-oidc-redis -p 56380:6379 redis:7-alpine

export DATABASE_URL='postgres://emc_auth:password@localhost:55433/emc_auth_oidc?sslmode=disable'
export REDIS_URL='redis://localhost:56380/0'
export JWT_ISSUER='http://localhost:9099'
export APP_BASE_URL='http://localhost:9099'
export PORT=9099
export SEED_ADMIN_EMAIL='admin@emc.local'
export SEED_ADMIN_PASSWORD='TestAdmin123!'
export TOTP_ENCRYPTION_KEY='0000000000000000000000000000000000000000000000000000000000000000'
export OAUTH_CLIENT_SECRET_ENCRYPTION_KEY='1111111111111111111111111111111111111111111111111111111111111111'
export ENV=development

go build -o emc-auth ./cmd/server && ./emc-auth
```

`APP_BASE_URL` is what discovery advertises, so it must be the host the client
will really reach. Point it at `localhost` and hand the document to a client on
another machine and every endpoint in it is wrong.

Dummy data — a confidential web client and one end user:

```bash
ADMIN=$(curl -s -X POST localhost:9099/api/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"admin@emc.local","password":"TestAdmin123!"}' | jq -r .access_token)

curl -s -X POST localhost:9099/api/v1/applications -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' -d '{
    "name":"EMC Insurance Portal (test)","app_type":"web",
    "redirect_uris":["http://localhost:3000/callback"],
    "scopes":["openid","profile","email","offline_access"],
    "require_pkce":true,"first_party":true}'
# -> {"id":1,"client_id":"app_...","client_secret":"..."}

BASIC=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64 -w0)

curl -s -X POST localhost:9099/api/v1/auth/apps/register -H "Authorization: Basic $BASIC" \
  -H 'Content-Type: application/json' -d '{
    "email":"policyholder@emcinsurance.test","password":"Policy123!Pass",
    "first_name":"Asha","last_name":"Raman"}'
```

Two gotchas that cost time the first run: `/auth/apps/register` requires the
client credentials as an **`Authorization: Basic`** header (a JSON body with
`client_id`/`client_secret` is rejected), and `POST /api/v1/tenants` requires
`owner_email` alongside `name` and `slug`. `PUT /applications/{id}/mfa` takes
`{"mode": ...}`, not `mfa_policy`.

---

## 2. Discovery and JWKS

```bash
curl -s localhost:9099/tenants/emc/.well-known/openid-configuration | jq
curl -s localhost:9099/tenants/emc/.well-known/jwks.json | jq
```

Verified output — check each line, because a client library will:

| Field | Value | Why it matters |
|---|---|---|
| `issuer` | `http://localhost:9099/tenants/emc` | Per-tenant. Must be **byte-identical** to the `iss` in the ID token; libraries compare exactly, so one trailing slash fails the whole flow |
| `jwks_uri` | `.../tenants/emc/.well-known/jwks.json` | Per-tenant, and the keys really are distinct per tenant (verified: `emc` and `rival` return different `kid`s) |
| `response_types_supported` | `["code"]` | No implicit, no hybrid |
| `code_challenge_methods_supported` | `["S256"]` | No `plain` — a client offering only `plain` cannot integrate |
| `grant_types_supported` | `authorization_code`, `refresh_token`, `client_credentials` | Advertised server-wide; **per-client allow-lists still apply** (§4) |
| `token_endpoint_auth_methods_supported` | `client_secret_basic`, `client_secret_post`, `none` | |
| `id_token_signing_alg_values_supported` | `["RS256"]` | |
| `claims_supported` | includes `at_hash`, `auth_time`, `nonce` | These are genuinely emitted, not aspirational — see §3 |

Caching is deliberate and observable:

```
Cache-Control: public, max-age=300
ETag: "_fpOP1P6h6HU4PlaLKs4PA"
```

All four RFC 9110 §13.1.2 forms were verified to return **304**: exact
(`"..."`), weak (`W/"..."`), wildcard (`*`), and a list with OWS
(`"other",   W/"..."`). A stale validator returns **200**. An unknown tenant
returns **404** `{"error":"tenant not found"}`.

> Tell integrators the 300s number out loud. After a client-config change or a
> key rotation their library serves the old document until the TTL expires.

---

## 3. The happy path, end to end

The hosted login is two steps: `GET /oauth/authorize` renders a form whose only
hidden field is an opaque `request` handle, and the credentials go to
`POST /oauth/authorize/login`. Scripted driver in Appendix A.

```
GET /oauth/authorize?response_type=code&client_id=app_...
    &redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback
    &scope=openid%20profile%20email%20offline_access
    &state=...&nonce=...&code_challenge=...&code_challenge_method=S256
-> 200, form with hidden "request" handle (64 hex chars)

POST /oauth/authorize/login   request=<handle>&email=...&password=...
-> 302 Location: http://localhost:3000/callback?code=<64 hex>&state=<echoed verbatim>

POST /oauth/token  (Authorization: Basic base64(client_id:client_secret))
    grant_type=authorization_code&code=...&redirect_uri=...&code_verifier=...
-> 200  Cache-Control: no-store   Pragma: no-cache
   { access_token, token_type: "Bearer", expires_in: 900,
     refresh_token, id_token, scope: "openid profile email offline_access" }
```

### Verify the ID token the way a library would

Do this **offline against JWKS**, not by trusting the server. Appendix B is a
~40-line pure-Python RS256 verifier with no dependencies — deliberately not our
Go code, so it is independent evidence. Observed claims:

```json
{
  "iss": "http://localhost:9099/tenants/emc",
  "aud": ["app_b5bjo_0oXbgfl1FbiD27qQ"],
  "sub": "2",
  "nonce": "<echoed>",
  "auth_time": 1787164452,
  "at_hash": "ou9wNyPNdNGE1gvpIl3o2g",
  "email": "policyholder@emcinsurance.test",
  "email_verified": false,
  "name": "Asha Raman", "given_name": "Asha", "family_name": "Raman",
  "updated_at": 1787164413,
  "exp": 1787165365, "iat": 1787164465,
  "jti": "749ec2e3-0302-479f-8dd1-339c30cffc4c"
}
```

All eleven assertions pass:

- signature verifies against the JWKS key named by `kid`
- `alg` is `RS256` (not `none`, not `HS256`)
- `iss` equals the discovery `issuer` exactly
- **`aud` equals the `client_id`** — OIDC Core §2, and the single most important
  one: get this wrong and no library on earth accepts the token
- `nonce` echoed exactly
- `at_hash` equals base64url(left 128 bits of SHA-256(access_token)) — **checked
  independently**, matches. Strict Java/Spring and MSAL clients validate this; a
  wrong `at_hash` breaks them while leaving looser clients working, which is the
  worst kind of bug to find in production
- `sub`, `exp` in future, `iat` not in future, `auth_time`, `email` present

`GET /oauth/userinfo` with the access token returns the same `sub` (`"2"`) plus
the profile claims. `sub` matching between ID token and userinfo is required by
OIDC Core §5.3.2 and is verified.

### The access token is a different animal — read this before building a resource server

```json
{ "aud": ["emc-auth-api"], "app_id": 1, "tenant_id": 1, "user_id": 2,
  "sid": 18, "scope": "openid profile email offline_access",
  "permissions": [], "role": "", "iss": "http://localhost:9099/tenants/emc" }
```

`aud` carries the **token type**, not the API being called. This is intentional
(issue #84: it stops an M2M token acting as a user token) and is tracked as
CLAUDE.md deferred #10. The consequence for an integrator with their own
resource server is specific and easy to get wrong:

- **Do not** configure their JWT library to expect `aud = <their API>`. It never
  will be.
- Validate `iss` + signature via the tenant's JWKS, then check `app_id`
  themselves. **Nothing validates `app_id` automatically** — every library
  validates `aud`, no library knows about `app_id`.

---

## 4. Negative tests — the matrix that matters

All verified. The error strings are what the server really returns, so this table
doubles as a debugging reference.

### Authorize endpoint

Correct RFC 6749 §4.1.2.1 split: if the `redirect_uri` cannot be trusted, render
a page; otherwise redirect the error back with `state` preserved.

| Case | Result |
|---|---|
| Unregistered `redirect_uri` | **400 HTML page**, no `Location` header — never redirects to an unregistered URI. Page carries `<meta name="referrer" content="no-referrer">` |
| Unknown `client_id` | **400 HTML page**, no redirect |
| Missing `code_challenge` (client has `require_pkce`) | **302** `error=invalid_request&error_description=code_challenge+is+required&state=s` |
| `code_challenge_method=plain` | **302** `error=invalid_request` … `code_challenge_method must be S256` |
| `response_type=token` | **302** `error=unsupported_response_type` … `only response_type=code is supported` |
| **Nonce replay** (same nonce twice) | 1st: code issued. 2nd: **302** `error=invalid_request` … `nonce has already been used — generate a fresh nonce per authorization` |
| MFA `mode=required`, user never enrolled | **403 HTML** "Two-factor setup required", **no redirect back** — see §7 |

### Token endpoint

| Case | Result |
|---|---|
| Happy path | 200, `no-store` + `no-cache` set |
| Code replay | 400 `invalid_grant` `authorization code is invalid or expired` |
| Unknown code | 400 `invalid_grant`, **identical message** — no oracle |
| Wrong `code_verifier` | 400 `invalid_grant` `code_verifier does not match the code_challenge` |
| Missing `code_verifier` | 400 `invalid_grant` |
| Wrong `redirect_uri` | 400 `invalid_grant` `authorization code is invalid or expired` ← see the debugging note below |
| **Another client redeems this code** | 400 `invalid_grant`; the real owner can **still** redeem it afterwards (200) — the code is bound to its client and a foreign attempt does not consume it |
| Refresh rotation | 200, new `refresh_token` issued, old one 400 `invalid_grant` on reuse |
| Wrong client secret | **401** `invalid_client` |
| `client_credentials` on a client without that grant | 400 `unauthorized_client` `this client is not permitted to use the client_credentials grant` |

### Revocation (`/oauth/revoke`)

| Case | Result |
|---|---|
| Revoke a valid refresh token | **200**; the token then fails 400 `invalid_grant` |
| Revoke an unknown token | **200** — RFC 7009 §2.2 forbids the oracle |
| No client authentication | **401** `invalid_client` — RFC 7009 §2.1, fixed in PR #107 |

### Bearer 401s

`WWW-Authenticate: Bearer realm="emc-auth"`, plus `Cache-Control: no-store` and
`Pragma: no-cache` (RFC 6750 §3, added in `6c27ee6`). The challenge never reveals
*why* the token failed — a wrong-audience token is indistinguishable from a
malformed one (issue #84).

> **Debugging note worth its own line.** A wrong `redirect_uri` at the token
> endpoint reports `authorization code is invalid or expired`, because the code is
> consumed before the redirect comparison runs. If an integrator reports "code
> invalid or expired" on their *very first* exchange, suspect a `redirect_uri`
> mismatch or a burned code (below), **not** an expiry. Say this in the
> integration guide; it will save a day.

---

## 5. Point a real library at it

Write ~40 lines in whatever EMC Insurance actually uses — `openid-client` (Node),
`authlib` (Python), Spring Security `oauth2Login` with `issuer-uri` (Java), MSAL.
Give it only the discovery URL, `client_id`, `client_secret`, `redirect_uri`.

The pass criterion is strict: **it completes with zero custom overrides.** Every
workaround needed — a hardcoded endpoint, a disabled `nonce` or `at_hash` check, a
relaxed `iss` comparison — is a bug the integrator will hit and attribute to us.

Ask them for their library and version *before* the pilot, and check it against
§7 first. Most of the friction is knowable in advance.

---

## 6. Being sure: the conformance suite

The [OpenID Foundation conformance suite](https://openid.net/certification/) is
free, runs in Docker locally, and exercises the Basic OP profile including cases
no hand-written client reaches. Run the `oidcc-basic-certification-test-plan`
against a throwaway tenant.

This is the only tier that produces *evidence* rather than confidence, and it is
the right thing to do before the first external integrator, not after.

---

## 7. Known constraints — the integrator questionnaire

Verified behaviour, not speculation. Work through this list **with** the
integrator before they write code; each item has broken a real integration
somewhere.

1. **No RP-initiated logout.** There is no `end_session_endpoint` in the
   discovery document, so OIDC logout is not available — sessions must be ended
   locally. Ask first: many enterprise stacks assume it exists.
2. **A failed token exchange consumes the code.** Verified: one wrong
   `code_verifier`, or a wrong `redirect_uri`, kills the code — the subsequent
   *correct* attempt returns `invalid_grant`. Fail-closed is the right call (it
   also blocks PKCE brute-forcing), but the client must **restart the flow**, not
   retry the exchange. A cross-client attempt is the exception: it does not
   consume the code.
3. **Nonce is burn-on-use** (#7b / audit FED-3). The browser back button, a
   duplicated tab, or a library that retries an authorize request with the same
   nonce all produce `invalid_request`. **Test the back button explicitly.**
4. **`offline_access` is decorative.** Verified: `scope=openid` alone still
   returns a `refresh_token`. Nothing breaks, but a client that gates its
   refresh logic on having been granted `offline_access` will find the scope
   absent from the response while the token is present.
5. **No `id_token` on refresh.** OIDC Core §12.2 permits this (it is MAY), but
   clients that re-read user claims from a refreshed ID token get nothing. They
   must call `/oauth/userinfo` instead.
6. **The refresh grant is unauthenticated when `client_id` is omitted — even for
   a confidential client.** Verified: a `web` client with a secret can refresh
   with no `Authorization` header at all (200). This is deliberate for public
   clients, which have no secret by definition, and the refresh token is
   single-use with family revocation on replay. But the doc-comment in
   `oauth_token.go` claims "client authentication is required whenever the client
   is confidential", and the code cannot enforce that: `refresh_tokens` has no
   `application_id`, so the server cannot tell whose token it is. Same root cause
   as CLAUDE.md deferred #22. **Consequence to state plainly:** for a
   confidential client, a stolen refresh token is sufficient on its own — the
   secret adds nothing on this path. Either close #22 or correct the comment.
7. **MFA `required` + a never-enrolled user is a dead end.** Verified: HTTP 403,
   "Two-factor setup required", no redirect back to the client. If the integrator
   wants required MFA, enrolment must exist in *their* application first
   (CLAUDE.md deferred #20).
8. **Third-party clients are refused.** `first_party = false` gets
   `error=consent_required` because no consent screen exists (deferred #19).
   Fine for a tenant-owned application — but verify the row, because the failure
   arrives only at the first login attempt.
9. **Same email + same password in two tenants = permanent login failure**
   (deferred #17). The error is indistinguishable from a wrong password. Password
   reuse across tenants is exactly what real users do.
10. **Do not route them to `/auth/refresh`.** The app-scoped refresh endpoint has
    a known delivery bug and is destructive on retry. `POST /oauth/token` with
    `grant_type=refresh_token` is the supported path. Likewise `/auth/token` is a
    deprecated alias of `/oauth/token` (deferred #21).
11. **Per-client grant allow-lists override discovery.** `grant_types_supported`
    is server-wide; a client still gets `unauthorized_client` for a grant its own
    row does not permit. Verified with `client_credentials` on a `web` client.
12. **Access tokens carry the internal `permissions` array** (deferred #23).
    Harmless while every client is first-party; it must be filtered before
    genuinely third-party clients exist.

---

## Appendix A — flow driver

Drives one authorize + login round trip and returns the callback query string.
Stdlib only. Saves re-deriving the two-step form each time.

```python
"""python flow.py '{"nonce":"reuse-me"}'  -> prints stage/status/location/verifier"""
import base64, hashlib, http.cookiejar, json, os, re, sys, urllib.parse, urllib.request

B = 'http://localhost:9099'
CLIENT_ID = 'app_...'            # paste yours
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None

def run(nonce=None, redirect='http://localhost:3000/callback',
        scope='openid profile email offline_access',
        email='policyholder@emcinsurance.test', password='Policy123!Pass'):
    ver = b64(os.urandom(32))
    ch  = b64(hashlib.sha256(ver.encode()).digest())
    st, no = b64(os.urandom(16)), nonce or b64(os.urandom(16))
    q = urllib.parse.urlencode({
        'response_type': 'code', 'client_id': CLIENT_ID, 'redirect_uri': redirect,
        'scope': scope, 'state': st, 'nonce': no,
        'code_challenge': ch, 'code_challenge_method': 'S256'})
    op = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect)
    try:
        html = op.open(f'{B}/oauth/authorize?{q}').read().decode()
    except urllib.error.HTTPError as e:                    # 400 error page
        return {'stage': 'authorize', 'status': e.code,
                'location': e.headers.get('Location'), 'body': e.read().decode()[:300],
                'verifier': ver, 'state': st, 'nonce': no}
    m = re.search(r'name="request"[^>]*value="([^"]*)"', html)
    if not m:                                              # e.g. a 302 error redirect
        return {'stage': 'authorize', 'status': 200, 'body': html[:400],
                'verifier': ver, 'state': st, 'nonce': no}
    data = urllib.parse.urlencode(
        {'request': m.group(1), 'email': email, 'password': password}).encode()
    try:
        r = op.open(f'{B}/oauth/authorize/login', data=data)
        return {'stage': 'login', 'status': r.status, 'body': r.read().decode()[:400],
                'verifier': ver, 'state': st, 'nonce': no}
    except urllib.error.HTTPError as e:                    # 302 success, or 403 MFA
        return {'stage': 'login', 'status': e.code, 'location': e.headers.get('Location'),
                'body': e.read().decode()[:400], 'verifier': ver, 'state': st, 'nonce': no}

if __name__ == '__main__':
    print(json.dumps(run(**(json.loads(sys.argv[1]) if len(sys.argv) > 1 else {})), indent=1))
```

## Appendix B — independent ID-token verifier

No third-party packages, and deliberately not our Go verifier: RSA PKCS#1 v1.5 by
hand, so a passing result is independent evidence rather than a restatement of
what the server already believes.

```python
"""python verify.py tokens.json <jwks_url> <client_id> <issuer> <nonce>"""
import base64, hashlib, json, sys, time, urllib.request

def b64u(s): return base64.urlsafe_b64decode((s + '=' * (-len(s) % 4)).encode())
def i(b):    return int.from_bytes(b, 'big')

def verify_rs256(token, n, e):
    h, p, sig = token.split('.')
    em = pow(i(b64u(sig)), e, n).to_bytes((n.bit_length() + 7) // 8, 'big')
    digest = hashlib.sha256(f'{h}.{p}'.encode()).digest()
    prefix = bytes.fromhex('3031300d060960864801650304020105000420')   # SHA-256 DigestInfo
    return em == b'\x00\x01' + b'\xff' * (len(em) - 3 - len(prefix) - 32) \
                + b'\x00' + prefix + digest

tokfile, jwks_url, client_id, issuer, nonce = sys.argv[1:6]
d      = json.load(open(tokfile))
tok    = d['id_token']
hdr    = json.loads(b64u(tok.split('.')[0]))
claims = json.loads(b64u(tok.split('.')[1]))
key    = next(k for k in json.load(urllib.request.urlopen(jwks_url))['keys']
              if k['kid'] == hdr['kid'])
at_hash = base64.urlsafe_b64encode(
    hashlib.sha256(d['access_token'].encode('ascii')).digest()[:16]).rstrip(b'=').decode()
now = int(time.time())

for name, ok in [
    ('signature verifies against JWKS', verify_rs256(tok, i(b64u(key['n'])), i(b64u(key['e'])))),
    ('alg is RS256',                    hdr['alg'] == 'RS256'),
    ('iss == discovery issuer',          claims.get('iss') == issuer),
    ('aud == client_id',                claims.get('aud') in (client_id, [client_id])),
    ('nonce echoed',                    claims.get('nonce') == nonce),
    ('at_hash correct (Core 3.1.3.6)',  claims.get('at_hash') == at_hash),
    ('sub present',                     bool(claims.get('sub'))),
    ('exp in the future',               claims.get('exp', 0) > now),
    ('iat not in the future',           claims.get('iat', 0) <= now + 5),
]:
    print(('  PASS  ' if ok else '  FAIL  ') + name)
```

## Appendix C — teardown

```bash
docker rm -f emc-oidc-pg emc-oidc-redis
```

---

## Result of the 2026-08-20 run

Against `master` `ee2a9db`: **every conformance assertion passed** — discovery,
JWKS, per-tenant key separation, all four `If-None-Match` forms, the full
authorization-code + PKCE round trip, independent RS256 verification including
`at_hash`, userinfo `sub` agreement, refresh rotation with replay refusal,
revocation semantics, and the whole negative matrix in §4.

Nothing in §4 failed. Everything in §7 is a **design boundary or a tracked
deferred item**, not a regression — with one exception worth a decision before
the next integrator: **§7.6**, where the code cannot enforce what its own comment
promises. That is a comment fix or a #22 fix, and it should be a conscious choice
rather than a discovered surprise.
