# EMC Auth — Postman collection

Two files, both importable directly into Postman:

| File | What it is |
|---|---|
| `EMC-Auth.postman_collection.json` | 56 requests in 11 numbered folders |
| `EMC-Auth.local.postman_environment.json` | Local-dev environment (39 variables) |

The collection JSON is the **source of truth**. Edit it in Postman, export, and
commit the export alongside the code change that needed it.

---

## Setup (2 minutes)

1. Postman → Import → drop both files in.
2. Top-right environment selector → **EMC Auth — Local Dev**.
3. Check three variables: `baseUrl`, `adminEmail`, `adminPassword`.
4. Run the **`01 · Bootstrap`** folder.
5. Run anything else.

Start the server first:

```bash
docker compose up -d          # postgres, redis, mailpit
go run ./cmd/server
```

`baseUrl` defaults to `http://localhost:9090`. **It must match `APP_BASE_URL`** —
the JWKS URL is derived from that setting, not from `JWT_ISSUER`.

---

## The one thing to understand

**You almost never write `pm.environment.set()` by hand.**

The collection's post-response script (Collection → … → Edit → Scripts) runs after
*every* request and auto-captures known fields into the environment: `access_token`,
`refresh_token`, `client_id`, `client_secret`, `api_key`, `kid`, `jwks_url`, and
resource ids. It looks at the top level of the response plus `data`, `meta`, and
`tokens`, and at the first element of arrays.

To make a new field capturable, add **one line** to `CAPTURE_MAP` in that script.

The same script applies five baseline assertions to every request, whether or not
whoever added it remembered:

- no 5xx
- responds within 5s
- `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` present
- **no private key material** — no `PRIVATE KEY`, and if a JWK is present, none of
  RFC 7518's private RSA params (`d`, `p`, `q`, `dp`, `dq`, `qi`)
- no `jwt_secret` in the body

That last pair is why this is worth having as a habit rather than a one-off: the
worst possible bug in this server is publishing signing material, and now every
single response is checked for it on every run.

---

## Run order

See the **RUN ORDER** table in the collection description (visible in Postman when
you click the collection name). Short version: `01 · Bootstrap` first, always.

A 401 anywhere almost always means either `01` was skipped, or the 15-minute access
token expired. The pre-request script warns in the console when a token has under
60 seconds left.

---

## The three things Postman cannot do

Each is called out in its folder description too.

| What | Why | How |
|---|---|---|
| TOTP activation | needs a live 6-digit code | Run `05 → TOTP enroll`, paste the logged secret into an authenticator app, set `totpCode`, then run Activate |
| Password reset | token only exists in the email | Read it from Mailpit at http://localhost:8025, set `reset_token` |
| Social login | needs a browser redirect through Google | Use `demo-tenant-app/` — see `GOOGLE_LOGIN_INTEGRATION.md` |

---

## Adding endpoints — the daily practice

Five steps, all in the same PR as the code change. Full version in the collection
description; the short version:

1. Right **numbered** folder — order is part of the contract.
2. A description saying *why*, not just what.
3. At least one test.
4. New response field → add to `CAPTURE_MAP`, don't write a per-request setter.
5. Authorization boundary → add the negative case to `99`.

---

## CI

Folders `00`, `01`, `02`, and `99` are fast, read-mostly, and safe to run on every
build. The rest create and delete data, so point them at a disposable database.

```bash
npm install -g newman

newman run postman/EMC-Auth.postman_collection.json \
  -e postman/EMC-Auth.local.postman_environment.json \
  --folder "00 · Smoke" \
  --folder "01 · Bootstrap — run first" \
  --folder "02 · Signing Keys & JWKS (#95)" \
  --folder "99 · Negative & Security" \
  --reporters cli,junit --reporter-junit-export newman-results.xml
```

Newman shares the environment across folders in one run, so the chaining works the
same as in the UI.

---

## Notable route quirk

The admin group is mounted as `apiV1.Group("")` — an **empty** prefix. So admin
endpoints live at `/api/v1/tenants`, `/api/v1/users`, `/api/v1/signing-keys` and so
on, **not** `/api/v1/admin/...`. The first draft of this collection got that wrong
and every admin request 404'd. If you are adding an admin endpoint, copy the path
from an existing request rather than guessing.

---

## What folder 02 proves (issue #95)

Worth understanding, because it is the acceptance test for asymmetric signing:

- a freshly issued token is `RS256` and carries a `kid`
- that exact `kid` appears in the tenant's published JWKS
- the JWKS is fetchable from **any** origin without a 403 (it must be — arbitrary
  relying parties fetch it)
- it is cacheable (`Cache-Control` + `ETag`) and revalidates with a 304
- an unknown tenant gets a 404, not a hint that the tenant does not exist
- rotation: the incoming key is **published before it signs anything**, the outgoing
  key is retired but stays published, and a token issued *before* the rotation still
  authenticates afterwards

That last point is the zero-downtime guarantee. If it ever goes red, rotation is
logging users out.
