# Migrating `POST /api/v1/auth/token` → `POST /oauth/token`

> **Nothing is broken today.** `POST /api/v1/auth/token` still works exactly as it always
> has — same request, same response, same status codes. This guide exists so you can move
> at your own pace before it is eventually removed.
>
> Tracking: CLAUDE.md deferred **#21**, issue **#132**.

## Why move

`POST /oauth/token` is the RFC 6749 token endpoint. It is what the OIDC discovery document
advertises as `token_endpoint`, so any standards-based OIDC/OAuth client library finds it
automatically. `/api/v1/auth/token` is a JSON-shaped alias that predates it and supports
only one grant.

**The tokens are identical.** Both endpoints call the same `IssueServiceToken` with the same
audience resolution, so the access token you end up holding — its claims, its audience, its
lifetime — does not change. This is a transport migration, not a credential migration.

## How to tell you are calling the deprecated one

Every response from `/api/v1/auth/token` now carries three advisory headers:

```http
Deprecation: @1789430400
Sunset: Thu, 31 Dec 2026 23:59:59 GMT
Link: </oauth/token>; rel="successor-version", <.../docs/AUTH_TOKEN_MIGRATION.md>; rel="deprecation"
```

`Deprecation` (RFC 9745) and `Sunset` (RFC 8594) are metadata only — they change no status
code and no response body, and a client that ignores them is entirely unaffected.

> The `Sunset` date is a **proposal under review**, not a commitment. It will not move
> earlier without notice to the consumers named below.

## ⚠️ Check this first — the one thing that can refuse you

`/oauth/token` enforces a per-client grant allowlist that `/api/v1/auth/token` does not.
The column backing it, `oauth_clients.grant_types`, defaults to:

```sql
grant_types TEXT[] NOT NULL DEFAULT '{authorization_code,refresh_token}'   -- migration 00032
```

**That default does not include `client_credentials`.** So a client that works fine today can
receive `unauthorized_client` from `/oauth/token` until an operator adds the grant. Check
before you switch a single line of code:

```sql
SELECT t.slug AS tenant, c.name, c.client_id, c.grant_types,
       ('client_credentials' = ANY(c.grant_types)) AS ready_to_migrate
FROM   oauth_clients c JOIN tenants t ON t.id = c.tenant_id
WHERE  c.deleted_at IS NULL
ORDER  BY t.slug, c.name;
```

If `ready_to_migrate` is `false`, an operator must add the grant through the applications
admin API before that client can use `/oauth/token`. Nothing about its current
`/api/v1/auth/token` usage is affected in the meantime.

**Status as of 2026-09-15:** all three live clients — `InsuredDesk_DEV`,
`InsuredDesk_PROD_AGENCY_PRINCIPAL` and `InsuredDesk_PROD_AGENT`, all in tenant
`insureddesk` — already carry `grant_types = {client_credentials}` and are ready to migrate
with no operator action.

## The actual change: JSON body → form encoding

That is the whole of it. Credentials stay in the `Authorization: Basic` header.

### Before

```bash
curl -X POST https://<host>/api/v1/auth/token \
  -H "Authorization: Basic $(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)" \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"client_credentials"}'
```

### After

```bash
curl -X POST https://<host>/oauth/token \
  -H "Authorization: Basic $(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'grant_type=client_credentials'
```

Note the path has **no `/api/v1` prefix** — `/oauth/token` is top-level, like the rest of the
OAuth surface.

### Response

Unchanged in the fields you already read:

```json
{ "access_token": "eyJ...", "token_type": "Bearer", "expires_in": 3600 }
```

No refresh token, on either endpoint — RFC 6749 §4.4.3 says `client_credentials` does not get
one.

## Differences worth knowing

| | `/api/v1/auth/token` (deprecated) | `/oauth/token` |
|---|---|---|
| Encoding | JSON body | form-encoded (RFC 6749) |
| Path prefix | `/api/v1` | top-level |
| Credentials | `Authorization: Basic` only | `Authorization: Basic` **or** `client_secret_post` |
| Grants | `client_credentials` only | `authorization_code`, `refresh_token`, `client_credentials` |
| Grant allowlist | not enforced | **enforced** (`AllowsGrant`) — see the warning above |
| Token minted | identical | identical |
| In discovery document | no | yes, as `token_endpoint` |

## Requesting a specific audience

Both endpoints accept an audience and resolve it identically (issue #131). On `/oauth/token`
it is a form field:

```bash
-d 'grant_type=client_credentials&audience=api://insureddesk/insureddesk-dev'
```

Omit it and the server assigns your application's own audience — the common case, and the one
that needs no change. A client may only request an audience it holds a grant for; anything
else returns `invalid_target`.

> **Scopes:** a grant with an empty `scopes` array permits no scopes at all (`FilterScopes` is
> fail-closed by design). If you start passing an explicit `audience` **and** expect scopes in
> the token, confirm the grant's `scopes` are populated first — all three InsuredDesk grants
> are currently `{}`.

## Checklist

- [ ] Confirm `client_credentials` is in your client's `grant_types` (query above)
- [ ] Change the URL to `/oauth/token` — drop the `/api/v1` prefix
- [ ] Change `Content-Type` to `application/x-www-form-urlencoded`
- [ ] Send `grant_type=client_credentials` as a form field, not JSON
- [ ] Keep the `Authorization: Basic` header exactly as it is
- [ ] Verify the `Deprecation` header is gone from your responses — that is your proof the
      migration actually took effect

## Questions

Raise them on issue #132.
