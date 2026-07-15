# GitHub Login — Manual Live Testing Checklist (issue #66)

Automated coverage: unit tests (`internal/auth/github_test.go`) and integration
tests against an httptest-stubbed GitHub (`internal/auth/github_integration_test.go`,
requires `DATABASE_URL` + `REDIS_URL`). The real browser + consent flow cannot
be automated — run this checklist against live GitHub before each release that
touches the flow, and attach the filled-in copy to the PR.

GitHub-specific notes (vs. the Google checklist):
- GitHub OAuth Apps have **no OIDC** — identity comes from `GET /user` +
  `GET /user/emails`; the login email is the **verified primary** address.
- GitHub **ignores PKCE** for OAuth Apps. The params are still sent for code
  uniformity, but the protections are the single-use state + client secret —
  do not treat PKCE as a control on this flow.
- One callback URL per OAuth App — separate dev/prod requires two OAuth Apps.

## Prerequisites

- [ ] GitHub OAuth App (Settings → Developer settings → OAuth Apps) with
      Authorization callback URL `<APP_BASE_URL>/oauth/github/callback`
      registered exactly; Device Flow left DISABLED
- [ ] `.env`: `OAUTH_CLIENT_SECRET_ENCRYPTION_KEY` set (64 hex chars);
      `GLOBAL_CORS_ORIGINS` includes the tenant app origin
- [ ] Application created + provider config saved via
      `PUT /api/v1/applications/{id}/identity-providers/github`
      (`redirect_allow` contains the tenant app callback URL exactly)
- [ ] Tenant app served (e.g. `demo-tenant-app/` on port 3000)

## Happy paths

- [ ] **First login (JIT provision):** GitHub authorize screen shows scopes
      `read:user` + `user:email` → callback lands on tenant app with
      `login_code` → exchange returns access+refresh pair → `GET /auth/me`
      shows the GitHub primary email (lowercased), correct tenant/app scoping
- [ ] **Private email:** with "Keep my email addresses private" enabled on the
      GitHub account, login still succeeds using the verified primary address
- [ ] **Repeat login:** same GitHub account again → succeeds; application user
      list still shows exactly ONE user for that email (identity keyed on the
      numeric GitHub id, no dup)
- [ ] **Username change survives:** rename the GitHub account (or verify via
      integration test) → login still resolves to the same user
- [ ] **Default role:** with an application role marked `is_default`, a fresh
      GitHub user receives it (JWT `role` + `permissions` populated)
- [ ] **Auto-link:** existing app-scoped password user with VERIFIED email +
      same GitHub primary email → same user id after GitHub login;
      `auth.github_account_linked` audit row written

## Security / failure paths

- [ ] **Replay login_code:** second `POST /auth/oauth/exchange` with the same
      code → 401
- [ ] **Replay callback:** re-open the callback URL from browser history → 400
      invalid/expired (state single-use)
- [ ] **Denied consent:** click Cancel on GitHub → redirected back with
      `error=access_denied`; no user row created
- [ ] **Evil redirect:** `/oauth/github/login?...&redirect=https://evil.com` →
      400, never redirects
- [ ] **Unverified local account:** app-scoped password user with
      `email_verified=false` + same GitHub email → `error=account_conflict`,
      NOT auto-linked (takeover gate)
- [ ] **Provider disabled mid-flight:** disable config while sitting on the
      authorize screen, then approve → generic `error=login_failed`
- [ ] **Logs redacted:** server log line for the callback reads
      `/oauth/github/callback?[redacted]` — no `code=`/`state=` anywhere;
      no GitHub access token in any log line
- [ ] **Audit trail:** `auth.github_login` (and `_failed` for the failure
      cases above) present in `GET /api/v1/audit-logs`
- [ ] **Rate limit:** >5 rapid hits on `/oauth/github/login` from one IP → 429

## Operational

- [ ] **Unlink guard:** `DELETE /api/v1/users/{id}/identities/github` on a
      GitHub-only user → 409; on a password+GitHub user → 204, then GitHub
      login re-links or re-provisions per resolution rules
- [ ] **Pre-production:** OAuth App transferred from personal account to the
      org account; client secret ROTATED (dev secret was shared in chat) and
      updated via the admin endpoint
