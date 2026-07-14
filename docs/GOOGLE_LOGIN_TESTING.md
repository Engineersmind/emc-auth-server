# Google Login — Manual Live Testing Checklist (issue #64)

Automated coverage: unit tests (`internal/auth/google_test.go`) and integration
tests against an httptest-stubbed Google (`internal/auth/google_integration_test.go`,
requires `DATABASE_URL` + `REDIS_URL`). The real browser + consent-screen flow
cannot be automated — run this checklist against live Google before each release
that touches the flow, and attach the filled-in copy to the PR.

## Prerequisites

- [ ] Google Cloud OAuth client (Web application) with redirect URI
      `<APP_BASE_URL>/oauth/google/callback` registered exactly
- [ ] Consent screen configured; testing account listed as Test user (dev) or
      app published (production)
- [ ] `.env`: `OAUTH_CLIENT_SECRET_ENCRYPTION_KEY` set (64 hex chars);
      `GLOBAL_CORS_ORIGINS` includes the tenant app origin
- [ ] Application created + provider config saved via
      `PUT /api/v1/applications/{id}/identity-providers/google`
      (`redirect_allow` contains the tenant app callback URL exactly)
- [ ] Tenant app served (e.g. `demo-tenant-app/` on port 3000)

## Happy paths

- [ ] **First login (JIT provision):** consent screen shows → callback lands on
      tenant app with `login_code` → exchange returns access+refresh pair →
      `GET /auth/me` shows the Google email, correct tenant/app scoping
- [ ] **Repeat login:** same Google account again → succeeds; application user
      list still shows exactly ONE user for that email (identity match, no dup)
- [ ] **Default role:** with an application role marked `is_default`, a fresh
      Google user receives it (JWT `role` + `permissions` populated)
- [ ] **Auto-link:** existing app-scoped password user with VERIFIED email +
      same Google email → same user id after Google login;
      `auth.google_account_linked` audit row written

## Security / failure paths

- [ ] **Replay login_code:** second `POST /auth/oauth/exchange` with the same
      code → 401
- [ ] **Replay callback:** re-open the callback URL from browser history → 400
      invalid/expired (state single-use)
- [ ] **Denied consent:** click Cancel on Google → redirected back with
      `error=access_denied`; no user row created
- [ ] **Evil redirect:** `/oauth/google/login?...&redirect=https://evil.com` →
      400, never redirects
- [ ] **Unverified local account:** app-scoped password user with
      `email_verified=false` + same Google email → `error=account_conflict`,
      NOT auto-linked (takeover gate)
- [ ] **Provider disabled mid-flight:** disable config while sitting on the
      consent screen, then approve → generic `error=login_failed`
- [ ] **Logs redacted:** server log line for the callback reads
      `/oauth/google/callback?[redacted]` — no `code=`/`state=` anywhere
- [ ] **Audit trail:** `auth.google_login` (and `_failed` for the failure
      cases above) present in `GET /api/v1/audit-logs`
- [ ] **Rate limit:** >5 rapid hits on `/oauth/google/login` from one IP → 429

## Operational

- [ ] **Unlink guard:** `DELETE /api/v1/users/{id}/identities/google` on a
      Google-only user → 409; on a password+Google user → 204, then Google
      login re-links or re-provisions per resolution rules
- [ ] **Key rotation drill (staging):** move key to `..._PREVIOUS`, set new
      key, restart → existing logins still work; re-save a provider config →
      row re-encrypted under the new key

| Field | Value |
|---|---|
| Date tested | |
| Tester | |
| Environment / APP_BASE_URL | |
| Commit | |
| Result | PASS / FAIL (attach notes) |
