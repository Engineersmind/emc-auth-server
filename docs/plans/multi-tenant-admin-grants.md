# Multi-Tenant Administration Plan

Owners and co-owners become multi-tenant. One human, one credential, N grants.

---

## Implementation status

| Step | State | Artifacts |
|---|---|---|
| 0 — Phase 0 merge | **tooling ready, not run in prod** | `scripts/phase0_duplicate_admins.sql` |
| 1 — `admin_grants` | **done, verified against Postgres 16** | `migrations/00071_admin_grants.sql` |
| 2 — dual-write + escalation rules | **done** | `internal/admin/admin_grants_mirror.go`, `internal/admin/grant_escalation.go` (enforced in `InviteTenantAdmin` + `RemoveTenantAdminAs`) |
| 3 — flagged resolver + shadow | **done** | `internal/auth/admin_grants.go` |
| 4 — `POST /auth/tenant-context` | **done** | `internal/auth/tenant_context.go`, `internal/api/handlers/tenant_context.go` |
| 5 — `GET /auth/my-tenants` | **done** | same files; capability flags server-derived |
| 6 — `primary_admin_grant_id` cutover | column added and populated; 5 Go call sites still read the old column | — |
| 7 — frontend | **done** | `emc-auth-frontend`: `types/tenant-reach.ts`, `lib/api/tenant-reach.ts`, `queries/tenant-reach.ts`, `hooks/useTenantReach.ts`, `components/tenants/TenantSwitcher.tsx` (+ test), wired into `DashboardLayout` header |
| 8 — `Can()` consolidation | not started | — |
| 9 — drop legacy tables | later release | — |

**Verified against a live Postgres 16 + Redis:** migration Up/Down both apply cleanly; all four backfill verification blocks pass; 9 SQL invariants confirmed adversarially; all four many-to-many cardinalities proven (3 owners on one tenant, one owner across 3 tenants, N×M, and mixed tiers for one person). **Backend suites all green** — `internal/auth` (409s), `internal/admin` (163s), `internal/api`, `.../handlers`, `.../middleware` — including 21 new Go tests (12 reach/isolation + 9 escalation). **Frontend**: typecheck clean, lint clean (0 errors), 7 new tests green, 520/523 suite passing.

**Flaky tests, not regressions.** Backend: `TestSQLInjection_LoginPassword` trips a 3-second wall-clock assertion under load (confirmed identical with these changes stashed; no injection occurs — every payload returns `invalid credentials`); it passed once Redis was healthy. Frontend: 2 of 523 tests time out at 5s per run, a DIFFERENT pair each run (`client.test.ts`, `sessionIdentity.test.ts`, `ApplicationDetailPage.test.tsx`), all passing in isolation both with and without these changes. Vitest reports ~930s of environment setup on this machine, so the 5s per-test timeout is the cause.

### Endpoint shapes as built

```
GET  /api/v1/auth/my-tenants
  → { can_create_tenant, total, tenants: [
        { tenant_id, name, slug, role, app_count, is_primary,
          applications?,            // co_owner only; absent for an owner
          can: { create_application, manage_users, manage_roles, manage_admins } } ] }

POST /api/v1/auth/tenant-context   { tenant_id }
  → { access_token, refresh_token, token_type, expires_in, tenant_id }
```

`my-tenants` queries `admin_grants` by user id and **ignores the caller's current tenant**, which is what lets an owner of five tenants see all five immediately after login. `tenant-context` authenticates with the existing access token — no password, no second factor — and verifies the target against grants rather than trusting the body.

### Deviations from the plan as written

- **No per-grant `role_id`.** Deleted once it was confirmed a co-owner's permissions never vary (§1), removing the plan's riskiest unvalidated assumption (that every existing `users.role_id` matched its `admin_role`).
- **`invited_by` is not backfilled.** A co-owner now holds several grants, so "the inviter's grant" is ambiguous; any mapping is arbitrary. The column is provenance, never authorization, so NULL ("unknown, predates the model") is honest where a guess would misattribute who onboarded a privileged account. The 00062 chain survives in `tenant_admins`.
- **Per-tenant session revocation needed no change.** `RevokeAllSessionsTx` and the Redis denylist key (`userDenyKey(userID, tenantID)`) were already tenant-scoped. `users.token_version` is bumped account-wide but is verified by nothing (`jwt.go:50`), so it confers no cross-tenant effect.
- **The mirror is derived, not translated.** `mirrorAdminGrants` re-derives one administrator's whole picture from the legacy tables rather than translating each write. Idempotent, so a forgotten call leaves a stale mirror rather than a wrong one — and there are six write sites that would each have to stay correct forever otherwise.
- **`loadPermissions` cannot serve a foreign tenant.** It joins `users u ON u.role_id` and filters `u.tenant_id = $2`, so for an administrator whose home tenant is A it returns nothing for tenant B. `loadAdminPermissionsForTenant` resolves the target tenant's seeded `owner`/`co_owner` role instead. This was not in the plan and is the subtlest thing found during implementation.
- **Named `tenant-context`, not `switch-tenant`.** It changes which tenant the token names; the identity was already proven at login. The old name implied re-authentication.
- **Frontend: `usePermissions` needed no change.** It reads the CURRENT session's claims, and the server re-issues them per tenant on a switch, so all existing gating (`canManageTenant`, `canCreateApps`, `scopedAppIds`) is automatically correct in the new tenant. The new `useTenantReach` hook is additive: it answers "what may I do in a tenant I am NOT currently in", which claims cannot express and which a tenant list needs per row.
- **The cache purge is the load-bearing frontend change.** Every tenant-scoped query key in the portal (`['users', params]`, `['applications']`, `['roles']`) omits the tenant, because until now a session named one tenant for its whole life. Once one session can act in two tenants those keys are ambiguous, and React Query would serve tenant A's user list under tenant B — indistinguishable from a broken authorization boundary. `useSetTenantContextMutation` drops the whole cache except `['session']` (removing it resets a live observer to `pending`, bouncing to /login mid-switch) and `['my-tenants']` (reach did not change, and it renders the switcher itself).
- **`refetchQueries` needs `type: 'all'`.** It defaults to active observers only. `ProtectedRoute` normally keeps the session query mounted so the default would usually work — but "usually" is the wrong guarantee for the query that decides what the operator may do.
- **Escalation rules were dead code until wired.** `AssertMayGrant`/`AssertMayRemove` existed but nothing called them, so they protected nothing. Now enforced inside the write transactions — `InviteTenantAdmin` after the tenant `FOR UPDATE` lock, and `RemoveTenantAdminAs` after the target's `FOR UPDATE` — so a concurrent revoke of the actor's own grant cannot be raced. `RemoveTenantAdmin` was split: the actor-less form is retained for platform paths and tests, `RemoveTenantAdminAs` enforces the rules.

---

## 1. Requirements

| Tier | Reach | May create tenant | May create application |
|---|---|---|---|
| **Platform admin** (`super_admin`) | every tenant | yes | yes |
| **Owner** | N owned tenants; **all** applications in each, present and future | no | yes (own tenants) |
| **Co-owner** | N tenants, but only **specific applications** per tenant | no | no |

A single user may be owner of tenant A **and** co-owner of tenant B simultaneously.

**A co-owner holds full authority over each granted application.** Permissions do not vary by tenant or by application — the grant decides *which* applications, not *what may be done to them*. This is why no per-grant role is needed (§4).

### Frontend

On login the dashboard lists every reachable tenant:

- platform admin → all tenants
- owner → owned tenants only; no "create tenant"
- co-owner → tenants where they hold at least one application grant; no "create tenant", no "create application"

**No tenant-selection screen.** Clicking into a tenant re-mints the token silently (§6).

---

## 2. What exists today, and the two gaps

Current model (migration `00062`):

- `tenant_admins` — one row per admin, `admin_role IN ('owner','co_owner')`
- `tenant_admin_app_scopes` — per-application grants, **co-owner only**
- an owner holds **zero** grant rows: *absence means all*
- `admin_scope` JWT claim: `AdminScopeTenant` (owner) or `AdminScopeApps` + app id list (co-owner)

Already correct, requiring **no change**:

- Tenant creation is `tenant:manage` only (`routes.go:807`), and `app_scope_test.go:220` already asserts both admin tiers are refused. **The "cannot create tenant" requirement is already met and tested.**
- Guards never trust path `:tid`; they compare it to claims (`permission.go:127`).
- `RevokeAllSessionsTx(ctx, tx, userID, tenantID, reason)` already takes a tenant, so per-tenant revocation is a call-site change, not new plumbing.
- Rate limiters exist and are reusable (`middleware/ratelimit.go`).

### Gap 1 — one admin row per user

`tenant_admins_user_key` is UNIQUE on `user_id` **alone** (`00062:67`). One live admin row per user, so multi-tenant administration is unrepresentable.

### Gap 2 — email uniqueness is per tenant

`users_tenant_email_tenant_level_key` is UNIQUE on `(tenant_id, email)` (`00042:24`). So `xyz@gmail.com` legally exists as **two independent users with two different passwords** in tenants A and B.

That is what the schema produces today for the target scenario, and it is wrong for it:

- **MFA is per-user row** — enrolled twice; revoking a compromised factor in A leaves B exposed
- **`users.blocked_at` is per row** — block the compromised account, they sign into the other tenant unaffected
- **`audit_logs.user_id` points at a row** — one person's actions split across two actors with no link
- **password reset is ambiguous** — one address, two flows (`00066` already fixed a normalization bug here)

Also, the trigger at `00062:106` asserts `users.tenant_id = tenant_admins.tenant_id`, structurally forbidding the row we need.

**Decision: one user, one password, N grants.** Same email = same human.

> **Note:** an earlier draft of this plan carried a third gap — `users.role_id` being a single column, unable to hold two roles at once. That gap only exists if permissions vary per tenant. They do not (§1), so the role is a pure function of `admin_role` and is resolved at token-issue time. **No per-grant role column, no role backfill.** This removed the riskiest unvalidated assumption in the plan.

---

## 3. Identity: home tenant vs administered tenants

Admin identity must become tenant-independent, but `users.tenant_id` is `NOT NULL` and load-bearing.

**Option A — separate `admin_identities` table.** Cleanest model. **Rejected**, for the reason `00062:19-28` already gives: `users.id` carries 16 foreign keys across 15 tables. Forking them duplicates all of `internal/auth` — login, both MFA paths, reset, verification, email change, block/unblock — into a second, less-scrutinized copy, and forces `audit_logs` into a polymorphic actor.

**Option B — home tenant (chosen).** `users.tenant_id` means *where the credentials live*; `admin_grants` carries *reach*. Nothing structural moves.

To stop the two meanings being reconflated:

- add a column comment stating `tenant_id` is the credential home, not administrative reach
- optionally rename to `home_tenant_id` (mechanical, and makes the distinction unmissable)
- add a uniqueness guard so a second admin identity cannot be created for an email that already has one (§5)

### Scope: admins only

Application end users keep per-application email independence — `00042:29-34` makes that deliberate, and it is correct for end users (different apps, different relationships). **Leave `users_tenant_app_email_key` alone.** Unify tenant-level admins only.

---

## 4. Schema — migration `00071_admin_grants.sql`

One grant table carrying both object dimensions. `application_id IS NULL` means *all applications in this tenant*, preserving `00062`'s absence-means-all rule.

```sql
CREATE TABLE admin_grants (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id        BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id      BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    admin_role     TEXT   NOT NULL CHECK (admin_role IN ('owner','co_owner')),
    -- NULL = every application in this tenant, present and future (owner).
    application_id BIGINT REFERENCES oauth_clients(id) ON DELETE CASCADE,
    invited_by     BIGINT REFERENCES admin_grants(id) ON DELETE SET NULL,
    activated_at   TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at     TIMESTAMPTZ,

    CONSTRAINT admin_grants_role_shape CHECK (
        (admin_role = 'owner'    AND application_id IS NULL) OR
        (admin_role = 'co_owner' AND application_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX admin_grants_owner_key ON admin_grants (user_id, tenant_id)
    WHERE admin_role = 'owner' AND deleted_at IS NULL;
CREATE UNIQUE INDEX admin_grants_coowner_key
    ON admin_grants (user_id, tenant_id, application_id)
    WHERE admin_role = 'co_owner' AND deleted_at IS NULL;

CREATE INDEX idx_admin_grants_user   ON admin_grants (user_id)   WHERE deleted_at IS NULL;
CREATE INDEX idx_admin_grants_tenant ON admin_grants (tenant_id, admin_role) WHERE deleted_at IS NULL;
CREATE INDEX idx_admin_grants_app    ON admin_grants (application_id) WHERE deleted_at IS NULL;
```

No `role_id` column: permissions are a function of `admin_role`, resolved at token-issue time from the tenant's seeded `owner` / `co_owner` role. A co-owner has full authority over their granted applications (§1), so there is nothing per-grant to store.

`admin_grants_role_shape` replaces **two** plpgsql triggers from `00062` with a column-level invariant — cheaper and stronger. "An owner must hold no application grants" becomes unrepresentable rather than trigger-rejected.

### Triggers still required

A `CHECK` cannot reach another table:

1. **app belongs to tenant** — port `tenant_admin_app_scopes_assert_valid` (`00062:140`): `oauth_clients.tenant_id` must equal `admin_grants.tenant_id`.
2. **grantee is tenant-level** — port `tenant_admins_assert_tenant_level_user` (`00062:83`), keeping the `users.application_id IS NULL` assertion but **dropping its same-tenant check** — that check is what currently forbids cross-tenant administration.

### Dropped

`tenant_admins_clear_grants_on_promote` (`00062:183`). Promotion becomes: soft-delete the co-owner rows, insert an owner row — one transaction, no trigger.

### Backfill

```sql
-- owner → one row, application_id NULL
INSERT INTO admin_grants (user_id, tenant_id, admin_role, application_id, activated_at, created_at)
SELECT ta.user_id, ta.tenant_id, 'owner', NULL, ta.activated_at, ta.created_at
FROM tenant_admins ta
WHERE ta.admin_role = 'owner' AND ta.deleted_at IS NULL;

-- co_owner → one row per existing app scope
INSERT INTO admin_grants (user_id, tenant_id, admin_role, application_id, activated_at, created_at)
SELECT ta.user_id, ta.tenant_id, 'co_owner', sc.application_id, ta.activated_at, ta.created_at
FROM tenant_admins ta
JOIN tenant_admin_app_scopes sc ON sc.admin_id = ta.id
WHERE ta.admin_role = 'co_owner' AND ta.deleted_at IS NULL;
```

**A co-owner with zero scopes produces zero rows** — matching today's fail-closed behaviour (`00062:47-48`: grants only narrow, never widen).

Keep `tenant_admins` in place, read-only, for at least one release. Do not drop it in the migration that introduces `admin_grants`.

### Backfill verification — must pass before step 3

Run inside the migration transaction; abort if any row is returned.

```sql
-- 1. Every live owner produced exactly one all-apps grant.
SELECT ta.id FROM tenant_admins ta
WHERE ta.admin_role = 'owner' AND ta.deleted_at IS NULL
  AND NOT EXISTS (
    SELECT 1 FROM admin_grants g
    WHERE g.user_id = ta.user_id AND g.tenant_id = ta.tenant_id
      AND g.admin_role = 'owner' AND g.application_id IS NULL AND g.deleted_at IS NULL);

-- 2. Every live co-owner scope produced exactly one grant.
SELECT sc.admin_id, sc.application_id
FROM tenant_admin_app_scopes sc
JOIN tenant_admins ta ON ta.id = sc.admin_id
WHERE ta.deleted_at IS NULL
  AND NOT EXISTS (
    SELECT 1 FROM admin_grants g
    WHERE g.user_id = ta.user_id AND g.tenant_id = ta.tenant_id
      AND g.admin_role = 'co_owner' AND g.application_id = sc.application_id
      AND g.deleted_at IS NULL);

-- 3. No grant invented reach that did not exist before.
SELECT g.id FROM admin_grants g
WHERE g.deleted_at IS NULL
  AND NOT EXISTS (
    SELECT 1 FROM tenant_admins ta
    WHERE ta.user_id = g.user_id AND ta.tenant_id = g.tenant_id
      AND ta.admin_role = g.admin_role AND ta.deleted_at IS NULL);

-- 4. activated_at preserved — a pending grant must not become live.
SELECT g.id FROM admin_grants g
JOIN tenant_admins ta ON ta.user_id = g.user_id AND ta.tenant_id = g.tenant_id
WHERE ta.deleted_at IS NULL AND g.deleted_at IS NULL
  AND (ta.activated_at IS NULL) <> (g.activated_at IS NULL);
```

Query 3 is the security-critical one: it proves the migration **widened nobody's authority**.

### `tenants.primary_admin_id`

Currently FKs to `tenant_admins(id)`. Repoint to `admin_grants(id)`, still one nullable FK on the parent so "two rows claim primary" stays unrepresentable (`00062:200-206`). Semantics tighten to *per tenant*, which is what it always meant.

---

## 5. Phase 0: merging duplicate-email admins

**Duplicates are expected in production.** This is a required phase, not a contingency — and the only phase that touches credentials, so it ships alone, before `00071`.

### Inventory

```sql
SELECT email, COUNT(*) AS rows, array_agg(tenant_id ORDER BY tenant_id) AS tenants,
       array_agg(id ORDER BY id) AS user_ids
FROM users
WHERE application_id IS NULL AND deleted_at IS NULL
GROUP BY email
HAVING COUNT(*) > 1
ORDER BY COUNT(*) DESC;
```

Also inventory what each duplicate carries, because it decides the merge cost:

```sql
-- per duplicate row: does it have MFA, sessions, audit history?
SELECT u.id, u.email, u.tenant_id, u.blocked_at IS NOT NULL AS blocked,
       EXISTS (SELECT 1 FROM totp_secrets ts WHERE ts.user_id = u.id AND ts.is_active) AS totp,
       EXISTS (SELECT 1 FROM email_mfa_settings em WHERE em.user_id = u.id AND em.is_active) AS email_mfa,
       (SELECT COUNT(*) FROM audit_logs al WHERE al.user_id = u.id) AS audit_rows,
       (SELECT MAX(al.created_at) FROM audit_logs al WHERE al.user_id = u.id) AS last_seen
FROM users u
WHERE u.application_id IS NULL AND u.deleted_at IS NULL
  AND u.email IN (SELECT email FROM users WHERE application_id IS NULL AND deleted_at IS NULL
                  GROUP BY email HAVING COUNT(*) > 1)
ORDER BY u.email, u.tenant_id;
```

### Merge procedure, per duplicate set

**Survivor selection** — deterministic, documented, in this order:

1. the row with active MFA (avoids re-enrolment; if several, the most recently used)
2. else the most recent `last_seen` from audit history
3. else the lowest `id`

**Then, in one transaction per set:**

1. Create an `admin_grants` row for **each** retired row's `(tenant_id, admin_role, application_id)`, pointing at the survivor. This is what preserves reach — the merge must not narrow anyone's access, and must not widen it either.
2. Repoint `audit_logs.user_id` from retired rows to the survivor, so one person's history is one actor. **Do not delete audit rows.**
3. Repoint or drop other FK-bearing rows per table. `users.id` carries 16 FKs across 15 tables (`00062:19-28`) — enumerate them explicitly; do not assume a cascade does the right thing. Credentials, TOTP secrets, and email-MFA settings on retired rows are **dropped, not merged** (two secrets cannot become one).
4. Revoke all sessions and refresh tokens for **every** row in the set, survivor included.
5. Soft-delete the retired rows (`deleted_at`), which frees the partial unique index.
6. Force a password reset on the survivor (`ActionAdminForcePasswordReset`) and email them.
7. Audit the merge itself — `admin.identity_merged`, recording every retired `user_id`, its tenant, and the survivor.

**If any row in the set is blocked** (`blocked_at IS NOT NULL`), stop and escalate. Merging a blocked identity into an active one silently unblocks it — the exact failure §2 lists. Resolve the block first, by hand.

### Why the password must be reset

The rows hold genuinely different secrets. There is no correct automatic choice, and picking one silently means an admin's known password stops working with no explanation — indistinguishable from a compromise. Reset and notify.

### Communication

These are your most privileged accounts, and they will be signed out and asked to reset. Notify before the migration runs, not after. Someone who receives an unexpected reset mail for an admin account should be able to recognise it as planned.

### Verification

```sql
-- no tenant-level email appears twice
SELECT email FROM users WHERE application_id IS NULL AND deleted_at IS NULL
GROUP BY email HAVING COUNT(*) > 1;              -- must return zero rows

-- every retired row's reach survived as a grant
-- (compare against the inventory captured before the merge — keep it as a fixture)
```

Capture the inventory output **before** merging and keep it: it is the only record of what reach existed, and step 1's verification queries (§4) depend on it.

Phase 0 is **reversible until step 5** (the soft-delete): retired rows can be restored by clearing `deleted_at`, provided credentials were not yet dropped. Order the transaction so credential drops come last.

---


---

## 5a. The duplicate-identity defect (found in dev, 2026-08-19)

Two tenants were created with the same owner email and different passwords. Both
passwords worked, and switching between the tenants was refused in both
directions. Neither was a bug in the new code — it was the pre-existing defect
Phase 0 exists to clean up, plus a second one that would have kept producing it.

**What the data showed:** `users` 2832 (tenant 2200) and 2833 (tenant 2201) —
two independent accounts, two password hashes, one grant each. Not one owner of
two tenants.

**Root cause 1 — the lookup was tenant-scoped.** `InviteTenantAdmin` resolved its
recipient with `WHERE tenant_id = $1 AND email = $2` (`tenant_admins.go`), so an
address that already existed in ANOTHER tenant matched nothing and a second
`users` row was created. Fixed: the lookup is now across tenants, so the second
invitation grants the existing identity. `ORDER BY id LIMIT 1` keeps the choice
deterministic while historical duplicates still exist.

**Root cause 2 — two legacy constraints blocked the cross-tenant row.** Migration
00071 lifted the single-tenant limit in `admin_grants`, but `tenant_admins` is
still dual-written and carried both halves of the old rule:

- the trigger asserting `users.tenant_id = tenant_admins.tenant_id`
- `tenant_admins_user_key`, UNIQUE on `user_id` **alone**

Migration **00072** relaxes the first (keeping the application-scoped-user
assertion, which is the one that matters) and widens the second to
`(user_id, tenant_id)`, mirroring `admin_grants_owner_key`.

**Also fixed: `previousRoleID` across tenants.** It is what removal restores, and
it comes from `users.role_id` — the *home* tenant's role. Restoring that when a
cross-tenant administration is withdrawn would attach a foreign tenant's role,
carrying permissions nobody granted. Now nil when `homeTenantID != in.TenantID`.

**Invitation legibility.** `Preview` now returns `tenant_name`, `admin_role`, and
`existing_tenants`, so the acceptance page can say "this adds Bolt as co-owner;
you already administer Acme; your password stays the same". Without it a
cross-tenant invitation is indistinguishable from a first-time one, and someone
who has used the account for months is told to set a password — which reads as an
error at best and phishing at worst.

**Recovery path added.** Both confirmation options require the current password
(deliberately — an invitation link is authority to accept a grant, not to take
over an account), but the page offered no way out for someone who has forgotten
it. It now links to forgot-password and states that the invitation stays valid:
verified in `reset.go`, which touches `password_reset_tokens` and sessions only,
never `user_invitations`.

**Credentials are unchanged on acceptance** — that was already true
(`activatePendingAdminGrant` never touches `user_credentials`) and is pinned by
`TestInvitation_ConfirmsAdminGrantWithoutTouchingPassword`.

**Merging existing duplicates:** `scripts/phase0_merge_duplicate_admin.sql`.
Deterministic survivor selection (active MFA → most recent activity → lowest id),
re-points administrations and audit history, revokes every session in the set,
drops credentials **last** so earlier steps stay reversible, and refuses outright
if any row is blocked — merging a blocked identity into an active one would
silently unblock it. It does not choose a password: the survivor is left with
none and must use forgot-password, because two different secrets cannot merge and
silently picking one makes an admin's known password stop working with no
explanation.


### Root cause 3 — `CreateTenant` inserted the owner blindly (the actual reported path)

The first fix addressed `InviteTenantAdmin`, and the duplicate reproduced anyway.
An audit of **every** `INSERT INTO users` site found the real one: `CreateTenant`
(`admin/service.go`) created its owner with no lookup at all, so naming the same
owner on a second tenant minted a parallel account. That is the path an operator
walks through the UI — "create tenant, enter owner email" — and it is distinct
from the invitation flow.

Full audit of the eight insert sites, and why only two needed changing:

| Site | Population | Fixed |
|---|---|---|
| `admin/service.go` CreateTenant owner | tenant-level administrator | **yes** |
| `admin/tenant_admins.go` InviteTenantAdmin | tenant-level administrator | **yes** |
| `admin/service.go` CreateUser | either; operator names the tenant explicitly | no |
| `auth/service.go` self-registration | application end user | no — 00042 intends per-app duplicates |
| `auth/oauthflow.go` OAuth callback | application end user | no |
| `saml/service.go` JIT provisioning | tenant-level, but not an administrator | no |
| `store/seed.go`, `store/seed_demo.go` | fixtures | no |

The distinction that decides it: an **administrator** must be one identity across
tenants, because reach is keyed on `user_id` and credentials/MFA/blocking are
per-row. An **application end user** must not be — migration 00042 deliberately
lets the same address exist independently per application, since those are
different relationships with different applications.

Verified end-to-end against the running server: two tenants created via
`POST /api/v1/tenants` with one owner email produced **one** `users` row (3398)
holding owner grants in both tenants, with a single credential slot. The
regression test was also confirmed to FAIL when the lookup is disabled, so it
pins the behaviour rather than passing vacuously.

**Operational note:** the fix is in Go, so a running container must be rebuilt
(`docker compose build emc-auth-server`) — the first verification attempt failed
because the container was serving a stale binary.

## 6. Token and login flow

`claims.TenantID` **stays a scalar**, so every guard in `permission.go` works untouched. This is the central design constraint: a list-valued tenant claim would touch every guard and break the per-tenant issuer/signing-key model (`jwt.go:348`), and would mean one leaked admin token is valid in every tenant that admin reaches.

### Login — no selection screen

```
POST /auth/login { email, password }
  → verify password (one hash), then MFA (one enrollment)
  → grants := live activated admin_grants for this user
  → mint an access token for a DEFAULT tenant
      (last used if still granted, else lowest-id owned tenant, else lowest-id granted)
  → 200 { access_token, ... }        # same shape as today
```

Single-tenant admins are unaffected. Multi-tenant admins land in a real tenant immediately — no interstitial.

### Seeing all tenants

The dashboard lists reach via `GET /admin/my-tenants` (§8). **That endpoint does not consult `claims.TenantID`** — it queries `admin_grants` by `user_id`, so both tenants appear regardless of which tenant the current token is for.

### Entering another tenant

```
POST /auth/switch-tenant { tenant_id }     # bearer: current access token
  → re-verify a live activated grant for (user, tenant_id)
  → mint a new access token:
      claims.TenantID = chosen tenant (scalar)
      permissions     = the tenant's seeded role for this grant's admin_role
      admin_scope     = loadAdminScope(user, chosen tenant)
  → 200 { access_token, ... }
```

Authenticated by the **existing** access token — there is no intermediate credential, and therefore no `select_tenant_token` audience to design or abuse. The user clicks a tenant; the client re-mints in the background and renders the page.

**Rate limit:** reuse `TokenRateLimiter` (`ratelimit.go:310`) — it is a token-minting endpoint. Per-user, not per-IP.

### `loadAdminScope`

Same signature, same return contract — one query against the new table:

```go
func loadAdminScope(ctx, pool, userID, tenantID int64) (string, []string, error)
```

- no live activated grant → `("", nil, nil)`
- an `owner` grant → `(AdminScopeTenant, nil, nil)` — **no app list**, so an application created a minute later is reachable without re-login (`tenant_admin.go:108-113`)
- `co_owner` grants → `(AdminScopeApps, [ids], nil)`

**Preserve the non-nil-empty-slice rule** (`tenant_admin.go:144-147`): a co-owner whose last grant was revoked is `AdminScopeApps` with an empty list, which `RequireAppScope` denies. Returning `nil` would be indistinguishable from "not an administrator".

### Per-tenant session revocation

`activatePendingAdminGrant` currently revokes **all** sessions (`tenant_admin.go:97`). With multi-tenant admins, losing or gaining a grant in tenant B must not end tenant A's sessions. `RevokeAllSessionsTx` already takes `tenantID` — pass the **grant's** tenant, not the user's home tenant.

The reason activation revokes at all still holds and must be kept: a refresh token captured before the grant existed would otherwise keep minting access tokens, now carrying `admin_scope`, because rotation re-reads the grant.

### Revocation latency — decide explicitly

Revoking a grant does not invalidate an already-issued access token. Until it expires, the holder keeps that tenant's authority. Options:

- accept it, bounded by access-token TTL (document the number)
- bump `users.token_version` on revoke — kills **all** tenants' tokens for that user (blunt, but immediate)
- check grant liveness on refresh only (rotation already re-reads the grant)

**Recommended:** accept TTL-bounded latency for ordinary revokes; bump `token_version` for a security-triggered revoke, where signing the person out everywhere is the point.

---

## 7. On "pure RBAC" — recommendation against

Pure RBAC means role names carrying the object dimensions: `co_owner:t3:app42`. With **two** dimensions (tenant × application) this is multiplicative — an owner of 5 tenants needs 5 assignments; a co-owner across 3 tenants × 4 apps needs 12.

It also reintroduces the failure `00062:39-45` was written to prevent, now across N tenants:

> Encoding an owner as grants-for-every-app would oblige every present and future application-creation path to backfill a grant row for every owner of the tenant, forever. A missed backfill fails silently — the owner simply gets 403 on an application they just created themselves, with no error to trace.

"All applications in those tenants" is inherently an absence-means-all rule; it does not survive translation into enumerated role names. A wildcard role (`co_owner:t3:*`) is `AdminScopeTenant` re-invented inside a string, now needing parsing at every check site instead of one comparison.

**Recommended instead: RBAC for verbs, `admin_grants` for objects.** This *is* the standard model — AWS IAM separates Action from Resource; GCP binds roles to resources; Kubernetes keeps the namespace out of the role name. Documented as "RBAC + resource scoping (ReBAC)", it audits better than 12 role assignments per user.

Since a co-owner's permissions are identical to an owner's (§1), pure RBAC would buy **nothing** here — the role names would differ only in the object part, which is precisely the part RBAC cannot express.

Worth doing regardless: the `has(perm)` closure is duplicated across three guards in `permission.go`. A single `Can(claims, action, resource)` entry point would centralize permission + scope so a new route cannot forget the scope step.

---

## 8. Frontend

Repo: `../emc-auth-frontend` (TS / react-query / zustand).

### One endpoint, server-derived

All three cases are "list the tenants I can reach" — **one** endpoint, not three branches:

```
GET /admin/my-tenants
  → { can_create_tenant: bool,
      tenants: [ { id, name, slug, role, app_count,
                   can: { create_application, manage_users, manage_roles } } ] }
```

| Tier | Server-side source | `can_create_tenant` |
|---|---|---|
| platform admin | all tenants (holds `tenant:manage`) | `true` |
| owner | `admin_grants` where `admin_role = 'owner'` | `false` |
| co-owner | `DISTINCT tenant_id` from co-owner grants | `false` |

**The frontend must not compute reach from claims.** Three client-side role branches drift from the middleware, and the UI starts showing tenants the API will 403 on.

Platform-admin response is paginated — "all tenants" may be thousands.

### Capability flags, never role comparisons

```tsx
{tenant.can.create_application && <NewApplicationButton />}   // yes
{role !== 'co_owner' && <NewApplicationButton />}             // no
```

Server-supplied capabilities mean a button's visibility and a route's guard share one source of truth, and a new tier needs no frontend change.

### Client work

1. **No selection screen.** Login goes straight to the default tenant's dashboard, which lists all reachable tenants.
2. **Clicking a tenant** calls `/auth/switch-tenant`, stores the new token, then navigates. Show a pending state — it is one round trip.
3. **Purge cached data on switch.** This is the leak to expect: react-query keys without a tenant will serve tenant A's users under tenant B. Do **both** — include `tenantId` in every query key, and `queryClient.clear()` on switch.
4. **Selected tenant in zustand**, hydrated from the token — never from an editable URL param. The backend already never trusts path `:tid`; the client should not either.
5. **Application lists are always fetched**, never read from claims. An owner's token deliberately carries no app list; a co-owner's does, but fetching keeps one code path and cannot go stale mid-session.
6. **Handle 403 on a stale token** — if a grant was revoked in another session, switch or refetch returns 403. Treat it as "reload my tenant list", not as a crash.

### Navigation

A co-owner of one tenant with two applications has no use for a tenants page. Suggested landing:

- platform admin, owner → tenant list
- co-owner → **application list directly**, tenant reduced to a switcher label

Their mental model is applications, not tenants.

The `/admin/my-tenants` shape is the contract — the frontend can build against a mock before the backend lands.

---

## 9. Audit

Granting cross-tenant administrative access is among the most security-sensitive events in the system. Add to `internal/audit/logger.go`, following the existing `admin.*` convention:

```go
ActionAdminGrantCreated   = "admin.grant_created"    // tenant, role, application (or "all")
ActionAdminGrantActivated = "admin.grant_activated"  // recipient accepted
ActionAdminGrantRevoked   = "admin.grant_revoked"
ActionAdminGrantPromoted  = "admin.grant_promoted"   // co_owner → owner
ActionAdminTenantSwitched = "admin.tenant_switched"  // from → to
ActionAdminIdentityMerged = "admin.identity_merged"  // phase 0: retired ids → survivor
```

Also audit **denied** grant writes — an owner attempting to create an `owner` grant, or to act in a tenant they do not own (§12), is a privilege-escalation attempt and belongs in the log. `denyAudited` already exists for this (`permission.go`), but the service-layer refusals in §12 are past the middleware and need their own entries.

Every entry must carry **actor**, **target user**, **tenant**, and **application** (or an explicit "all applications" marker). Without the application dimension the log cannot answer "who could reach this app last Tuesday" — the question an incident actually asks.

`admin.tenant_switched` matters more than it looks: it is the only record that one identity acted across tenant boundaries, and reconstructing a multi-tenant admin's session is impossible without it.

Audit rows are written for the **grant's** tenant, not the actor's home tenant, so a tenant's log shows everything that changed its own access.

---

## 10. Rollout, rollback, zero-downtime

### Dual-read behind a flag

Step 3 changes how every admin's authority is computed. It ships behind `ADMIN_GRANTS_ENABLED`:

- **off** — `loadAdminScope` reads `tenant_admins` + `tenant_admin_app_scopes` (today's behaviour)
- **on** — reads `admin_grants`

Both tables stay in sync while the flag exists: **grant writes go to both** (dual-write) until `tenant_admins` is dropped in step 9. This makes rollback a config change rather than a migration.

### Shadow comparison before flipping

With the flag off, run both resolvers and log disagreements without acting on them. Flip only after the disagreement rate is zero across a full day of real traffic. This catches backfill errors that §4's static queries cannot — e.g. a grant that resolves differently under concurrent writes.

### Tokens in flight

Tokens issued before the flip carry the old `admin_scope`; both are valid simultaneously during deploy. This is safe because the claim's **shape does not change** — only its source. An owner is `AdminScopeTenant` under both resolvers.

`RequireAppScope` already fails closed on an absent `admin_scope` (`permission.go:167-168`), so the pre-existing self-healing window is unchanged. **Do not** change the claim's shape in the same release as the source change.

### Rollback per step

| Step | Rollback |
|---|---|
| 0 (merge) | separate reversible migration, verified before continuing |
| 1 (table) | additive only — `admin_grants` unread while the flag is off |
| 3 (resolver) | flag off; dual-write means `tenant_admins` is still current |
| 4 (switch endpoint) | route removed; no schema change |
| 6 (`primary_admin_id`) | keep the old column one release, populate both |
| 9 (drop) | **irreversible** — only after a full release with zero flag-off traffic |

### Deploy order

Migration first (additive, unread), then application with the flag off, then shadow-compare, then flip. Never a migration and a behaviour change in one deploy.

---

## 11. Sequencing

| # | Step | Risk |
|---|---|---|
| 0 | **Phase 0** (§5) — inventory, merge duplicate admins, forced resets. Ships alone. | **blocking, touches credentials** |
| 1 | `00071_admin_grants.sql` — table, CHECK, 2 triggers, backfill + verification (§4) | high |
| 2 | Dual-write grants to both models; escalation rules (§12); audit actions (§9) | medium |
| 3 | `loadAdminScope` on `admin_grants` behind the flag; shadow-compare; per-tenant revocation | **highest — a mistake here leaks across tenants** |
| 4 | `/auth/switch-tenant` + `TokenRateLimiter`; default-tenant selection at login | medium |
| 5 | `GET /admin/my-tenants` with capability flags | low |
| 6 | Repoint `tenants.primary_admin_id` → `admin_grants(id)` | low |
| 7 | Frontend: tenant list, switcher, cache purge, capability-driven UI | medium |
| 8 | Optional: `Can()` consolidation in `permission.go` (§7) | low |
| 9 | Later release: drop `tenant_admins`, `tenant_admin_app_scopes`, the flag | low |

Step 0 must be **fully verified in production** before step 1 begins. Its inventory output is a required input to step 1's verification (§4), and merging after `admin_grants` exists would mean repointing grants mid-flight.

`ListPlatformAdministrators` (`platform_admins.go:158`) becomes one row **per grant**, so an owner of 3 tenants appears 3×. Grant-shaped is more honest for a directory whose unit is "who administers what" — but decide explicitly and note it in the API docs.

### Test matrix — step 3 does not ship without these

**Isolation (the ones that matter):**
- owner of A + co-owner of B: token for A carries `AdminScopeTenant`; token for B carries `AdminScopeApps` with **only** B's apps
- owner of A gets 403 on tenant B despite holding `apps:write`
- co-owner of B cannot reach tenant-level routes in B (`RequireTenantSelfOrAny` still refuses)
- co-owner with zero grants in a tenant → `AdminScopeApps{}`, denied, **not** treated as non-admin
- a tenant-A token cannot act on tenant B after a switch back

**Boundaries:**
- neither tier can create a tenant — extend `app_scope_test.go:220` to the multi-tenant case
- co-owner cannot create an application
- an app-scoped user still cannot receive a grant (ported trigger)
- a grant cannot name an application from another tenant (ported trigger)
- an owner grant cannot carry an `application_id`; a co-owner grant cannot omit one (CHECK)

**Lifecycle:**
- losing the B grant does not end A's sessions
- revoking a grant mid-session: switch returns 403, existing token behaves as §6 documents
- two grants activating concurrently for one user — no lost update
- `/auth/switch-tenant` with a tenant the caller has no grant for → 403, audited
- rate limit enforced per user

**Migration:**
- all four §4 verification queries return zero rows against a seeded fixture
- shadow comparison agrees on every admin in the test corpus
- flag off ⇒ byte-identical `admin_scope` to pre-change behaviour

---

## 12. Who may write grants

**An owner may grant co-ownership within their own tenants.** Platform admins may grant anywhere.

The existing routes already have the right guard shape — `/tenants/:tid/admins` uses `tidUsersWrite` = `RequireTenantSelfOrAny("users:write")` (`routes.go:982-988`), which admits `tenant:manage` for any tenant, admits an owner in their own tenant, and refuses a co-owner outright (`permission.go:120`). No new middleware is needed.

What must be added are the escalation rules the guard cannot express:

### Rules enforced in the service layer

1. **An owner may create only `co_owner` grants.** Creating another `owner` is platform-admin only — otherwise any owner can mint a peer with authority equal to their own, and ownership becomes unboundedly self-propagating.
2. **An owner may grant only applications in a tenant they own.** Already covered by the `:tid` comparison plus the app-belongs-to-tenant trigger, but assert it in the service too — the trigger's error is not a usable API response.
3. **A co-owner may never write grants.** Enforced by the guard, but test it explicitly: they hold `users:write`, so only the `AdminScopeApps` refusal stops them.
4. **Nobody may modify their own grant.** An owner must not revoke or narrow themselves, and must not promote themselves. Compare actor `user_id` to target and refuse.
5. **An owner may revoke a co-owner in their tenant, but not another owner.** Removing a peer owner is platform-admin only, for the same reason as rule 1.
6. **Grants remain inert until accepted.** Unchanged from `00062` — the emailed activation is what attaches authority, so an owner alone cannot make someone an administrator (`tenant_admin.go:35-45`).

Rules 1 and 5 together mean ownership can only be conferred by the platform tier. That keeps the owner population auditable.

### Tests

- an owner creating an `owner` grant → 403
- an owner creating a `co_owner` grant in their own tenant → 201
- an owner creating a grant in a tenant they do not own → 403
- a co-owner creating any grant → 403
- an owner revoking themselves → 403
- an owner revoking a peer owner → 403
- an owner revoking a co-owner in their tenant → 200
- a created grant carries no authority until activated

---

## 13. Remaining open questions

1. **`ListPlatformAdministrators`**: group by user, or one row per grant? (Recommendation: per grant — the directory's unit is "who administers what".)
2. **Revocation latency** (§6) — confirm TTL-bounded is acceptable for ordinary revokes.
3. **Default tenant at login** — lowest-id owned, or persist last-used? Persisting needs a column.

### Resolved

- ~~Do co-owner permissions vary by tenant?~~ **No** — full access to granted applications. Removed the per-grant role column and its backfill.
- ~~Tenant selection screen?~~ **No** — login lands in a default tenant; switching is a silent re-mint (§6).
- ~~One token spanning tenants?~~ **No** — scalar `claims.TenantID` preserved; per-tenant signing keys and isolation intact.
- ~~May an owner grant co-ownership?~~ **Yes**, within their own tenants, `co_owner` only (§12).
- ~~Duplicate-email admins in production?~~ **Expected** — step 0 is confirmed necessary, not contingent (§5).
