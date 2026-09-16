# Demo user-import data

`demo-user-import.json` exercises every branch of the bulk import validator in
one upload: twenty-three rows that import cleanly — covering all four accepted
password formats across a spread of cost factors — and fourteen that are each
rejected for a different reason.

Verified against the real validator — the numbers below are the actual output,
not an intention.

## Running it

Import is application-scoped. Pick an application in the console, then:

```bash
# Dry run — writes nothing, returns the per-row verdict.
curl -X POST \
  "$BASE/api/v1/admin/tenants/$TENANT_ID/applications/$APP_ID/users/import/validate" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @testdata/demo-user-import.json

# Commit — creates the rows that passed.
curl -X POST \
  "$BASE/api/v1/admin/tenants/$TENANT_ID/applications/$APP_ID/users/import" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @testdata/demo-user-import.json
```

Or upload it through **Users → Import** in the console, which shows the same
verdict as a reviewable table.

## Expected result

```
total=37  create=23  skip=0  reject=14
```

Re-running the commit gives `create=0 skip=23` — the import is idempotent on
(tenant, application, email).

## The twenty-three that import

| # | Email | What it covers |
|---|-------|----------------|
| 1 | jane.okafor@example.com | bcrypt `$2a$` cost 10, plus `password_changed_at` carried from the source system rather than defaulting to now |
| 2 | MARCUS.Webb@Example.COM | Mixed-case address — normalised to `marcus.webb@example.com` on the way in |
| 3 | priya.raman@example.com | `is_active: false` — imported blocked, proving an explicit false is honoured (an *absent* `is_active` defaults to true) |
| 4 | tom.lindqvist@example.com | Argon2id at the server's **current** parameters |
| 5 | hanna.virtanen@example.com | bcrypt `$2b$` cost 12 |
| 6 | diego.salazar@example.com | bcrypt `$2y$` cost 8 — the PHP/Symfony revision marker |
| 7 | yuki.tanaka@example.com | Argon2id at **different** parameters (`m=19456,t=2`) — verification uses the parameters stored in the hash, not the server's |
| 8 | noor.alghamdi@example.com | bcrypt `$2a$` **cost 4** — the floor, and a 2019 `password_changed_at` |
| 9 | luca.rossi@example.com | bcrypt `$2b$` cost 11 |
| 10 | amara.okon@example.com | bcrypt `$2y$` cost 6, `email_verified: false` — arrives unverified |
| 11 | kenji.sato@example.com | bcrypt `$2a$` **cost 13** — expensive end of the range |
| 12 | elena.popa@example.com | bcrypt `$2b$` cost 5, imported blocked |
| 13 | ravi.sharma@example.com | Argon2id at current parameters (second instance) |
| 14 | ingrid.berg@example.com | Argon2id **low memory** (`m=12288,t=3`) — OWASP's alternative profile |
| 15 | omar.haddad@example.com | Argon2id **high memory, p=2** (`m=65536,p=2`) |
| 16 | rosa.mendes@example.com | Assigned the application role **`EMC`** by name |
| 17 | viktor.novak@example.com | `EMC` again, this time alongside an Argon2id digest |
| 18 | grace.mutua@example.com | `"role": ""` — falls back to the application's default role, or blank if none is set |
| 19 | padded.role@example.com | `"role": "  EMC  "` — surrounding whitespace is trimmed before lookup |
| 20 | sofia.duarte@example.com | Federated-only: a Google identity and no password |
| 21 | chen.wei@example.com | Federated-only via **Microsoft**, subject in GUID form |
| 22 | fatima.zahra@example.com | Password **plus two** identities (Google and GitHub) |
| 23 | aaron.mbeki@example.com | Both a password and a federated identity |

Cost factors run 4 → 13 on bcrypt, and Argon2id appears at four distinct
parameter sets. That spread matters: verification derives with the parameters
stored *in each hash*, so a corpus that accumulated different settings over the
years imports without anyone having to normalise it first.

Rows 3 and 22 deliberately share the password `Sh4red!Secret` with different
digests — per-hash salts mean two accounts with the same password are
indistinguishable in storage.

### Roles

Rows 16, 17 and 19 need a non-system role named **`EMC`** in the target
application. Create it first (Applications → Roles → Add Role), or those three
rows come back as `role "EMC" is not available in this application` — which is
itself a useful thing to see once.

Roles are matched **by name, exactly, and case-sensitively**. Surrounding
whitespace is trimmed (row 19) because a trailing space in a spreadsheet export
is invisible and never intentional. Case is *not* folded (row 34) because
`roles.name` is unique per (tenant, application) case-sensitively, so `emc` and
`EMC` can both exist as separate roles and guessing between them would hand out
the wrong one.

Resolution runs in three tiers:

| The row… | Gets |
|----------|------|
| names a role that exists here | that role |
| names a role that does **not** exist here | **rejected** — `role "X" is not available in this application` |
| names no role, and the app has a default | the application's default role |
| names no role, and there is no default | no role (blank) |

The middle case is a rejection, not a silent import without the role: an
operator who asked for a role and got an account without one would believe the
role was applied. A role that exists in *another* application counts as not
existing here — roles are per-application, and `importRoleMap` only ever loads
this application's own.

The default-role tier applies the same role `/register` would, so a migrated
user and a user who signs up a minute later land identically. System roles are
never eligible for either tier.

## Every accepted algorithm

`Identify` dispatches on the digest's own prefix, and recognises exactly four:

| Prefix | Algorithm | Demo rows |
|--------|-----------|-----------|
| `$2a$` | bcrypt | 1, 2, 3, 8, 11, 16, 22, 23 |
| `$2b$` | bcrypt | 5, 9, 12, 18 |
| `$2y$` | bcrypt | 6, 10, 19 |
| `$argon2id$` | Argon2id (PHC) | 4, 7, 13, 14, 15, 17 |

The three bcrypt markers are revision tags, not different algorithms — the salt
and digest that follow are identical work. Different corpora carry different
markers (`$2y$` is common in PHP), so all three are accepted.

Anything else is rejected. There is no separate-salt field: `user_credentials`
stores one self-describing string, so PBKDF2, scrypt and raw SHA exports cannot
be imported without adding a verifier first.

### Passwords

Real digests, each verified against the live `Verify` path. After importing,
these accounts sign in with:

| Account | Password | Stored as |
|---------|----------|-----------|
| jane.okafor@example.com | `Passw0rd!demo` | bcrypt `$2a$` cost 10 |
| MARCUS.Webb@Example.COM | `Migrate2024!` | bcrypt `$2a$` cost 10 |
| priya.raman@example.com | `Sh4red!Secret` | bcrypt `$2a$` (blocked until unblocked) |
| tom.lindqvist@example.com | `Argon2!demo` | Argon2id, current params |
| hanna.virtanen@example.com | `Bcrypt2b!demo` | bcrypt `$2b$` cost 12 |
| diego.salazar@example.com | `Bcrypt2y!demo` | bcrypt `$2y$` cost 8 |
| yuki.tanaka@example.com | `Argon2!legacy` | Argon2id, `m=19456,t=2` |
| noor.alghamdi@example.com | `Noor!2019pass` | bcrypt `$2a$` cost 4 |
| luca.rossi@example.com | `Luca!Rossi22` | bcrypt `$2b$` cost 11 |
| amara.okon@example.com | `Amara!Okon07` | bcrypt `$2y$` cost 6 |
| kenji.sato@example.com | `Kenji!Sato31` | bcrypt `$2a$` cost 13 |
| elena.popa@example.com | `Elena!Popa88` | bcrypt `$2b$` cost 5 (blocked) |
| ravi.sharma@example.com | `Ravi!Sharma44` | Argon2id, current params |
| ingrid.berg@example.com | `Ingrid!Berg19` | Argon2id, `m=12288,t=3` |
| omar.haddad@example.com | `Omar!Haddad56` | Argon2id, `m=65536,p=2` |
| rosa.mendes@example.com | `Passw0rd!demo` | bcrypt `$2a$` cost 10, role `EMC` |
| viktor.novak@example.com | `Ravi!Sharma44` | Argon2id current params, role `EMC` |
| grace.mutua@example.com | `Luca!Rossi22` | bcrypt `$2b$` cost 11, no role |
| padded.role@example.com | `Amara!Okon07` | bcrypt `$2y$` cost 6, role `EMC` |
| fatima.zahra@example.com | `Sh4red!Secret` | bcrypt `$2a$` cost 10 |
| aaron.mbeki@example.com | `Federated!1` | bcrypt `$2a$` cost 10 |

That is the point of a pre-hashed import: users keep the password they already
had, whatever produced it.

### Watching the corpus converge

Seventeen of the nineteen credentials are scheduled for upgrade. `NeedsRehash` returns true
for all three bcrypt variants *and* for Argon2id at non-current parameters, so
only `tom.lindqvist` and `ravi.sharma` — already at current settings — are left
alone:

```sql
SELECT u.email,
       left(uc.password_hash, 30) AS stored,
       uc.password_hash LIKE '$2%' AS is_bcrypt
FROM user_credentials uc
JOIN users u ON u.id = uc.user_id
ORDER BY u.email;
```

Run it, sign in as `hanna.virtanen@example.com` with `Bcrypt2b!demo`, run it
again: her row is now `$argon2id$` at current parameters. Same password, no
reset, nothing the user notices. `yuki.tanaka` behaves the same way even though
she arrived as Argon2id — her parameters were below current, which counts.

## The fourteen that are rejected

| # | Email | Reason returned |
|---|-------|-----------------|
| 24 | not-an-email-address | `invalid email` |
| 25 | *(empty)* | `invalid email` |
| 26 | no.credentials@example.com | `row has neither password_hash nor identities; the account could not authenticate` |
| 27 | plaintext.password@example.com | `unsupported password_hash: expected bcrypt ($2a/$2b/$2y) or argon2id PHC` |
| 28 | md5.legacy@example.com | same — MD5 is not verifiable by this server |
| 29 | sha1.legacy@example.com | same — SHA-1 likewise |
| 30 | broken.argon@example.com | `malformed argon2id hash: password: malformed parameter value` |
| 31 | ghost.role@example.com | `role "role-that-does-not-exist" is not available in this application` |
| 32 | escalation.attempt@example.com | `role "owner" is not available in this application` |
| 33 | superadmin.attempt@example.com | `role "super_admin" is not available in this application` |
| 34 | wrong.case.role@example.com | `role "emc" is not available in this application` — case-sensitive |
| 35 | double.google@example.com | `duplicate identity for provider "google"` |
| 36 | headless.identity@example.com | `identity requires provider and provider_sub` |
| 37 | jane.okafor@example.com | `duplicate of row 1 in this file` |

### Rows worth understanding

**Rows 32 and 33 are the privilege-escalation cases.** They ask for `owner` and `super_admin`, both system roles.
The refusal reports it as *unknown* rather than *forbidden*, because
`importRoleMap` only ever loads `is_system = false` roles — so from the
importer's perspective it genuinely is not an assignable role. That also means
the response never confirms which administrative roles exist, which is the right
answer to give an uploaded file.

**Rows 27-29 are why plaintext is not an import format.** The server refuses any
digest it cannot verify. Accepting them would create accounts that exist and can
never be signed in to — a failure invisible until the user complains.

**Row 37 is caught against the file, not the database.** Duplicate detection
covers the upload itself, so the second Jane is rejected at validation rather
than failing against the unique index halfway through a commit.

**Rows 20, 21, 22, 23, 35 and 36 need an application-scoped import.** `user_identities.application_id`
is `NOT NULL`, so identities are only valid when the import targets a specific
application. Run the same file at tenant level (omit `/applications/$APP_ID`)
and those six flip to `identities require an application-scoped import`. The
three `EMC` rows fail there too — an application role is not in scope for a
tenant-level import — so the whole file gives `create=16 reject=21` instead of
`create=23 reject=14`.

## Testing export

After committing, `GET .../users/export` returns the directory as CSV. Two
things to check:

- **No credential material.** No password hash, TOTP secret, or passkey appears
  in any column — enforced by the query, not by a filter that could be lifted.
- **Formula injection is neutralised.** Register a user whose first name is
  `=HYPERLINK("http://evil.example","click")`, export, and open the CSV in Excel
  or Sheets: the cell shows the text rather than running it. The leading
  apostrophe is the guard.
