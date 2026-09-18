# Demo user-import data

`demo-user-import.json` exercises every branch of the bulk import validator in
one upload: forty-three rows, of which twenty-five import cleanly — covering all
four accepted password formats across a spread of cost factors, plus plaintext —
and eighteen that are each rejected for a different reason.

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

# Commit — queues the rows that passed.
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
total=43  create=25  skip=0  reject=18
```

Re-running the commit gives `create=0 skip=25` — the import is idempotent on
(tenant, application, email).

## The twenty-five that import

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
| 24 | nina.plaintext@example.com | **Plaintext** `password` — hashed by the worker at current parameters, which is why a file containing one runs as a background job |
| 25 | otto.plainrole@example.com | Plaintext plus the `EMC` role |
| 26 | pia.plainfed@example.com | Plaintext plus a GitHub identity |

Row 23 is absent from that list on purpose — see the rejections below.

Cost factors run 4 → 13 on bcrypt, and Argon2id appears at four distinct
parameter sets. That spread matters: verification derives with the parameters
stored *in each hash*, so a corpus that accumulated different settings over the
years imports without anyone having to normalise it first.

Rows 24-26 are the plaintext arm. A pre-hashed row is an INSERT of a string
somebody else derived; a plaintext row costs one Argon2id derivation against the
process-wide semaphore shared with every login, which is the whole reason commit
returns a job to poll rather than a result.

Rows 3 and 22 deliberately share the password `Sh4red!Secret` with different
digests — per-hash salts mean two accounts with the same password are
indistinguishable in storage.

### Roles

Rows 16, 17, 19 and 25 need a non-system role named **`EMC`** in the target
application. Create it first (Applications → Roles → Add Role), or those four
rows come back as `role "EMC" is not available in this application` — which is
itself a useful thing to see once.

Roles are matched **by name, exactly, and case-sensitively**. Surrounding
whitespace is trimmed (row 19) because a trailing space in a spreadsheet export
is invisible and never intentional. Case is *not* folded (row 37) because
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
never eligible for either tier — which is also why the user export leaves out
the accounts holding one: an owner row could not be fed back through this path.

## Every accepted algorithm

`Identify` dispatches on the digest's own prefix, and recognises exactly four:

| Prefix | Algorithm | Demo rows |
|--------|-----------|-----------|
| `$2a$` | bcrypt | 1, 2, 3, 8, 11, 16, 22 |
| `$2b$` | bcrypt | 5, 9, 12, 18 |
| `$2y$` | bcrypt | 6, 10, 19 |
| `$argon2id$` | Argon2id (PHC) | 4, 7, 13, 14, 15, 17 |

The three bcrypt markers are revision tags, not different algorithms — the salt
and digest that follow are identical work. Different corpora carry different
markers (`$2y$` is common in PHP), so all three are accepted.

Anything else in `password_hash` is rejected. There is no separate-salt field:
`user_credentials` stores one self-describing string, so PBKDF2, scrypt and raw
SHA exports cannot be imported without adding a verifier first. A *plaintext*
password is a different matter — it goes in `password` and this server hashes
it, which is what rows 24-26 cover.

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
| nina.plaintext@example.com | `Plaintext!Import1` | Argon2id, current params (hashed on import) |
| otto.plainrole@example.com | `Plaintext!WithRole2` | Argon2id, current params, role `EMC` |
| pia.plainfed@example.com | `Plaintext!AndFed3` | Argon2id, current params |

That is the point of a pre-hashed import: users keep the password they already
had, whatever produced it. The three plaintext rows are the other half — a
source system that cannot export digests at all still migrates, at the cost of
one derivation per row.

### Watching the corpus converge

Eighteen of the twenty pre-hashed credentials are scheduled for upgrade.
`NeedsRehash` returns true for all three bcrypt variants *and* for Argon2id at
non-current parameters, so only `tom.lindqvist` and `ravi.sharma` — already at
current settings — are left alone. The three plaintext rows need no upgrade
either: this server derived them, at current parameters, on the way in.

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

## The eighteen that are rejected

| # | Email | Reason returned |
|---|-------|-----------------|
| 23 | aaron.mbeki@example.com | `identities require email_verified: true` — a digest and a Google identity, but an unverified address |
| 27 | not-an-email-address | `invalid email` |
| 28 | *(empty)* | `invalid email` |
| 29 | no.credentials@example.com | `row has no password_hash, password or identities, and the email is not verified` |
| 30 | plaintext.password@example.com | `unsupported password_hash: expected bcrypt ($2a/$2b/$2y) or argon2id PHC` |
| 31 | md5.legacy@example.com | same — MD5 is not verifiable by this server |
| 32 | sha1.legacy@example.com | same — SHA-1 likewise |
| 33 | broken.argon@example.com | `unusable password_hash: password: malformed parameter value` |
| 34 | ghost.role@example.com | `role "role-that-does-not-exist" is not available in this application` |
| 35 | escalation.attempt@example.com | `role "owner" is not available in this application` |
| 36 | superadmin.attempt@example.com | `role "super_admin" is not available in this application` |
| 37 | wrong.case.role@example.com | `role "emc" is not available in this application` — case-sensitive |
| 38 | double.google@example.com | `duplicate identity for provider "google"` |
| 39 | headless.identity@example.com | `identity requires provider and provider_sub` |
| 40 | jane.okafor@example.com | `duplicate of row 1 in this file` |
| 41 | both.credentials@example.com | `row has both password_hash and password; supply exactly one` |
| 42 | short.plaintext@example.com | `password is shorter than 8 characters` |
| 43 | hash.in.password.field@example.com | `password looks like a hash; use password_hash for pre-hashed credentials` |

### Rows worth understanding

**Row 23 is the one that reads as accepted and is not.** It carries a real
bcrypt digest *and* a Google identity, but `email_verified` is false. An
imported provider subject only matches if this application uses the same OAuth
client the source system did; when it does not, the fallback that would rescue
the account — matching on a verified email at first social sign-in and linking
the identity server-side — is itself refused on an unverified address. The row
would occupy the user's single slot for that provider and lock them out
silently, so it is refused up front. Set `email_verified: true`, as rows 20-22
do, and it imports.

**Rows 35 and 36 are the privilege-escalation cases.** They ask for `owner` and `super_admin`, both system roles.
The refusal reports it as *unknown* rather than *forbidden*, because
`importRoleMap` only ever loads `is_system = false` roles — so from the
importer's perspective it genuinely is not an assignable role. That also means
the response never confirms which administrative roles exist, which is the right
answer to give an uploaded file.

**Rows 30-32 are why a digest you cannot verify is not an import format.** The
server refuses any hash it has no verifier for. Accepting them would create
accounts that exist and can never be signed in to — a failure invisible until
the user complains. Note the contrast with rows 24-26: a plaintext password *is*
accepted, in the `password` field, and hashed here.

**Rows 41-43 are the credential-field mix-ups.** A row carrying both forms is
ambiguous about which credential wins (41); a plaintext below the minimum length
would create an account weaker than `/register` allows (42); and a digest pasted
into `password` would be hashed *again*, so the password the user actually holds
would never work (43).

**Row 40 is caught against the file, not the database.** Duplicate detection
covers the upload itself, so the second Jane is rejected at validation rather
than failing against the unique index halfway through a commit.

**Rows 20-23, 26, 38 and 39 need an application-scoped import.** `user_identities.application_id`
is `NOT NULL`, so identities are only valid when the import targets a specific
application. Run the same file at tenant level (omit `/applications/$APP_ID`)
and those rows flip to `identities require an application-scoped import`. The
four `EMC` rows — 16, 17, 19 and 25 — fail there too, since an application role
is not in scope for a tenant-level import, so the whole file gives
`create=17 reject=26` instead of `create=25 reject=18`.

## Testing export

After committing, `GET .../users/export` returns the directory as CSV. Three
things to check:

- **No credential material.** No password hash, TOTP secret, or passkey appears
  in any column — enforced by the query, not by a filter that could be lifted.
- **Formula injection is neutralised.** Register a user whose first name is
  `=HYPERLINK("http://evil.example","click")`, export, and open the CSV in Excel
  or Sheets: the cell shows the text rather than running it. The leading
  apostrophe is the guard.
- **No system-role holders.** The tenant's owner and super_admin accounts are
  absent. They are left out so the export stays re-importable: `importRoleMap`
  refuses system roles, so those rows would come back as exactly the rejection
  rows 35 and 36 demonstrate.
