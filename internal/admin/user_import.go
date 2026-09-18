// user_import.go — bulk user import for migrations off another identity provider.
//
// # Why JSON and not CSV
//
// The export beside this file is CSV because a user row is flat. An import row
// is not: a credential is {algorithm, digest} and a federated account is
// {provider, subject, email}, repeated. Auth0 and Keycloak both take JSON for
// exactly this reason, and Okta takes a JSON object per user. CSV survives as an
// import format only where credentials are not imported at all (Cognito).
//
// # Why pre-hashed, and why that makes this cheap
//
// internal/password already verifies bcrypt alongside Argon2id and rewrites any
// foreign or stale hash on the owner's next successful login (NeedsRehash
// returns true for "bcrypt and anything unrecognised"). A migrated corpus
// therefore keeps working on arrival and converges to current Argon2id
// parameters by itself, with no password reset and no mass rehash.
//
// That is what keeps this import synchronous. Hashing 10k passwords with
// Argon2id at m=47104 costs 5-15 minutes of CPU and would need a durable job
// runner; storing 10k already-hashed strings costs an INSERT each. The
// architecture removed the work rather than the work being avoided here.
//
// Accepted digests are consequently limited to the two schemes password.Verify
// can read: bcrypt ($2a/$2b/$2y) and Argon2id in PHC form. A scheme that keeps
// its salt in a separate field (Okta's PBKDF2/SHA export shape) cannot be
// imported without somewhere to put the salt, and user_credentials has one
// column.
//
// # Shape
//
// Validate-then-commit, per Auth0's dry-run-and-report model: Validate writes
// nothing and returns a per-row verdict; Commit applies the rows it accepted.
// Both enforce tenant and application scope from the CALLER's context, never
// from the file, and both re-run CreateUser's role invariants on every row — a
// bulk path that validates once and loops is privilege escalation with an
// upload as the payload.
package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/engineersmind/emc-auth-server/internal/emailaddr"
	"github.com/engineersmind/emc-auth-server/internal/password"
)

// maxImportRows bounds one import. Auth0 caps a users-import job at 500; this is
// higher because no hashing happens here, but it is still bounded so a single
// request cannot hold a connection or a transaction budget indefinitely.
const maxImportRows = 5000

// ImportIdentity is a federated account to link to the imported user.
//
// user_identities.application_id is NOT NULL, so an identity is only meaningful
// for an application-scoped import; validation rejects one on a tenant-level row
// rather than silently dropping it.
type ImportIdentity struct {
	Provider      string `json:"provider"`
	ProviderSub   string `json:"provider_sub"`
	ProviderEmail string `json:"provider_email"`
}

// ImportUser is one row of the import document.
type ImportUser struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`

	// EmailVerified carries the source IdP's verification state. Defaulting it
	// to false would re-challenge every migrated user for an address their old
	// provider already proved, which is the kind of friction that makes a
	// migration visible to end users.
	EmailVerified bool `json:"email_verified"`

	// IsActive defaults to true when the field is absent — see UnmarshalJSON.
	IsActive bool `json:"is_active"`

	// Role is the role NAME. Ids are not accepted: an id in an uploaded file is
	// an opaque integer the operator cannot check and an attacker can guess, and
	// it means nothing outside this database.
	Role string `json:"role"`

	// PasswordHash is a bcrypt or Argon2id PHC digest from the source system.
	// Empty is allowed when the row carries a Password or at least one identity.
	PasswordHash string `json:"password_hash"`

	// Password is a plaintext password, for the source systems that cannot
	// export digests. Hashed by the import worker with current parameters.
	//
	// Mutually exclusive with PasswordHash. A row carrying both is ambiguous
	// about which credential is authoritative, and silently preferring one
	// would mean an operator who made a mistake in their export script gets an
	// account whose password is not the one they think it is.
	//
	// Costs ~65ms of Argon2id per row against a process-wide concurrency cap,
	// which is why a document containing any plaintext runs as a background job
	// rather than inside the request.
	Password string `json:"password"`

	// PasswordChangedAt is when the password was last set in the SOURCE system.
	// user_credentials.password_changed_at defaults to NOW(), which for an
	// imported credential is false — it would report every migrated user as
	// having just rotated, and any future password-age policy would read that.
	PasswordChangedAt *time.Time `json:"password_changed_at"`

	Identities []ImportIdentity `json:"identities"`
}

// UnmarshalJSON makes is_active default to true when the key is absent, while
// still honouring an explicit false. A plain struct decode cannot express that:
// the zero value of bool is false, so an omitted is_active would import every
// user deactivated.
//
// The unknown-field check is repeated here on purpose. DisallowUnknownFields on
// the handler's decoder does not reach inside a type that implements
// UnmarshalJSON — the decoder hands this method the raw bytes and whatever it
// does with them is its own business — so a row with "passwordHash" instead of
// "password_hash" was accepted by the outer decoder and dropped here. With
// email_verified true that row still validates (a verified address is a route
// in) and imports with no credential at all: an account the operator believes
// carries a migrated password and which nobody can ever sign into. Rejecting
// the upload is the only outcome that tells them.
//
// The export-only fields below are named explicitly so they keep being accepted
// and ignored. ExportedUser emits application, created_at, last_login_at and
// login_count — an export is also read by people reconciling licences and
// dormancy — and the documented round trip is "export, add credentials,
// re-import", so a strictness that refused the server's own export would break
// the one thing the JSON format exists for. They are read into nothing on
// purpose: an import does not get to choose a user's created_at or claim a
// login history. Every OTHER unknown key is now a hard error, which is the
// point — an operator who typed the wrong one hears about it.
func (u *ImportUser) UnmarshalJSON(b []byte) error {
	type raw ImportUser
	var probe struct {
		raw
		IsActive *bool `json:"is_active"`

		Application string     `json:"application"`
		CreatedAt   *time.Time `json:"created_at"`
		LastLoginAt *time.Time `json:"last_login_at"`
		LoginCount  *int64     `json:"login_count"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&probe); err != nil {
		return err
	}
	*u = ImportUser(probe.raw)
	u.IsActive = probe.IsActive == nil || *probe.IsActive
	return nil
}

// ImportDocument is the uploaded payload.
type ImportDocument struct {
	Users []ImportUser `json:"users"`

	// UpdateExisting amends users that already exist instead of skipping them.
	//
	// OFF by default, and deliberately so. A file is a snapshot of somebody's
	// export — possibly stale, possibly hand-edited — and an operator who
	// re-uploads it to fix three rejected rows does not expect the other two
	// hundred to be rewritten from whatever that file happened to contain.
	// Auth0 takes the same position (upsert defaults to false) and routes
	// corrections through a separate assignment endpoint.
	//
	// When on, only the ROLE and PROFILE fields are amended. Credentials are
	// never touched: a file that could overwrite password_hash on existing
	// accounts is a credential-stuffing primitive, and no migration needs it.
	UpdateExisting bool `json:"update_existing"`
}

// Import row outcomes.
const (
	ImportOutcomeCreate = "create" // will be / was created
	ImportOutcomeSkip   = "skip"   // already present; left untouched
	ImportOutcomeUpdate = "update" // already present; role/profile amended
	ImportOutcomeReject = "reject" // failed validation or failed to write
)

// ImportRowResult is the per-row verdict. Index is the row's position in the
// uploaded document so an operator can fix the source file and re-upload it;
// the import is idempotent on (tenant, application, email), so a corrected
// re-run creates only what it failed to create the first time.
type ImportRowResult struct {
	Index   int    `json:"index"`
	Email   string `json:"email"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
}

// ImportResult summarises a validate or commit run.
type ImportResult struct {
	DryRun   bool              `json:"dry_run"`
	Total    int               `json:"total"`
	Created  int               `json:"created"`
	Skipped  int               `json:"skipped"`
	Updated  int               `json:"updated"`
	Rejected int               `json:"rejected"`
	Rows     []ImportRowResult `json:"rows"`
}

// ErrImportTooLarge is returned when a document exceeds maxImportRows.
var ErrImportTooLarge = fmt.Errorf("import exceeds %d rows", maxImportRows)

// ValidateImport checks every row and writes nothing.
//
// A dry run that touches the users table is not a dry run: this is the stage an
// operator reviews before anything exists, and it is the only chance to catch a
// bad file while nothing has been created.
func (s *Service) ValidateImport(ctx context.Context, tenantID int64, applicationID *int64, doc ImportDocument) (*ImportResult, error) {
	return s.runImport(ctx, tenantID, applicationID, doc, true)
}

// CommitImport creates the rows that pass validation.
//
// Per-row transactions, not one transaction for the document: a 5,000-row
// import that rolls back entirely because row 4,999 is malformed is unusable,
// and an operator forced to bisect a file by hand will do something worse
// instead. Rows that fail are reported and the run continues.
func (s *Service) CommitImport(ctx context.Context, tenantID int64, applicationID *int64, doc ImportDocument) (*ImportResult, error) {
	return s.runImport(ctx, tenantID, applicationID, doc, false)
}

func (s *Service) runImport(ctx context.Context, tenantID int64, applicationID *int64, doc ImportDocument, dryRun bool) (*ImportResult, error) {
	if len(doc.Users) > maxImportRows {
		return nil, ErrImportTooLarge
	}

	// Roles resolved once, by name, within the import's own scope. Doing this
	// per row would be N queries for a value that cannot change mid-import, and
	// resolving outside the scope would let a file name another application's
	// role.
	roles, err := s.importRoleMap(ctx, tenantID, applicationID)
	if err != nil {
		return nil, err
	}

	// The application's default role, applied to rows that name none. Resolved
	// once for the same reason the role map is.
	defaultRoleID, err := s.importDefaultRole(ctx, tenantID, applicationID)
	if err != nil {
		return nil, err
	}

	res := &ImportResult{DryRun: dryRun, Total: len(doc.Users)}

	// Duplicate detection has to cover the file itself, not just the database:
	// two rows with the same address inside one upload would otherwise both pass
	// validation and the second would fail at the unique index during commit.
	seen := make(map[string]int, len(doc.Users))

	for i, u := range doc.Users {
		row := ImportRowResult{Index: i, Email: u.Email}

		email := emailaddr.Normalize(u.Email)
		if email == "" || !strings.Contains(email, "@") {
			res.reject(row, "invalid email")
			continue
		}
		row.Email = email

		if first, dup := seen[email]; dup {
			// Reported 1-based: Index is a zero-based array position, but this
			// string is read by a person looking at their own file, and every
			// editor numbers the first line 1.
			res.reject(row, fmt.Sprintf("duplicate of row %d in this file", first+1))
			continue
		}
		seen[email] = i

		// A row carrying both forms is ambiguous about which credential wins.
		// Rejecting is the only honest answer: silently preferring one would
		// give the operator an account whose password is not the one they
		// believe they imported, and they would not find out until a user
		// complained.
		if u.PasswordHash != "" && u.Password != "" {
			res.reject(row, "row has both password_hash and password; supply exactly one")
			continue
		}

		// A verified address counts as a route in, because it is one: at first
		// social sign-in the server matches on a verified email and links the
		// provider identity itself. That is the SHAPE A REAL MIGRATION TAKES —
		// subjects issued by the source system's OAuth client never match this
		// one, so the guidance is to omit identities entirely and let the link
		// form on first use. Rejecting those rows would refuse the exact file
		// the documentation tells people to build.
		//
		// Without any of the three, the account genuinely has no way in: no
		// credential, no identity, and no verified address to link against. That
		// is a malformed export rather than an intent.
		if u.PasswordHash == "" && u.Password == "" && len(u.Identities) == 0 && !u.EmailVerified {
			res.reject(row, "row has no password_hash, password or identities, and the email is "+
				"not verified; the account would have no way to sign in")
			continue
		}

		if u.PasswordHash != "" {
			if err := validateImportHash(u.PasswordHash); err != nil {
				res.reject(row, err.Error())
				continue
			}
		}

		if u.Password != "" {
			if err := validateImportPlaintext(u.Password); err != nil {
				res.reject(row, err.Error())
				continue
			}
		}

		if len(u.Identities) > 0 && applicationID == nil {
			res.reject(row, "identities require an application-scoped import; user_identities.application_id is NOT NULL")
			continue
		}
		if err := validateIdentities(u.Identities); err != nil {
			res.reject(row, err.Error())
			continue
		}

		// An identity on an unverified address is a dead end in both directions,
		// so it is refused rather than written.
		//
		// A provider subject is issued per OAuth client. Unless the target
		// application uses the SAME client the source system did, the subject
		// being imported is one this deployment will never be shown — and the
		// row it creates occupies the user's single slot for that provider
		// (user_identities_user_provider_key). That blocks the fallback which
		// would otherwise have rescued them: at first social sign-in the server
		// looks the subject up, misses, then matches on a VERIFIED email and
		// links the identity itself.
		//
		// With email_verified false, that fallback is refused too
		// (ErrOAuthLinkConflict — linking a social account to an unverified
		// address is an account-takeover path). So the account would have no
		// password, a subject that never matches, and no way to earn a working
		// link. The user is simply locked out, silently, until somebody deletes
		// the row by hand.
		if len(u.Identities) > 0 && !u.EmailVerified {
			res.reject(row, "identities require email_verified: true — an imported subject only "+
				"matches if this application uses the same OAuth client as the source, and the "+
				"email fallback that would otherwise link the account needs a verified address")
			continue
		}

		// Role resolution, in three tiers:
		//
		//   1. the row names a role  -> that role
		//   2. the row names none    -> the application's default role, the same
		//                               one self-registration picks up
		//   3. no default configured -> no role
		//
		// Tier 2 is what stops a migrated user being less privileged than the
		// identical user who signs up through /register a minute later. An
		// imported account with no role holds no permissions at all, which looks
		// like a broken migration rather than a deliberate choice.
		//
		// The name is trimmed but NOT case-folded. Surrounding whitespace is
		// invisible in the spreadsheet an export came from and never intentional,
		// so rejecting " EMC " would be a puzzle with no clue attached. Case is
		// different: roles.name is unique per (tenant, application)
		// case-sensitively, so "emc" and "EMC" can both exist as separate roles
		// and guessing between them would hand out the wrong one.
		// Shared with the worker's own row handling, so a job validated here and
		// applied there can never disagree about which role a row resolves to.
		roleID, roleOK := resolveImportRole(u.Role, roles, defaultRoleID)
		if !roleOK {
			// Deliberately says "not available" rather than naming why. A role
			// can be missing here for two reasons — it does not exist, or it
			// exists as a system role and is never assignable — and
			// distinguishing them would confirm to an uploaded file that
			// "owner" and "super_admin" are real roles in this tenant. The
			// operator's fix is the same either way: create the role in this
			// application, or correct the name.
			res.reject(row, fmt.Sprintf(
				"role %q is not available in this application — create it first, or correct the name",
				strings.TrimSpace(u.Role)))
			continue
		}

		existing, err := s.importUserExists(ctx, tenantID, applicationID, email)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			if !doc.UpdateExisting {
				row.Outcome = ImportOutcomeSkip
				row.Reason = "user already exists"
				res.Rows = append(res.Rows, row)
				res.Skipped++
				continue
			}

			// Spell out the role change rather than reporting a bare "updated".
			// A demotion and a promotion are the same word otherwise, and the
			// dry run is the only place an operator can catch the former before
			// it happens.
			newRoleName := roleNameFor(roles, roleID)
			row.Outcome = ImportOutcomeUpdate
			if newRoleName != existing.roleName {
				row.Reason = fmt.Sprintf("role %s → %s",
					displayRole(existing.roleName), displayRole(newRoleName))
			} else {
				row.Reason = "profile updated; role unchanged"
			}

			if !dryRun {
				if err := s.updateImportedUser(ctx, tenantID, existing.id, u, roleID); err != nil {
					res.reject(row, "update failed")
					continue
				}
				// A role change does not reach an already-issued access token:
				// permissions are baked in at login and the middleware reads
				// them from the claims. Without this the demotion is advisory
				// until the token expires — and in a bulk run that is every
				// amended user at once.
				if newRoleName != existing.roleName && s.authSvc != nil {
					s.authSvc.DenyUserSessions(ctx, existing.id, tenantID)
				}
			}

			res.Rows = append(res.Rows, row)
			res.Updated++
			continue
		}

		if dryRun {
			row.Outcome = ImportOutcomeCreate
			res.Rows = append(res.Rows, row)
			res.Created++
			continue
		}

		if err := s.insertImportedUser(ctx, tenantID, applicationID, email, u, roleID); err != nil {
			if isDuplicateErr(err) {
				// Lost a race against a concurrent create between the existence
				// check and the insert. Reported as a skip, not a failure: the
				// desired end state (the user exists) holds.
				row.Outcome = ImportOutcomeSkip
				row.Reason = "user already exists"
				res.Rows = append(res.Rows, row)
				res.Skipped++
				continue
			}
			// The underlying error is deliberately not echoed: it can carry
			// column values and constraint names, and this report is handed
			// back over the API.
			res.reject(row, "write failed")
			continue
		}

		row.Outcome = ImportOutcomeCreate
		res.Rows = append(res.Rows, row)
		res.Created++
	}

	return res, nil
}

func (r *ImportResult) reject(row ImportRowResult, reason string) {
	row.Outcome = ImportOutcomeReject
	row.Reason = reason
	r.Rows = append(r.Rows, row)
	r.Rejected++
}

// validateImportHash accepts only what password.Verify can read back.
//
// Checked before any write so a malformed digest is a dry-run rejection rather
// than an account that exists and can never be logged into — a failure mode
// that is invisible until the user complains.
func validateImportHash(h string) error {
	// Identify alone is not enough, and that was the gap: it reads the prefix
	// only — as its own doc says — so `$2a$10$abc` was accepted and stored, and
	// the account it created could never authenticate. bcrypt.Cost refuses it at
	// every login and nothing in the UI can explain why a password that imported
	// successfully does not work.
	//
	// ValidateStoredHash runs each algorithm's real parser, and for Argon2id
	// also bounds the cost parameters — so an uploaded hash cannot declare a
	// gigabyte of memory and turn the first login into an OOM.
	switch password.Identify(h) {
	case password.AlgorithmBcrypt, password.AlgorithmArgon2id:
		if err := password.ValidateStoredHash(h); err != nil {
			return fmt.Errorf("unusable password_hash: %v", err)
		}
		return nil
	default:
		return errors.New("unsupported password_hash: expected bcrypt ($2a/$2b/$2y) or argon2id PHC")
	}
}

// minImportPasswordLen matches the floor the reset and invitation flows apply.
// An import that accepted weaker passwords than the product's own set-password
// paths would be a way around the policy rather than a migration tool.
const minImportPasswordLen = 8

// maxImportPasswordLen bounds the hashing work one row can ask for.
//
// Argon2id's cost is dominated by its memory parameter rather than input
// length, so this is not a denial-of-service bound so much as a sanity one: a
// megabyte in a password field is a malformed export, not a credential.
const maxImportPasswordLen = 256

// validateImportPlaintext checks a plaintext password before the job is
// accepted, so a bad row fails in the dry run rather than after the worker has
// already spent 65ms of Argon2id on it.
func validateImportPlaintext(pw string) error {
	if len(pw) < minImportPasswordLen {
		return fmt.Errorf("password is shorter than %d characters", minImportPasswordLen)
	}
	if len(pw) > maxImportPasswordLen {
		return fmt.Errorf("password is longer than %d characters", maxImportPasswordLen)
	}
	// A digest in the plaintext field is the likeliest mistake an export script
	// makes, and it would otherwise be hashed a second time — leaving an
	// account whose password is a bcrypt string nobody knows.
	if password.Identify(pw) != password.AlgorithmUnknown {
		return errors.New("password looks like a hash; use password_hash for pre-hashed credentials")
	}
	return nil
}

func validateIdentities(ids []ImportIdentity) error {
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id.Provider == "" || id.ProviderSub == "" {
			return errors.New("identity requires provider and provider_sub")
		}
		// user_identities has a unique index on (user_id, provider): one
		// identity per provider per user, so two links for the same provider on
		// one row cannot both be written.
		if seen[id.Provider] {
			return fmt.Errorf("duplicate identity for provider %q", id.Provider)
		}
		seen[id.Provider] = true
	}
	return nil
}

// importRoleMap resolves assignable role names within the import's scope.
//
// Mirrors the two invariants CreateUser enforces per call, as a query rather
// than a per-row check: is_system roles are excluded (administrative tiers are
// granted by invitation, never by assignment — see AssignUserRole), and the
// role's application scope must equal the import's, so a file cannot name
// another application's role.
func (s *Service) importRoleMap(ctx context.Context, tenantID int64, applicationID *int64) (map[string]int64, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT name, id FROM roles
		WHERE tenant_id = $1
		  AND is_system = false
		  AND deleted_at IS NULL
		  AND application_id IS NOT DISTINCT FROM $2
	`, tenantID, applicationID)
	if err != nil {
		return nil, fmt.Errorf("import: load roles: %w", err)
	}
	defer rows.Close()

	out := map[string]int64{}
	for rows.Next() {
		var name string
		var id int64
		if err := rows.Scan(&name, &id); err != nil {
			return nil, fmt.Errorf("import: scan role: %w", err)
		}
		out[name] = id
	}
	return out, rows.Err()
}

// importDefaultRole returns the application's default role, or nil when none is
// configured.
//
// Deliberately the same predicate self-registration uses (auth.Register):
// application-scoped, is_default, and is_system = false. A migrated user and a
// user who signs up through /register a minute later should land identically —
// anything else makes "how did this account get its permissions?" depend on
// which door it came through.
//
// Tenant-level imports get nil: default roles are defined per application, and
// migration 00043's partial unique index deliberately excludes
// application_id IS NULL so a tenant-management role can never be a default.
func (s *Service) importDefaultRole(ctx context.Context, tenantID int64, applicationID *int64) (*int64, error) {
	if applicationID == nil {
		return nil, nil
	}
	var id int64
	err := s.pool.QueryRow(ctx, `
		SELECT id FROM roles
		WHERE tenant_id = $1
		  AND application_id = $2
		  AND is_default = true
		  AND is_system = false
		  AND deleted_at IS NULL
	`, tenantID, *applicationID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("import: load default role: %w", err)
	}
	return &id, nil
}

// importUserExists mirrors the two partial unique indexes on users, which split
// on whether application_id is NULL and both exclude soft-deleted rows. Keying
// on email alone would be wrong in both directions: it would collide across
// applications, and it would refuse to re-create a user whose old account was
// deleted.
// Returns the user's id and current role name alongside the flag, so an update
// can report what it is about to change rather than only that it changed.
func (s *Service) importUserExists(ctx context.Context, tenantID int64, applicationID *int64, email string) (existing *importExistingUser, err error) {
	var u importExistingUser
	err = s.pool.QueryRow(ctx, `
		SELECT u.id, COALESCE(r.name, '')
		FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.tenant_id = $1
		  AND u.email = $2
		  AND u.deleted_at IS NULL
		  AND u.application_id IS NOT DISTINCT FROM $3
		LIMIT 1
	`, tenantID, email, applicationID).Scan(&u.id, &u.roleName)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("import: existence check: %w", err)
	}
	return &u, nil
}

type importExistingUser struct {
	id       int64
	roleName string
}

// insertImportedUser writes one user, its credential and its identities in a
// single transaction. The row is the unit of atomicity: either the whole user
// arrives or none of it does, and a failure here does not affect other rows.
func (s *Service) insertImportedUser(ctx context.Context, tenantID int64, applicationID *int64, email string, u ImportUser, roleID *int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("import: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var userID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO users (tenant_id, application_id, email, first_name, last_name,
		                   role_id, is_active, email_verified)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`, tenantID, applicationID, email, u.FirstName, u.LastName,
		roleID, u.IsActive, u.EmailVerified).Scan(&userID)
	if err != nil {
		return err
	}

	// Exactly one of the two is set — validation rejects a row carrying both.
	storedHash := u.PasswordHash
	if storedHash == "" && u.Password != "" {
		// Hashed here, inside the row's own transaction, so a failure leaves no
		// user behind. Uses the shared hasher, and therefore the shared
		// concurrency guard: the import competes for slots with logins rather
		// than adding a second, independent memory ceiling.
		h, err := s.hasher().Hash(ctx, u.Password)
		if err != nil {
			return fmt.Errorf("import: hash password: %w", err)
		}
		storedHash = h
	}

	if storedHash != "" {
		// password_changed_at is taken from the SOURCE system where the export
		// carried one, rather than letting it default to NOW(). An imported
		// credential was not just rotated, and password-age policy reads this
		// column.
		//
		// A plaintext row is the exception: that password IS being set now, so
		// an inherited timestamp would be a lie in the other direction.
		changedAt := time.Now().UTC()
		if u.PasswordChangedAt != nil && u.PasswordHash != "" {
			changedAt = u.PasswordChangedAt.UTC()
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO user_credentials (user_id, tenant_id, password_hash, password_changed_at)
			VALUES ($1, $2, $3, $4)
		`, userID, tenantID, storedHash, changedAt); err != nil {
			return err
		}
	}

	for _, id := range u.Identities {
		if _, err := tx.Exec(ctx, `
			INSERT INTO user_identities (user_id, tenant_id, application_id,
			                             provider, provider_sub, provider_email)
			VALUES ($1, $2, $3, $4, $5, $6)
		`, userID, tenantID, *applicationID,
			id.Provider, id.ProviderSub, nullIfEmpty(id.ProviderEmail)); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// roleNameFor reverses the name→id map so an update can name the role it is
// about to apply. The map is small (one application's roles) and this runs only
// for rows that are actually being amended.
func roleNameFor(roles map[string]int64, id *int64) string {
	if id == nil {
		return ""
	}
	for name, rid := range roles {
		if rid == *id {
			return name
		}
	}
	// The default role is resolved separately and may not be in the assignable
	// map; naming it is a nicety, and "(unchanged)" would be a lie.
	return ""
}

func displayRole(name string) string {
	if name == "" {
		return "(none)"
	}
	return name
}

// updateImportedUser amends an existing user's role and profile.
//
// Credentials are deliberately absent: password_hash, email_verified and the
// identity rows are all left alone. Overwriting a live credential from an
// uploaded file has no legitimate migration use and turns an import into a way
// to take over accounts; email_verified is left because downgrading a verified
// address from a stale file would silently lock someone out of their own
// account.
//
// first_name and last_name are only written when the row carries them, so a
// file listing nothing but emails and roles does not blank everybody's name.
func (s *Service) updateImportedUser(ctx context.Context, tenantID, userID int64, u ImportUser, roleID *int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE users SET
		    role_id    = $1,
		    first_name = CASE WHEN $2 = '' THEN first_name ELSE $2 END,
		    last_name  = CASE WHEN $3 = '' THEN last_name  ELSE $3 END,
		    updated_at = NOW()
		WHERE id = $4 AND tenant_id = $5 AND deleted_at IS NULL
	`, roleID, u.FirstName, u.LastName, userID, tenantID)
	if err != nil {
		return fmt.Errorf("import: update user: %w", err)
	}
	return nil
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
