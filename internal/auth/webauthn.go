package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

// ---------------------------------------------------------------------------
// WebAuthn / passkeys — issue #112.
//
// Design notes live in docs/WEBAUTHN_MASTER_PLAN.md. Three properties drive
// every decision in this file:
//
//  1. A credential is bound to an RP ID by the browser, not by us. We store the
//     rp_id and filter every lookup on it, so the credentials we OFFER match the
//     ones the browser will ACCEPT. Getting this wrong is not an exploit, it is
//     a dead end the user cannot diagnose.
//
//  2. Nothing secret is stored. The security comes from scoping (tenant + RP),
//     from the challenge being single-use, and from the flag checks below —
//     never from confidentiality of the credential table.
//
//  3. No trust decision is ever parameterised by the client. RP ID, the origin
//     allow-list, and whether user verification is required all come from
//     server-side policy (see passkeypolicy.go), because those three values are
//     precisely what a phishing page would want to choose.
// ---------------------------------------------------------------------------

// Challenge lifetimes. Short on purpose: a challenge is a one-shot nonce, and a
// long window is a replay window. 120s is enough for a biometric prompt plus a
// slow authenticator, and short enough that an abandoned tab expires rather than
// lingering — see ErrChallengeExpired for how that is surfaced.
const (
	webauthnRegTTL   = 2 * time.Minute
	webauthnLoginTTL = 2 * time.Minute
)

// webauthnUserHandleLen is the size of the opaque per-user handle. The spec
// permits up to 64 bytes and recommends using them; there is no reason to use
// fewer.
const webauthnUserHandleLen = 64

// passkeyNameMaxLen bounds the user-supplied label. Mirrors the CHECK constraint
// added by migration 00072 — enforced in both places because the column is also
// reachable by hand during support work.
const passkeyNameMaxLen = 64

var (
	// ErrWebAuthnNotConfigured is returned when the server has no relying-party
	// configuration, so no ceremony can be started.
	ErrWebAuthnNotConfigured = errors.New("webauthn is not configured on this server")

	// ErrCookieSessionNotAvailable reports that the verified identity is
	// application-scoped and so cannot be given a browser cookie session.
	//
	// Returned by LoginWebAuthnForCookieSession INSTEAD of issuing tokens, which
	// is the point of it: the assertion succeeded, and the refusal is about where
	// the resulting credential may be stored, not about whether the user proved
	// who they are. Not a WebAuthn error as such — it names a transport
	// constraint the /auth/passkey/session endpoint has and /login/complete does
	// not.
	ErrCookieSessionNotAvailable = errors.New("cookie sessions are not available to application-scoped identities")

	// ErrChallengeExpired is returned when the ceremony state behind a token is
	// gone. It is deliberately DISTINGUISHABLE from a verification failure: the
	// frontend re-arms silently on this one, because the usual cause is a login
	// page left open past the TTL, which the user did not do wrong and cannot
	// act on. Every genuine verification failure returns ErrWebAuthnVerification
	// instead, and that one says nothing about why.
	ErrChallengeExpired = errors.New("challenge expired")

	// ErrWebAuthnVerification is the single, uninformative error for every
	// genuine ceremony failure — bad signature, wrong origin, unknown
	// credential, missing user verification. One error for all of them so the
	// endpoint cannot be used to probe which credentials or accounts exist.
	ErrWebAuthnVerification = errors.New("passkey verification failed")

	// ErrUserVerificationRequired is returned when a verified assertion carried no
	// user-verification gesture under a policy that demands one.
	//
	// It exists so the refusal is distinguishable INTERNALLY — in the log, in the
	// audit row, and in a test that needs to prove the UV requirement is what
	// rejected an assertion rather than some other failure it would be
	// indistinguishable from. The client is still told only the opaque
	// webauthn_failed: see loginRejected. A separate sentinel for an identical
	// response is the point, not an oversight.
	ErrUserVerificationRequired = errors.New("passkey verification failed: user verification required")

	// ErrCredentialCloned is returned when an assertion shows evidence that the
	// private key exists in more than one place. Wrapped by
	// ClonedCredentialError, which carries who and which credential — see there
	// for why that detail has to escape the service.
	ErrCredentialCloned = errors.New("passkey appears to be cloned")

	// ErrCredentialNotDiscoverable is returned when registration produced a
	// non-discoverable credential. Rejected rather than stored: a
	// non-discoverable credential can never satisfy a passwordless sign-in,
	// so keeping it would hand the user a passkey that silently never works.
	ErrCredentialNotDiscoverable = errors.New("authenticator did not create a discoverable passkey")

	// ErrCredentialAlreadyRegistered is returned when the authenticator offered
	// a credential we already hold. excludeCredentials should prevent it, but
	// only in browsers that honour it.
	ErrCredentialAlreadyRegistered = errors.New("this passkey is already registered")

	// ErrCredentialNotFound is returned by credential management when the target
	// does not exist within the caller's own scope. A credential belonging to
	// another user is reported as not found, never touched.
	ErrCredentialNotFound = errors.New("passkey not found")

	// ErrLastFactor is returned when removing a passkey would leave the account
	// with no way to sign in at all — see RevokeCredential.
	ErrLastFactor = errors.New("this is the only way to sign in to this account")

	// ErrInvalidPasskeyName is returned when a label is empty after trimming or
	// longer than passkeyNameMaxLen.
	ErrInvalidPasskeyName = errors.New("passkey name must be 1 to 64 characters")
)

// ClonedCredentialError reports a cloned-authenticator detection with enough
// detail to act on it.
//
// The detail has to leave the service because the response to a clone is not
// "reject this attempt" — that is the least of it. It is: end every session the
// account has, and write a critical audit event naming the credential. Neither
// is possible from a bare sentinel error, and re-deriving the user from the
// request afterwards is not possible either, because a passwordless assertion is
// the only thing that named them.
type ClonedCredentialError struct {
	UserID          int64
	TenantID        int64
	CredentialRowID int64
	CredentialLabel string
	// Reason is a stable machine-readable key for the audit metadata:
	// "sign_count_regression" or "backup_eligibility_changed".
	Reason string
}

func (e *ClonedCredentialError) Error() string {
	return fmt.Sprintf("passkey appears to be cloned (%s)", e.Reason)
}

// Is makes errors.Is(err, ErrCredentialCloned) work, so call sites that only
// need to know "was this a clone" stay unchanged while the ones that must act on
// it use errors.As.
func (e *ClonedCredentialError) Is(target error) bool { return target == ErrCredentialCloned }

// WebAuthnConfig is the deployment-level relying-party configuration, read from
// WEBAUTHN_* environment variables. It is the fallback that per-tenant policy
// inherits from, and the floor that policy cannot relax — see
// PasskeyPolicyService.merge.
//
// None of it is ever taken from a request: RP ID and the origin allow-list are
// exactly what a phishing page would want to control, so they are server-side
// only.
type WebAuthnConfig struct {
	// RPID is the relying-party ID — the registrable domain, no scheme, no port
	// (e.g. "localhost", "insurance.acme.com").
	RPID string
	// RPDisplayName is what the authenticator shows the user when it asks
	// whether to create a passkey. The user sees this string, in their password
	// manager, effectively forever.
	RPDisplayName string
	// Origins is the exact-match allow-list of page origins permitted to run a
	// ceremony, INCLUDING scheme and port ("http://localhost:5173").
	Origins []string
	// RequireUserVerification demands a biometric or PIN gesture. Required for
	// passwordless: with no password in the flow, the gesture is the only
	// evidence the right human is present.
	RequireUserVerification bool
}

// WebAuthnService runs the registration and authentication ceremonies and owns
// the credential table.
type WebAuthnService struct {
	pool   *pgxpool.Pool
	redis  *redis.Client
	policy *PasskeyPolicyService
	// cfg is the deployment configuration, kept for the fallback path and for
	// reporting. Per-request configuration comes from policy, not from here.
	cfg WebAuthnConfig

	// rpCache holds one relying-party instance per distinct configuration.
	//
	// Built lazily and cached because webauthn.New validates and normalises its
	// config on every call, and a multi-tenant deployment resolves a relying
	// party on every ceremony — but the set of distinct configurations is the
	// number of tenant domains, not the number of requests.
	rpMu    sync.RWMutex
	rpCache map[string]*webauthn.WebAuthn

	logger zerolog.Logger
}

// NewWebAuthnService builds the service. A missing RPID is not an error — it
// disables the feature, so a deployment that has not configured WebAuthn simply
// does not serve it rather than failing to boot.
func NewWebAuthnService(pool *pgxpool.Pool, redisCli *redis.Client, cfg WebAuthnConfig, logger zerolog.Logger) (*WebAuthnService, error) {
	if cfg.RPID == "" {
		logger.Info().Msg("WEBAUTHN_RP_ID not set — passkey endpoints disabled")
		return nil, nil
	}
	if len(cfg.Origins) == 0 {
		return nil, fmt.Errorf("webauthn: WEBAUTHN_ORIGINS must list at least one origin when WEBAUTHN_RP_ID is set")
	}

	svc := &WebAuthnService{
		pool:    pool,
		redis:   redisCli,
		policy:  NewPasskeyPolicyService(pool, cfg, logger),
		cfg:     cfg,
		rpCache: make(map[string]*webauthn.WebAuthn),
		logger:  logger,
	}

	// Build the deployment's own relying party eagerly. A malformed
	// WEBAUTHN_RP_ID must fail at boot, where an operator is watching, rather
	// than on a user's first sign-in attempt.
	if _, err := svc.rpFor(PasskeyPolicy{
		RPID:                    cfg.RPID,
		RPDisplayName:           cfg.RPDisplayName,
		Origins:                 cfg.Origins,
		RequireUserVerification: cfg.RequireUserVerification,
	}); err != nil {
		return nil, err
	}
	return svc, nil
}

// Policy exposes the policy resolver so handlers and the admin write path can
// read and invalidate it without a second instance.
func (s *WebAuthnService) Policy() *PasskeyPolicyService {
	if s == nil {
		return nil
	}
	return s.policy
}

// RPID exposes the deployment's configured relying-party ID for handlers that
// report it. Per-request RP IDs come from policy.
func (s *WebAuthnService) RPID() string { return s.cfg.RPID }

// rpFor returns the relying party for a resolved policy, building it on first
// use.
//
// Keyed on every field that changes verification behaviour. Leaving any of them
// out of the key would serve a cached relying party that verifies against the
// wrong origin list — which is the one failure in this file that would look like
// success.
func (s *WebAuthnService) rpFor(p PasskeyPolicy) (*webauthn.WebAuthn, error) {
	if p.RPID == "" || len(p.Origins) == 0 {
		return nil, ErrWebAuthnNotConfigured
	}
	key := strings.Join([]string{
		p.RPID, p.RPDisplayName, strconv.FormatBool(p.RequireUserVerification),
		strings.Join(p.Origins, ","),
	}, "\x00")

	s.rpMu.RLock()
	rp, ok := s.rpCache[key]
	s.rpMu.RUnlock()
	if ok {
		return rp, nil
	}

	uv := protocol.VerificationPreferred
	if p.RequireUserVerification {
		uv = protocol.VerificationRequired
	}

	rp, err := webauthn.New(&webauthn.Config{
		RPID:          p.RPID,
		RPDisplayName: p.RPDisplayName,
		RPOrigins:     p.Origins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// Discoverable ("resident") keys are what make a username-less
			// sign-in possible. Required, not preferred: a non-discoverable
			// credential would register successfully and then never be offered
			// to the user, because login/begin sends no allowCredentials list
			// for the authenticator to match against.
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: uv,
		},
		// 'none' asks the authenticator not to identify its make and model. We
		// have no metadata service to check an attestation against, so asking
		// for one would collect an identifier we cannot verify. The AAGUID that
		// arrives anyway is used as a display label only — see aaguid.go.
		AttestationPreference: protocol.PreferNoAttestation,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: build relying party for %q: %w", p.RPID, err)
	}

	s.rpMu.Lock()
	s.rpCache[key] = rp
	s.rpMu.Unlock()
	return rp, nil
}

// AuthenticatorSelectionForTest exposes the resolved authenticator-selection
// criteria for the deployment's own relying party so tests can pin them.
//
// These two values — residentKey and userVerification — are the ones that fail
// SILENTLY when wrong: the ceremony still succeeds, and either the credential
// never satisfies a passwordless login or a single factor is treated as two.
// Nothing else in the system would notice, which is why they are worth a direct
// assertion rather than being left to an end-to-end test nobody runs on every
// commit.
func (s *WebAuthnService) AuthenticatorSelectionForTest() protocol.AuthenticatorSelection {
	rp, err := s.rpFor(PasskeyPolicy{
		RPID:                    s.cfg.RPID,
		RPDisplayName:           s.cfg.RPDisplayName,
		Origins:                 s.cfg.Origins,
		RequireUserVerification: s.cfg.RequireUserVerification,
	})
	if err != nil {
		return protocol.AuthenticatorSelection{}
	}
	return rp.Config.AuthenticatorSelection
}

// ---------------------------------------------------------------------------
// webauthnUser — the library's view of an account
// ---------------------------------------------------------------------------

// webauthnUser adapts one of our accounts to the library's User interface.
type webauthnUser struct {
	userID   int64
	tenantID int64
	handle   []byte
	email    string
	role     string
	appID    string
	creds    []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte { return u.handle }

// WebAuthnName is what the authenticator's account picker displays, so it must
// be the email — this is the one place a human-readable identifier belongs.
// WebAuthnID stays opaque (see the migration comment); they are different
// fields and conflating them either leaks PII into the handle or shows the user
// a meaningless blob.
func (u *webauthnUser) WebAuthnName() string        { return u.email }
func (u *webauthnUser) WebAuthnDisplayName() string { return u.email }

func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// beAligned returns a shallow copy of the user whose credential matching rawID
// carries the ASSERTED backup-eligibility flag rather than the stored one.
//
// It exists for exactly one reason: go-webauthn refuses a BE change with a
// generic bad request, which would mask a cloned authenticator as an ordinary
// verification failure and skip containment entirely (see LoginComplete). The
// library's BE comparison runs after the signature check, so suppressing it here
// removes no cryptographic guarantee — the signature is still verified against
// the stored public key, and the real stored flag is compared by our own check
// once verification has succeeded.
//
// The copy is deliberate. Mutating resolved.creds would leave the caller holding
// a credential set that no longer reflects the database, and the one field this
// touches is the field a clone detection turns on.
func beAligned(u *webauthnUser, rawID []byte, assertedBE bool) *webauthnUser {
	creds := make([]webauthn.Credential, len(u.creds))
	copy(creds, u.creds)
	for i := range creds {
		if bytes.Equal(creds[i].ID, rawID) {
			creds[i].Flags.BackupEligible = assertedBE
			break
		}
	}
	clone := *u
	clone.creds = creds
	return &clone
}

// ---------------------------------------------------------------------------
// User handle
// ---------------------------------------------------------------------------

// userHandle returns the account's stable opaque WebAuthn handle, creating it on
// first use. The insert is an upsert with a returning read so two concurrent
// first-time registrations cannot produce two handles for one account — which
// would split the user's credentials into two authenticator accounts.
func (s *WebAuthnService) userHandle(ctx context.Context, userID, tenantID int64) ([]byte, error) {
	// Scoped by tenant even though user_id alone is the primary key here, so no
	// cross-tenant row could be returned. The invariant is that every query in
	// this codebase names the tenant it means — the INSERT below already does —
	// and an unscoped read is the one that silently becomes wrong if this table
	// ever grows a composite key.
	var handle []byte
	err := s.pool.QueryRow(ctx,
		`SELECT handle FROM webauthn_user_handles WHERE user_id = $1 AND tenant_id = $2`,
		userID, tenantID,
	).Scan(&handle)
	if err == nil {
		return handle, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("load webauthn user handle: %w", err)
	}

	fresh := make([]byte, webauthnUserHandleLen)
	if _, err := rand.Read(fresh); err != nil {
		return nil, fmt.Errorf("generate webauthn user handle: %w", err)
	}

	err = s.pool.QueryRow(ctx, `
		INSERT INTO webauthn_user_handles (user_id, tenant_id, handle)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO UPDATE SET handle = webauthn_user_handles.handle
		RETURNING handle
	`, userID, tenantID, fresh).Scan(&handle)
	if err != nil {
		return nil, fmt.Errorf("create webauthn user handle: %w", err)
	}
	return handle, nil
}

// ---------------------------------------------------------------------------
// Credential storage
// ---------------------------------------------------------------------------

// StoredCredential is the API-facing view of a passkey. It carries no key
// material: the public key is useless to a client and the credential ID is only
// meaningful inside a ceremony.
type StoredCredential struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	RPID   string `json:"rp_id"`
	Synced bool   `json:"synced"`
	// SyncedLabel is the phrase to show a user. "This device only" is the fact
	// that matters to them: a device-bound passkey (Windows Hello) dies with the
	// laptop, a synced one does not.
	SyncedLabel string `json:"synced_label"`
	// AuthenticatorName is the model that created the credential ("iCloud
	// Keychain", "Windows Hello", "YubiKey 5 Series"), or empty when the
	// authenticator did not identify itself — which is the normal case under the
	// 'none' attestation we request. A DISPLAY LABEL ONLY: it comes from an
	// unattested response and must never gate anything. See aaguid.go.
	AuthenticatorName string `json:"authenticator_name,omitempty"`
	// AAGUID is the raw model identifier, so a frontend can supply its own icon
	// for a model we have no name for, and so an unrecognised authenticator is
	// still reportable in a support ticket.
	AAGUID     string     `json:"aaguid,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// setSyncLabel fills the derived display fields. One place, so the two callers
// that build a StoredCredential cannot word it differently.
func (c *StoredCredential) setSyncLabel() {
	c.SyncedLabel = "This device only"
	if c.Synced {
		c.SyncedLabel = "Synced across your devices"
	}
}

// loadCredentials returns the user's active credentials for one RP ID, in the
// library's shape. Scoped by tenant AND rp_id: offering a credential the
// browser will refuse produces an unexplainable dead end.
func (s *WebAuthnService) loadCredentials(ctx context.Context, userID, tenantID int64, rpID string) ([]webauthn.Credential, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT credential_id, public_key, attestation_type, transports,
		       sign_count, backup_eligible, backup_state, uv_capable, aaguid
		FROM webauthn_credentials
		WHERE user_id = $1 AND tenant_id = $2 AND rp_id = $3 AND is_active
	`, userID, tenantID, rpID)
	if err != nil {
		return nil, fmt.Errorf("load webauthn credentials: %w", err)
	}
	defer rows.Close()

	var creds []webauthn.Credential
	for rows.Next() {
		var (
			credID, pubKey, aaguid []byte
			attType                string
			transports             []string
			signCount              int64
			be, bs, uv             bool
		)
		if err := rows.Scan(&credID, &pubKey, &attType, &transports, &signCount, &be, &bs, &uv, &aaguid); err != nil {
			return nil, fmt.Errorf("scan webauthn credential: %w", err)
		}
		tr := make([]protocol.AuthenticatorTransport, 0, len(transports))
		for _, t := range transports {
			tr = append(tr, protocol.AuthenticatorTransport(t))
		}
		creds = append(creds, webauthn.Credential{
			ID:              credID,
			PublicKey:       pubKey,
			AttestationType: attType,
			Transport:       tr,
			Flags: webauthn.CredentialFlags{
				UserPresent:    true,
				UserVerified:   uv,
				BackupEligible: be,
				BackupState:    bs,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID: aaguid,
				// #nosec G115 -- the signature counter is a uint32 on the wire, so
				// every value this column ever receives came from a uint32 in the
				// first place. The column is BIGINT only because that is the
				// integer type the rest of this schema uses.
				SignCount: uint32(signCount),
			},
		})
	}
	return creds, rows.Err()
}

// ListCredentials returns the user's passkeys for display, newest first.
//
// Not filtered by rp_id, deliberately: this is the user's own inventory of
// devices, and a passkey they registered on another of the tenant's surfaces is
// still theirs to see and revoke. Filtering here would hide a credential the
// user cannot otherwise reach. Ceremony lookups filter; management does not.
func (s *WebAuthnService) ListCredentials(ctx context.Context, userID, tenantID int64) ([]StoredCredential, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::TEXT, name, rp_id, backup_state, aaguid, created_at, last_used_at
		FROM webauthn_credentials
		WHERE user_id = $1 AND tenant_id = $2 AND is_active
		ORDER BY created_at DESC
	`, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list webauthn credentials: %w", err)
	}
	defer rows.Close()

	out := []StoredCredential{}
	for rows.Next() {
		var c StoredCredential
		var aaguid []byte
		if err := rows.Scan(&c.ID, &c.Name, &c.RPID, &c.Synced, &aaguid, &c.CreatedAt, &c.LastUsedAt); err != nil {
			return nil, fmt.Errorf("scan webauthn credential row: %w", err)
		}
		c.AuthenticatorName = AuthenticatorName(aaguid)
		c.AAGUID = AAGUIDString(aaguid)
		c.setSyncLabel()
		out = append(out, c)
	}
	return out, rows.Err()
}

// RenameCredential relabels one of the caller's own passkeys.
//
// The label is the only thing distinguishing four passkeys in a settings list,
// and the name assigned at registration ("What device is this?") is the one a
// user is most likely to get wrong — they are mid-ceremony and guessing. Without
// this endpoint the only correction available is delete and re-enrol.
func (s *WebAuthnService) RenameCredential(ctx context.Context, userID, tenantID int64, credRowID, name string) (*StoredCredential, error) {
	clean := strings.TrimSpace(name)
	if clean == "" || len([]rune(clean)) > passkeyNameMaxLen {
		return nil, ErrInvalidPasskeyName
	}

	var c StoredCredential
	var aaguid []byte
	err := s.pool.QueryRow(ctx, `
		UPDATE webauthn_credentials SET name = $4
		WHERE id::TEXT = $1 AND user_id = $2 AND tenant_id = $3 AND is_active
		RETURNING id::TEXT, name, rp_id, backup_state, aaguid, created_at, last_used_at
	`, credRowID, userID, tenantID, clean).
		Scan(&c.ID, &c.Name, &c.RPID, &c.Synced, &aaguid, &c.CreatedAt, &c.LastUsedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrCredentialNotFound
		}
		return nil, fmt.Errorf("rename webauthn credential: %w", err)
	}
	c.AuthenticatorName = AuthenticatorName(aaguid)
	c.AAGUID = AAGUIDString(aaguid)
	c.setSyncLabel()
	return &c, nil
}

// RevokeCredential deactivates one of the caller's own passkeys. Scoped by user
// and tenant, so a credential belonging to anyone else is reported as not found
// rather than touched. Soft-delete: which passkey was removed is audit-relevant.
//
// Refuses to remove the last remaining sign-in method. A user with no password
// row and one passkey has exactly one way in, and letting them delete it from a
// settings page produces an account nobody — including support — can recover
// without an out-of-band identity check. Passwordless accounts are created by
// social login and by admin invite, so this is a reachable state, not a
// hypothetical.
//
// byAdmin skips the guard: support removing a lost device is the case the guard
// must not block, because the alternative is an account permanently signed in
// on a stolen laptop.
func (s *WebAuthnService) RevokeCredential(ctx context.Context, userID, tenantID int64, credRowID string, byAdmin bool) error {
	// The guard and the revocation are ONE statement, not a check followed by an
	// update. Two settings-page requests deleting two different passkeys can each
	// see the other one as "another active credential", both pass a separate
	// guard, and both commit — leaving a passwordless account with no way in at
	// all, which is the single state this guard exists to prevent and the one with
	// no self-service recovery (master plan P8 is not built). Folding the count
	// into the UPDATE's WHERE clause makes the row lock serialise them: the second
	// writer re-evaluates the subquery after the first has committed and finds
	// nothing to update.
	//
	// The admin path keeps no guard at all, deliberately — support removing a lost
	// device must not be blocked — so it runs the plain form.
	sql := `
		UPDATE webauthn_credentials
		SET is_active = false, revoked_at = NOW(), revoked_by_admin = $4
		WHERE id::TEXT = $1 AND user_id = $2 AND tenant_id = $3 AND is_active`
	//
	// "Another way in" means a password row or another active passkey, and
	// nothing else. TOTP and email MFA deliberately do not count: both are SECOND
	// factors gated behind a first one, so an account holding TOTP but no password
	// and no passkey cannot sign in at all. Counting them would let the guard pass
	// on an account that is in fact locked out — the exact failure it exists to
	// prevent.
	if !byAdmin {
		sql += `
		  AND (
		    EXISTS (SELECT 1 FROM user_credentials
		             WHERE user_id = $2 AND tenant_id = $3)
		    OR EXISTS (SELECT 1 FROM webauthn_credentials other
		                WHERE other.user_id = $2 AND other.tenant_id = $3
		                  AND other.is_active AND other.id::TEXT <> $1)
		  )`
	}

	tag, err := s.pool.Exec(ctx, sql, credRowID, userID, tenantID, byAdmin)
	if err != nil {
		return fmt.Errorf("revoke webauthn credential: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Nothing updated means either the credential is not the caller's, or the
		// last-factor clause refused it. They are told apart with a second read
		// rather than collapsed, because "not found" and "this is your only way to
		// sign in" need different words in a settings page. Existence is checked
		// first: without it, a bogus id on an account that has no password and no
		// other passkeys would look exactly like a last-factor refusal for a
		// credential that never existed. Only reached on the failure path, so the
		// extra queries cost nothing in the normal case.
		if !byAdmin {
			var exists bool
			if err := s.pool.QueryRow(ctx, `
				SELECT EXISTS (SELECT 1 FROM webauthn_credentials
				                WHERE id::TEXT = $1 AND user_id = $2 AND tenant_id = $3
				                  AND is_active)
			`, credRowID, userID, tenantID).Scan(&exists); err != nil {
				return fmt.Errorf("revoke webauthn credential: %w", err)
			}
			if exists {
				return ErrLastFactor
			}
		}
		return ErrCredentialNotFound
	}
	return nil
}

// ---------------------------------------------------------------------------
// Administration
// ---------------------------------------------------------------------------

// AdminListCredentials returns one user's passkeys on behalf of an operator.
//
// The scope check is the whole point of this method existing separately from
// ListCredentials: there, the ids come from the caller's own verified token and
// cannot name anyone else. Here the user id comes from a path parameter, so
// tenant and application membership has to be proved before anything is read.
// A user outside the caller's scope is reported as not found — never as
// forbidden, which would confirm the account exists.
func (s *WebAuthnService) AdminListCredentials(ctx context.Context, tenantID int64, appRowID *int64, userID int64) ([]StoredCredential, error) {
	if err := s.assertUserInScope(ctx, tenantID, appRowID, userID); err != nil {
		return nil, err
	}
	return s.ListCredentials(ctx, userID, tenantID)
}

// AdminRevokeCredential removes one user's passkey on behalf of an operator.
//
// Skips the last-factor guard, deliberately: support removing a lost device is
// exactly the case the guard must not block, because the alternative is leaving
// an account permanently reachable from a stolen laptop. The operator can see
// the account has no other factor — the list this sits next to shows it — and
// getting the user back in is a support problem, while leaving the stolen device
// working is a security one.
func (s *WebAuthnService) AdminRevokeCredential(ctx context.Context, tenantID int64, appRowID *int64, userID int64, credRowID string) error {
	if err := s.assertUserInScope(ctx, tenantID, appRowID, userID); err != nil {
		return err
	}
	return s.RevokeCredential(ctx, userID, tenantID, credRowID, true)
}

// assertUserInScope reports ErrUserNotFound unless the user belongs to the
// tenant and, when appRowID is non-nil, to that application's isolated user
// base. Mirrors the check ResetUserMFA makes, for the same reason.
func (s *WebAuthnService) assertUserInScope(ctx context.Context, tenantID int64, appRowID *int64, userID int64) error {
	var exists bool
	if err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM users
			WHERE id = $1 AND tenant_id = $2
			  AND ($3::BIGINT IS NULL OR application_id = $3)
			  AND deleted_at IS NULL
		)
	`, userID, tenantID, appRowID).Scan(&exists); err != nil {
		return fmt.Errorf("verify user scope: %w", err)
	}
	if !exists {
		return ErrUserNotFound
	}
	return nil
}

// ---------------------------------------------------------------------------
// Ceremony state
// ---------------------------------------------------------------------------

// ceremonyState is what must survive between begin and finish.
//
// The library's SessionData is opaque to us and must be handed back unchanged.
// The identity fields bind the ceremony to the account that started it, so a
// registration cannot be completed against a different user. The relying-party
// fields pin the ceremony to the RP it STARTED under: policy is re-read at
// finish for the authorization decision, but verification has to use the same
// origin list and RP ID the challenge was minted with, or an administrator
// editing a policy mid-ceremony would turn a legitimate registration into a
// signature failure.
type ceremonyState struct {
	Session  webauthn.SessionData `json:"session"`
	UserID   int64                `json:"user_id,omitempty"`
	TenantID int64                `json:"tenant_id,omitempty"`
	AppID    string               `json:"app_id,omitempty"`

	RPID          string   `json:"rp_id"`
	RPDisplayName string   `json:"rp_display_name,omitempty"`
	Origins       []string `json:"origins"`
	RequireUV     bool     `json:"require_uv"`
}

// rp reconstructs the relying party the ceremony began under.
func (st ceremonyState) rp() PasskeyPolicy {
	return PasskeyPolicy{
		RPID:                    st.RPID,
		RPDisplayName:           st.RPDisplayName,
		Origins:                 st.Origins,
		RequireUserVerification: st.RequireUV,
	}
}

func webauthnRegKey(token string) string   { return "webauthn:reg:" + token }
func webauthnLoginKey(token string) string { return "webauthn:auth:" + token }

// storeCeremony persists ceremony state under a fresh random token. The token is
// the only thing the client holds — an opaque pointer to server-side state, the
// same shape as the existing otp_session_token. Nothing security-relevant
// travels through the browser.
func (s *WebAuthnService) storeCeremony(ctx context.Context, keyFn func(string) string, ttl time.Duration, st ceremonyState) (string, error) {
	token, err := GenerateRefreshToken()
	if err != nil {
		return "", fmt.Errorf("generate ceremony token: %w", err)
	}
	blob, err := json.Marshal(st)
	if err != nil {
		return "", fmt.Errorf("marshal ceremony state: %w", err)
	}
	if err := s.redis.Set(ctx, keyFn(token), blob, ttl).Err(); err != nil {
		return "", fmt.Errorf("store ceremony state: %w", err)
	}
	return token, nil
}

// takeCeremony loads and DELETES ceremony state in one atomic step.
//
// GETDEL, not GET-then-DEL: the challenge must be consumed before we know
// whether verification succeeds, so a failed attempt cannot be retried against
// the same challenge, and two concurrent requests cannot both redeem it. This is
// what makes the challenge single-use, which is the property the ticket's
// "second complete call returns 400" acceptance criterion is testing.
func (s *WebAuthnService) takeCeremony(ctx context.Context, keyFn func(string) string, token string) (*ceremonyState, error) {
	if token == "" {
		return nil, ErrChallengeExpired
	}
	blob, err := s.redis.GetDel(ctx, keyFn(token)).Bytes()
	if err != nil || len(blob) == 0 {
		return nil, ErrChallengeExpired
	}
	var st ceremonyState
	if err := json.Unmarshal(blob, &st); err != nil {
		return nil, ErrChallengeExpired
	}
	return &st, nil
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

// RegisterBegin starts registration for an authenticated user and returns the
// creation options the browser passes to navigator.credentials.create().
//
// origin is the page's Origin header. It is checked against the resolved
// policy's allow-list BEFORE the ceremony starts, because the alternative is a
// credential minted for a relying party the page cannot serve — which the
// browser then silently never offers. That failure is invisible until a user
// tries to sign in weeks later, so it is worth an explicit refusal now.
//
// excludeCredentials lists what the user already has for this RP, so a
// cooperating browser declines to make a second credential on the same
// authenticator. Browsers that ignore it are caught by the unique index at
// finish.
func (s *WebAuthnService) RegisterBegin(ctx context.Context, userID, tenantID int64, email, appID, origin string) (*protocol.CredentialCreation, string, error) {
	policy, err := s.policy.Resolve(ctx, tenantID, appRowIDFromClaim(appID))
	if err != nil {
		return nil, "", err
	}
	if !policy.AllowPasskeys {
		return nil, "", ErrPasskeysNotAllowed
	}
	if !policy.AllowsOrigin(origin) {
		s.logger.Warn().Int64("tenant_id", tenantID).Str("origin", origin).
			Str("policy_source", policy.Source).Str("rp_id", policy.RPID).
			Msg("passkey registration refused: origin not on the policy allow-list")
		return nil, "", ErrOriginNotAllowed
	}

	rp, err := s.rpFor(policy)
	if err != nil {
		return nil, "", err
	}

	handle, err := s.userHandle(ctx, userID, tenantID)
	if err != nil {
		return nil, "", err
	}
	existing, err := s.loadCredentials(ctx, userID, tenantID, policy.RPID)
	if err != nil {
		return nil, "", err
	}
	if len(existing) >= policy.MaxCredentialsPerUser {
		return nil, "", ErrTooManyCredentials
	}

	user := &webauthnUser{userID: userID, tenantID: tenantID, handle: handle, email: email, creds: existing}

	exclusions := make([]protocol.CredentialDescriptor, 0, len(existing))
	for _, c := range existing {
		exclusions = append(exclusions, c.Descriptor())
	}

	// credProps asks the browser to report whether the credential it created is
	// actually discoverable. Requesting it is the only way to find out: the
	// authenticator selection is a REQUEST, and a browser may satisfy it with a
	// non-discoverable credential. See RegisterComplete.
	creation, session, err := rp.BeginRegistration(user,
		webauthn.WithExclusions(exclusions),
		webauthn.WithExtensions(protocol.AuthenticationExtensions{"credProps": true}),
	)
	if err != nil {
		return nil, "", fmt.Errorf("begin webauthn registration: %w", err)
	}

	token, err := s.storeCeremony(ctx, webauthnRegKey, webauthnRegTTL, ceremonyState{
		Session: *session, UserID: userID, TenantID: tenantID, AppID: appID,
		RPID: policy.RPID, RPDisplayName: policy.RPDisplayName,
		Origins: policy.Origins, RequireUV: policy.RequireUserVerification,
	})
	if err != nil {
		return nil, "", err
	}
	return creation, token, nil
}

// RegisterComplete verifies the attestation and stores the credential.
//
// The caller's identity comes from their JWT, and the ceremony's identity comes
// from the stored state; they must match. Without that check a user could finish
// a registration another user began, binding their authenticator to the victim's
// account.
func (s *WebAuthnService) RegisterComplete(ctx context.Context, userID, tenantID int64, email, token, label string, r *http.Request) (*StoredCredential, error) {
	st, err := s.takeCeremony(ctx, webauthnRegKey, token)
	if err != nil {
		return nil, err
	}
	if st.UserID != userID || st.TenantID != tenantID {
		return nil, ErrWebAuthnVerification
	}

	// Re-read policy for the authorization decision. An administrator who
	// disabled passkeys while this ceremony was in flight wins: the challenge
	// being outstanding is not a grant. Verification, by contrast, uses the
	// relying party from the ceremony state — see the ceremonyState comment.
	policy, err := s.policy.Resolve(ctx, tenantID, appRowIDFromClaim(st.AppID))
	if err != nil {
		return nil, err
	}
	if !policy.AllowPasskeys {
		return nil, ErrPasskeysNotAllowed
	}

	rp, err := s.rpFor(st.rp())
	if err != nil {
		return nil, err
	}

	handle, err := s.userHandle(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	existing, err := s.loadCredentials(ctx, userID, tenantID, st.RPID)
	if err != nil {
		return nil, err
	}
	// Re-checked here and not only at begin: two ceremonies started in parallel
	// would both pass the check at begin. This read is the fast, friendly refusal
	// — it stops before the attestation is verified — but it is NOT the one that
	// holds the ceiling. The INSERT below carries the same bound in its WHERE
	// clause, because two completions racing each other would both read
	// limit-1 here and both insert.
	if len(existing) >= policy.MaxCredentialsPerUser {
		return nil, ErrTooManyCredentials
	}
	user := &webauthnUser{userID: userID, tenantID: tenantID, handle: handle, email: email, creds: existing}

	// Parsed separately from verification so the client extension results are
	// available for the discoverability check below.
	parsed, err := protocol.ParseCredentialCreationResponse(r)
	if err != nil {
		s.logger.Warn().Err(err).Int64("user_id", userID).Msg("webauthn registration: malformed response")
		return nil, ErrWebAuthnVerification
	}

	// The library performs the checks that must not be reimplemented here:
	// origin against the allow-list, rpIdHash against SHA256(rp_id),
	// clientData.type == "webauthn.create", challenge equality, attestation
	// signature, and the UV flag when we asked for it.
	cred, err := rp.CreateCredential(user, st.Session, parsed)
	if err != nil {
		s.logger.Warn().Err(err).Int64("user_id", userID).Msg("webauthn registration verification failed")
		return nil, ErrWebAuthnVerification
	}

	// Discoverability is REQUESTED in the options and only confirmed here. A
	// non-discoverable credential can never satisfy a passwordless sign-in, so
	// storing one hands the user a passkey that silently never works — refuse it
	// now, while there is still a person watching who can try another
	// authenticator.
	//
	// Three-state on purpose: an explicit rk=false is a refusal, but a browser
	// that omits credProps entirely tells us nothing, and refusing on absence
	// would lock out every browser that does not implement the extension. Absent
	// is accepted and logged, so the gap is visible in the data rather than
	// silently assumed either way.
	switch discoverabilityOf(parsed) {
	case discoverableNo:
		return nil, ErrCredentialNotDiscoverable
	case discoverableUnknown:
		s.logger.Info().Int64("user_id", userID).
			Msg("webauthn: browser did not report credProps — discoverability unconfirmed")
	}

	label = strings.TrimSpace(label)
	if label == "" {
		// Named from the authenticator model when we recognise it, so a user who
		// skipped the "what device is this?" prompt still gets a list they can
		// read. Falls back to a generic label rather than the raw AAGUID.
		if name := AuthenticatorName(cred.Authenticator.AAGUID); name != "" {
			label = name
		} else {
			label = "Passkey"
		}
	}
	if len([]rune(label)) > passkeyNameMaxLen {
		label = string([]rune(label)[:passkeyNameMaxLen])
	}

	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}

	var out StoredCredential
	var aaguid []byte
	// INSERT ... SELECT so the ceiling is evaluated by the database at write time
	// rather than by us beforehand. The count and the insert are then one
	// statement and cannot interleave: a second completion racing this one
	// re-evaluates the subquery after the first has committed and inserts nothing.
	// Cheaper than a per-user advisory lock on a user-interactive path, and it
	// keeps the bound where the rows are.
	err = s.pool.QueryRow(ctx, `
		INSERT INTO webauthn_credentials (
			user_id, tenant_id, application_id, rp_id,
			credential_id, public_key, aaguid, attestation_type, transports,
			sign_count, backup_eligible, backup_state, uv_capable, discoverable, name
		)
		SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,true,$14
		WHERE (
			SELECT COUNT(*) FROM webauthn_credentials
			 WHERE user_id = $1 AND tenant_id = $2 AND rp_id = $4 AND is_active
		) < $15
		RETURNING id::TEXT, name, rp_id, backup_state, aaguid, created_at, last_used_at
	`,
		userID, tenantID, appRowIDFromClaim(st.AppID), st.RPID,
		cred.ID, cred.PublicKey, cred.Authenticator.AAGUID, cred.AttestationType, transports,
		int64(cred.Authenticator.SignCount), cred.Flags.BackupEligible, cred.Flags.BackupState,
		cred.Flags.UserVerified, label, policy.MaxCredentialsPerUser,
	).Scan(&out.ID, &out.Name, &out.RPID, &out.Synced, &aaguid, &out.CreatedAt, &out.LastUsedAt)
	if err != nil {
		// The unique index on credential_id is the backstop for browsers that
		// ignore excludeCredentials. Report it as the conflict it is, not as a
		// server error.
		if isUniqueViolation(err) {
			return nil, ErrCredentialAlreadyRegistered
		}
		// No row returned means the WHERE clause refused: the ceiling was reached
		// between the read above and this write. Same answer the read gives, so the
		// caller cannot tell whether it lost a race — which is correct, because
		// there is nothing they would do differently.
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTooManyCredentials
		}
		return nil, fmt.Errorf("store webauthn credential: %w", err)
	}

	out.AuthenticatorName = AuthenticatorName(aaguid)
	out.AAGUID = AAGUIDString(aaguid)
	out.setSyncLabel()
	return &out, nil
}

// ---------------------------------------------------------------------------
// Passwordless login
// ---------------------------------------------------------------------------

// WebAuthnIdentity is a verified passkey sign-in: who the assertion proved, and
// whether a user-verification gesture backed it. The caller turns this into
// tokens; this service never mints them.
type WebAuthnIdentity struct {
	UserID   int64
	TenantID int64
	Email    string
	Role     string
	AppID    string
	// UserVerified reports whether the AUTHENTICATOR said a biometric or PIN was
	// performed. It is read off the assertion, never inferred from the options we
	// sent, because only the response is evidence. It is what decides whether the
	// issued token may honestly claim 'mfa'.
	UserVerified bool
	// CredentialRowID and CredentialLabel identify which passkey signed in, for
	// the audit event. A user with four devices needs their audit trail to say
	// which one.
	CredentialRowID int64
	CredentialLabel string
}

// LoginBegin starts a discoverable ("passkey") assertion.
//
// It takes NO user identifier — no email, no login hint. With an empty
// allowCredentials the authenticator identifies the user from the credentials it
// holds, so there is nothing for the server to look up and therefore no account
// oracle to abuse.
//
// The relying party is resolved from the request ORIGIN, which is the only thing
// identifying it at this point — and is also the correct answer, since as far as
// the browser is concerned the relying party IS the origin. An origin no policy
// and no server config claims is refused rather than served under whatever RP
// happens to be configured.
//
// Consequence to remember when reading traffic: this endpoint is hit once per
// login-page view by every visitor, whether or not they own a passkey.
func (s *WebAuthnService) LoginBegin(ctx context.Context, origin string) (*protocol.CredentialAssertion, string, error) {
	policy, err := s.policy.ResolveByOrigin(ctx, origin)
	if err != nil {
		return nil, "", err
	}
	if !policy.AllowPasskeys {
		return nil, "", ErrPasskeysNotAllowed
	}
	if !policy.AllowPasswordless {
		return nil, "", ErrPasswordlessNotAllowed
	}

	rp, err := s.rpFor(policy)
	if err != nil {
		return nil, "", err
	}

	assertion, session, err := rp.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", fmt.Errorf("begin webauthn login: %w", err)
	}
	token, err := s.storeCeremony(ctx, webauthnLoginKey, webauthnLoginTTL, ceremonyState{
		Session: *session,
		RPID:    policy.RPID, RPDisplayName: policy.RPDisplayName,
		Origins: policy.Origins, RequireUV: policy.RequireUserVerification,
	})
	if err != nil {
		return nil, "", err
	}
	return assertion, token, nil
}

// LoginComplete verifies a passkey assertion and returns the identity it proved.
//
// The account is resolved from the credential presented, not from anything the
// client claimed. Cloned-authenticator signals are checked here rather than left
// to the library, because what to do about them is a policy decision: we refuse,
// and the caller ends every session the account has.
func (s *WebAuthnService) LoginComplete(ctx context.Context, token string, r *http.Request) (*WebAuthnIdentity, error) {
	st, err := s.takeCeremony(ctx, webauthnLoginKey, token)
	if err != nil {
		return nil, err
	}

	rp, err := s.rpFor(st.rp())
	if err != nil {
		return nil, err
	}

	// Parsed and resolved before verification because the assertion has to be
	// matched to a stored credential before anything can be verified against it.
	// The clone checks themselves run AFTER verification — see below.
	parsed, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		s.logger.Warn().Err(err).Str("rp_id", st.RPID).Msg("webauthn login: malformed response")
		return nil, ErrWebAuthnVerification
	}

	resolved, storedRow, err := s.resolveByCredential(ctx, parsed.RawID, parsed.Response.UserHandle, st.RPID)
	if err != nil {
		// Unknown credential, wrong relying party, mismatched user handle, or a
		// deactivated account — all one error, so the endpoint cannot be used to
		// probe which credentials exist.
		s.logger.Warn().Err(err).Str("rp_id", st.RPID).Msg("webauthn login: credential did not resolve")
		return nil, ErrWebAuthnVerification
	}

	// Verification comes FIRST, and the clone comparison second, because
	// containment is destructive and account-wide: it deactivates the credential,
	// revokes every session the account has, bumps token_version and writes a
	// Redis denylist entry. Running any of that on unverified input would mean
	// anyone who learned a credential ID — an identifier, not a secret — could
	// sign an account out everywhere and disable its passkey by posting a
	// malformed assertion with one flipped flag, without ever proving possession
	// of the private key. Nothing may be contained until a signature over our own
	// challenge has been checked against the stored public key.
	//
	// The library performs the checks that must not be reimplemented here:
	// challenge equality, origin against the allow-list, rpIdHash against
	// SHA256(rp_id), clientData.type == "webauthn.get", the assertion signature
	// over authenticatorData ‖ SHA256(clientDataJSON), and user presence.
	//
	// The account already resolved above is returned rather than looked up again —
	// a second query is a second chance to resolve to a different answer than the
	// one the clone checks are made against.
	//
	// beAligned is what lets our clone check survive the library's own. The
	// library compares the stored BackupEligible flag against the asserted one
	// (login.go, "Backup Eligible flag inconsistency") and rejects a change with a
	// generic bad request — behind which a cloned authenticator is
	// indistinguishable from a bad signature, so no clone audit event, no session
	// revocation and no credential deactivation would ever run. Its check sits
	// AFTER the signature verification it performs, so aligning the flag on a
	// throwaway copy suppresses only that one comparison and weakens nothing: the
	// signature is still verified against the real stored public key, and the real
	// stored flag is compared immediately below.
	assertedFlags := parsed.Response.AuthenticatorData.Flags
	assertedCount := int64(parsed.Response.AuthenticatorData.Counter)

	verifyUser := beAligned(resolved, parsed.RawID, assertedFlags.HasBackupEligible())
	_, cred, err := rp.ValidatePasskeyLogin(func(_, _ []byte) (webauthn.User, error) {
		return verifyUser, nil
	}, st.Session, parsed)
	if err != nil {
		s.logger.Warn().Err(err).Str("rp_id", st.RPID).Msg("webauthn login verification failed")
		return nil, ErrWebAuthnVerification
	}

	// Possession of the private key is now proven, so a mismatch here is evidence
	// about the authenticator rather than about the caller, and containment is
	// safe to run.
	//
	// Backup Eligible is fixed for the life of a credential. A change means the
	// private key exists somewhere it did not before — a clone or a swapped
	// authenticator.
	if assertedFlags.HasBackupEligible() != storedRow.be {
		s.logger.Error().Int64("credential_row", storedRow.rowID).
			Int64("user_id", resolved.userID).
			Bool("stored_be", storedRow.be).Bool("asserted_be", assertedFlags.HasBackupEligible()).
			Msg("webauthn: backup-eligibility flag changed — possible cloned credential")
		return nil, s.clonedError(ctx, resolved, storedRow, "backup_eligibility_changed")
	}

	// A signature counter that fails to advance means two copies of the key are in
	// use. Only a stored non-zero value gives us anything to compare against:
	// counters that stay at zero are normal, because most platform authenticators
	// (Apple, Google) never increment. Once a credential HAS reported a non-zero
	// counter, any value at or below it is a regression — including a drop to
	// zero, which is the signal a second authenticator that does not keep a
	// counter would produce. Which also means this control is inert for the
	// majority of real passkeys; backup-eligibility above is the one that will
	// actually fire.
	if storedRow.signCount > 0 && assertedCount <= storedRow.signCount {
		s.logger.Error().Int64("credential_row", storedRow.rowID).
			Int64("user_id", resolved.userID).
			Int64("stored", storedRow.signCount).Int64("asserted", assertedCount).
			Msg("webauthn: signature counter did not advance — possible cloned credential")
		return nil, s.clonedError(ctx, resolved, storedRow, "sign_count_regression")
	}

	// The account is now known, so policy can be evaluated against the scope the
	// CREDENTIAL belongs to rather than the scope the request came from. This is
	// the authoritative check: the origin-derived policy at begin decided which
	// relying party to run as, but only the credential says whose account is
	// being signed into, and only the credential's own tenant may authorise it.
	policy, perr := s.policy.Resolve(ctx, resolved.tenantID, appRowIDFromClaim(resolved.appID))
	if perr != nil {
		return nil, perr
	}
	if !policy.AllowPasskeys {
		return nil, ErrPasskeysNotAllowed
	}
	if !policy.AllowPasswordless {
		return nil, ErrPasswordlessNotAllowed
	}

	// With user verification required, a missing UV flag is a hard rejection and
	// never a downgraded token: in a passwordless sign-in the gesture is the
	// only proof the right person is present, so accepting the assertion without
	// it would make this weaker than a password.
	//
	// Checked against the CREDENTIAL's policy, not the ceremony's: a tenant that
	// requires UV must not have it relaxed by a login begun from a surface whose
	// policy was laxer.
	if policy.RequireUserVerification && !cred.Flags.UserVerified {
		s.logger.Warn().Int64("credential_row", storedRow.rowID).
			Int64("user_id", resolved.userID).
			Msg("webauthn login: policy requires user verification and the assertion had none")
		return nil, ErrUserVerificationRequired
	}

	if _, err := s.pool.Exec(ctx, `
		UPDATE webauthn_credentials
		SET sign_count = $1, backup_state = $2, last_used_at = NOW()
		WHERE id = $3
	`, assertedCount, cred.Flags.BackupState, storedRow.rowID); err != nil {
		// The sign-in itself already verified. Failing it now because a
		// bookkeeping write failed would lock the user out over a non-security
		// problem; log and continue.
		s.logger.Warn().Err(err).Int64("credential_row", storedRow.rowID).
			Msg("webauthn: failed to update credential usage")
	}

	return &WebAuthnIdentity{
		UserID:          resolved.userID,
		TenantID:        resolved.tenantID,
		Email:           resolved.email,
		Role:            resolved.role,
		AppID:           resolved.appID,
		UserVerified:    cred.Flags.UserVerified,
		CredentialRowID: storedRow.rowID,
		CredentialLabel: storedRow.label,
	}, nil
}

// clonedError deactivates the credential and builds the typed error.
//
// The credential is revoked here rather than by the caller because a key we
// believe is copied must not remain usable for the round trip it would take to
// decide that elsewhere. Revocation failure does not change the verdict — the
// assertion is refused either way — so it is logged and swallowed.
func (s *WebAuthnService) clonedError(ctx context.Context, u *webauthnUser, row credentialRow, reason string) error {
	// Detached from the request but not from its values: the request is being
	// refused and on some paths the client has already gone, which would cancel
	// the write that takes a suspected-cloned credential out of service. A
	// revocation that only happens when the attacker waits for the response is
	// not a revocation.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	if _, err := s.pool.Exec(ctx, `
		UPDATE webauthn_credentials
		SET is_active = false, revoked_at = NOW(), revoked_by_admin = true
		WHERE id = $1 AND is_active
	`, row.rowID); err != nil {
		s.logger.Error().Err(err).Int64("credential_row", row.rowID).
			Msg("webauthn: could not deactivate cloned credential")
	}
	return &ClonedCredentialError{
		UserID:          u.userID,
		TenantID:        u.tenantID,
		CredentialRowID: row.rowID,
		CredentialLabel: row.label,
		Reason:          reason,
	}
}

// credentialRow is the stored state a login compares the assertion against.
type credentialRow struct {
	rowID     int64
	signCount int64
	be        bool
	label     string
}

// discoverability is the tri-state answer to "did this credential come back as
// a resident key?". Unknown is a real and common answer — see RegisterComplete.
type discoverability int

const (
	discoverableUnknown discoverability = iota
	discoverableYes
	discoverableNo
)

// discoverabilityOf reads the credProps extension result. Browsers that do not
// implement the extension omit it entirely, which is Unknown rather than No.
func discoverabilityOf(pcc *protocol.ParsedCredentialCreationData) discoverability {
	raw, ok := pcc.ClientExtensionResults["credProps"]
	if !ok {
		return discoverableUnknown
	}
	props, ok := raw.(map[string]any)
	if !ok {
		return discoverableUnknown
	}
	rk, ok := props["rk"].(bool)
	if !ok {
		return discoverableUnknown
	}
	if rk {
		return discoverableYes
	}
	return discoverableNo
}

// resolveByCredential maps a presented credential to its owner.
//
// The lookup is by credential_id and is filtered by rp_id: a credential
// registered for a different relying party must not authenticate here even if
// the row exists. The user handle from the authenticator is verified against the
// stored handle rather than trusted, so a mismatched pair is refused instead of
// resolving to whichever account the credential ID happened to name.
func (s *WebAuthnService) resolveByCredential(ctx context.Context, rawID, userHandle []byte, rpID string) (*webauthnUser, credentialRow, error) {
	var (
		row     credentialRow
		u       webauthnUser
		handle  []byte
		role    *string
		appRowI *int64
	)
	// Role and application_id come out of the same query: a passkey sign-in must
	// mint exactly the token the account would otherwise get, and a second round
	// trip to assemble it is a second chance to assemble it differently.
	err := s.pool.QueryRow(ctx, `
		SELECT wc.id, wc.sign_count, wc.backup_eligible, wc.name,
		       wc.user_id, wc.tenant_id, u.email, wh.handle, r.name, u.application_id
		FROM webauthn_credentials wc
		JOIN users u  ON u.id = wc.user_id
		JOIN webauthn_user_handles wh ON wh.user_id = wc.user_id
		LEFT JOIN roles r ON r.id = u.role_id
		JOIN tenants t ON t.id = u.tenant_id
		WHERE wc.credential_id = $1
		  AND wc.rp_id = $2
		  AND wc.is_active
		  AND u.is_active = true
		  AND u.deleted_at IS NULL
		  AND t.is_active = true
	`, rawID, rpID).Scan(&row.rowID, &row.signCount, &row.be, &row.label,
		&u.userID, &u.tenantID, &u.email, &handle, &role, &appRowI)
	if err != nil {
		return nil, row, ErrWebAuthnVerification
	}
	if role != nil {
		u.role = *role
	}
	if appRowI != nil {
		u.appID = strconv.FormatInt(*appRowI, 10)
	}
	if len(userHandle) > 0 && !bytes.Equal(userHandle, handle) {
		return nil, row, ErrWebAuthnVerification
	}

	creds, err := s.loadCredentials(ctx, u.userID, u.tenantID, rpID)
	if err != nil {
		return nil, row, err
	}
	u.handle = handle
	u.creds = creds
	return &u, row, nil
}

// ---------------------------------------------------------------------------
// AuthService integration
// ---------------------------------------------------------------------------

// WithWebAuthn attaches the passkey service so LoginWebAuthn can issue tokens.
func (s *AuthService) WithWebAuthn(svc *WebAuthnService) *AuthService {
	s.webauthnSvc = svc
	return s
}

// PasskeyPolicyFor resolves passkey policy for a scope through the attached
// service. Reports ErrWebAuthnNotConfigured when passkeys are disabled at the
// deployment level, so a caller can tell "off for this tenant" from "not built
// into this deployment".
func (s *AuthService) PasskeyPolicyFor(ctx context.Context, tenantID int64, appID *int64) (PasskeyPolicy, error) {
	if s.webauthnSvc == nil {
		return PasskeyPolicy{}, ErrWebAuthnNotConfigured
	}
	return s.webauthnSvc.policy.Resolve(ctx, tenantID, appID)
}

// LoginWebAuthn completes a passwordless passkey sign-in and issues tokens.
//
// The MFA gate is deliberately NOT consulted: a verified passkey with user
// verification already is two factors (possession of the authenticator plus the
// biometric), so challenging for a second one would be asking the user to prove
// the same thing twice. That is also why 'mfa' below is conditional on the UV
// flag rather than assumed — see WebAuthnIdentity.UserVerified.
//
// It is also why passkeys are off until a tenant enables them: skipping the MFA
// gate is a change to the tenant's authentication policy, and only they can make
// it. See migration 00072.
// Returns the verified identity alongside the tokens. The caller needs it for
// the audit row: which account signed in and with WHICH passkey, and neither is
// recoverable from an AuthResult — a user with four devices needs their audit
// trail to name the one that was used.
func (s *AuthService) LoginWebAuthn(ctx context.Context, token string, r *http.Request) (*AuthResult, *WebAuthnIdentity, error) {
	return s.loginWebAuthn(ctx, token, r, false)
}

// LoginWebAuthnForCookieSession is LoginWebAuthn for the cookie-session
// endpoint, refusing an application-scoped identity BEFORE it mints (issue
// #116).
//
// A separate entry point rather than a parameter on LoginWebAuthn: the caller
// distinction is the whole content of the flag, every existing call site means
// false, and threading it through them would only create places for a future
// change to pass the wrong one.
//
// Returns the verified identity alongside ErrCookieSessionNotAvailable. The
// identity is real — the assertion verified — so the caller can audit the
// refusal against an actual account and passkey rather than logging an anonymous
// failure.
//
// Why the refusal has to live here and not in the handler: the account is not
// known until the assertion verifies, because a discoverable credential carries
// its own identity, and issueTokenPair follows immediately. The handler only
// ever sees the far side of the mint. By then a user_sessions row exists, and
// enforceSessionCap has already run inside that transaction and evicted the
// user's least-recently-used session — a write no later revocation can undo.
func (s *AuthService) LoginWebAuthnForCookieSession(ctx context.Context, token string, r *http.Request) (*AuthResult, *WebAuthnIdentity, error) {
	return s.loginWebAuthn(ctx, token, r, true)
}

// loginWebAuthn is the shared body. refuseApplicationScoped stops between
// verifying the assertion and issuing tokens.
func (s *AuthService) loginWebAuthn(ctx context.Context, token string, r *http.Request, refuseApplicationScoped bool) (*AuthResult, *WebAuthnIdentity, error) {
	if s.webauthnSvc == nil {
		return nil, nil, ErrWebAuthnNotConfigured
	}

	id, err := s.webauthnSvc.LoginComplete(ctx, token, r)
	if err != nil {
		// A cloned credential is not merely a failed sign-in. Somebody is
		// holding a copy of a private key, so every session the account has is
		// suspect — including ones established before the copy was made, since
		// we cannot tell which side of the clone made them.
		var cloned *ClonedCredentialError
		if errors.As(err, &cloned) {
			s.revokeAllAfterClone(ctx, cloned)
		}
		return nil, nil, err
	}

	// Before any minting, and deliberately before loadPermissions too: there is
	// nothing to load permissions for.
	//
	// The credential's sign count and backup flags have already been advanced by
	// LoginComplete above, and that is correct — the assertion was genuine, so
	// the counter must move whatever we do with the identity. Not advancing it
	// would make the next legitimate assertion look like a replayed one.
	if refuseApplicationScoped && id.AppID != "" {
		return nil, id, ErrCookieSessionNotAvailable
	}

	perms, err := s.loadPermissions(ctx, id.UserID, id.TenantID)
	if err != nil {
		s.logger.Warn().Err(err).Int64("user_id", id.UserID).Msg("webauthn login: failed to load permissions")
		perms = []string{}
	}

	amr := []string{AMRWebAuthn}
	if id.UserVerified {
		// The gesture happened, so this genuinely is two factors and the token
		// may say so. Without it the token claims one factor and a relying party
		// that cares can tell the difference.
		amr = append(amr, AMRUserVerif, AMRMFA)
	}

	result, err := s.issueTokenPair(ctx, id.UserID, id.TenantID, id.Email, id.Role, perms,
		sessionContext{amr: amr}, id.AppID)
	if err != nil {
		return nil, nil, err
	}
	return result, id, nil
}

// revokeAllAfterClone signs the account out everywhere after a clone detection.
//
// Best-effort and never propagated: the sign-in is already refused, and turning
// a failed cleanup into a different error would tell the caller something about
// our internal state while changing nothing about the outcome. Every failure
// here is logged at error, because a clone detection whose containment did not
// run is exactly the event somebody has to see.
func (s *AuthService) revokeAllAfterClone(ctx context.Context, cloned *ClonedCredentialError) {
	// Detached from the request, for the same reason clonedError detaches its own
	// write: the request is being refused, and a caller who sends a clone
	// assertion and drops the connection would otherwise cancel the containment
	// mid-way — leaving the credential deactivated (that write survives) but
	// every session still live. Containment that only completes when the attacker
	// waits for the response is not containment. Bounded rather than unbounded so
	// a stalled database cannot pin the goroutine indefinitely.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		s.logger.Error().Err(err).Int64("user_id", cloned.UserID).
			Msg("passkey clone: could not begin session revocation")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := RevokeAllSessionsTx(ctx, tx, cloned.UserID, cloned.TenantID, RevokeReasonPasskeyCloned); err != nil {
		s.logger.Error().Err(err).Int64("user_id", cloned.UserID).
			Msg("passkey clone: session revocation failed")
		return
	}
	// Bumped for the same reason the admin revoke-all bumps it: this is an
	// account-wide event, not a single-session one.
	if _, err := tx.Exec(ctx, `
		UPDATE users SET token_version = token_version + 1, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2
	`, cloned.UserID, cloned.TenantID); err != nil {
		s.logger.Error().Err(err).Int64("user_id", cloned.UserID).
			Msg("passkey clone: token version bump failed")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.logger.Error().Err(err).Int64("user_id", cloned.UserID).
			Msg("passkey clone: session revocation commit failed")
		return
	}

	// After the commit, deliberately: a Redis deny entry cannot be rolled back,
	// so writing it before the transaction lands would sign a user out on the
	// strength of a write that then failed. Same ordering as the admin path.
	s.DenyUserSessions(ctx, cloned.UserID, cloned.TenantID)

	s.logger.Error().
		Int64("user_id", cloned.UserID).Int64("tenant_id", cloned.TenantID).
		Int64("credential_row", cloned.CredentialRowID).Str("reason", cloned.Reason).
		Msg("passkey clone detected: credential revoked and all sessions ended")
}
