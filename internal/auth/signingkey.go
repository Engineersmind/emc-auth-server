package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"golang.org/x/sync/singleflight"
)

// Signing-key lifecycle states. See migrations/00065_signing_keys.sql for the
// rationale; the short version is that a key is published (next) before it ever
// signs, and stays published (retired) after it stops, so rotation never
// invalidates a live token.
const (
	KeyStatusNext    = "next"
	KeyStatusActive  = "active"
	KeyStatusRetired = "retired"
)

// AlgorithmRS256 is the only signing algorithm currently issued. RS256 is chosen
// over the smaller/faster ES256 purely for universal library support — it is what
// Auth0 issues and what every JWT library verifies out of the box. The algorithm
// column exists so switching is a per-key decision later, not a migration.
const AlgorithmRS256 = "RS256"

// signingKeyBits is the RSA modulus size. 2048 is the floor every JWT library
// accepts and what Auth0 uses; 4096 would roughly triple verification cost on
// every consumer for no threat-model gain at our token lifetimes (15 minutes).
const signingKeyBits = 2048

// RetiredKeyGrace is how long a retired public key stays published after it stops
// signing. It must exceed the longest token lifetime, otherwise a token minted
// moments before rotation would outlive the key needed to verify it. The longest
// is AgentTokenTTL (1 h), so this is that plus a wide margin for clock skew and
// for verifiers holding a stale cached JWKS.
const RetiredKeyGrace = 3 * time.Hour

// signingKeyCacheTTL bounds how long a cached key set is reused before being
// re-read from the DB. Verification and JWKS serving both go through the cache,
// so without a TTL a rotation performed on another process (or directly in SQL)
// would never be picked up. Short enough to make rotation converge quickly, long
// enough that steady-state verification does no DB work at all.
const signingKeyCacheTTL = 5 * time.Minute

var (
	// ErrNoActiveSigningKey means the tenant has no usable signing key. Callers
	// must treat this as fatal for the request rather than silently falling back
	// to a weaker algorithm.
	ErrNoActiveSigningKey = errors.New("tenant has no active signing key")

	// ErrUnknownKID means a token's kid names no key we hold. Returned during
	// verification, where it must read as a signature failure, not as a hint
	// about which keys exist.
	ErrUnknownKID = errors.New("unknown signing key id")

	// ErrNoTenantsToCollect guards against a programming error: calling
	// CollectGarbage with an empty tenant list would otherwise widen a scoped
	// delete of signing-key material into an unscoped one.
	ErrNoTenantsToCollect = errors.New("collect garbage: no tenants specified")
)

// SigningKey is one asymmetric key pair for a tenant.
//
// Private is nil for keys loaded through a verification/JWKS path: those paths
// need only the public half, and not decrypting the private key means it never
// enters memory where it is not required.
type SigningKey struct {
	ID          int64
	TenantID    int64
	KID         string
	Algorithm   string
	Public      *rsa.PublicKey
	Private     *rsa.PrivateKey
	Status      string
	CreatedAt   time.Time
	ActivatedAt *time.Time
	RetiredAt   *time.Time
}

// tenantKeySet is one tenant's cached keys.
type tenantKeySet struct {
	active      *SigningKey            // the signing key (private loaded)
	publishable []*SigningKey          // active + next + in-grace retired (public only)
	byKID       map[string]*SigningKey // verification lookup
	loadedAt    time.Time
}

// SigningKeyService owns the asymmetric signing keys: generation, encrypted
// storage, in-memory caching, rotation, and the public JWKS view.
//
// Caching is not an optimisation here but a requirement: every token
// verification resolves a key, so an uncached implementation would put a DB read
// on the hot path of every authenticated request — the exact amplification
// problem ME-07 flagged.
type SigningKeyService struct {
	pool   *pgxpool.Pool
	box    *SecretBox
	logger zerolog.Logger

	mu    sync.RWMutex
	cache map[int64]*tenantKeySet

	// loading collapses concurrent cache misses for the same tenant into one
	// load. Without it, a cold start or a TTL expiry under load has every
	// in-flight request issue its own query plus an AES-GCM decrypt and an RSA
	// PEM parse — the classic cache stampede, and the decrypt makes it expensive
	// rather than merely wasteful.
	loading singleflight.Group
}

// NewSigningKeyService builds the service. box must be non-nil — it protects the
// private keys at rest, and a nil box would silently store them in plaintext.
func NewSigningKeyService(pool *pgxpool.Pool, box *SecretBox, logger zerolog.Logger) (*SigningKeyService, error) {
	if box == nil {
		return nil, errors.New("signing key service requires a SecretBox — refusing to store private keys unencrypted")
	}
	return &SigningKeyService{
		pool:   pool,
		box:    box,
		logger: logger,
		cache:  make(map[int64]*tenantKeySet),
	}, nil
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

// thumbprintKID returns the RFC 7638 JWK thumbprint of a public key, base64url
// encoded, for use as the "kid".
//
// A thumbprint rather than a random string: it is derived deterministically from
// the key material, so any verifier can recompute it from the published JWKS and
// confirm that a kid really does name the key it claims to. A random kid is an
// opaque label nobody can check.
func thumbprintKID(pub *rsa.PublicKey) (string, error) {
	jwk := jose.JSONWebKey{Key: pub, Algorithm: AlgorithmRS256, Use: "sig"}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("jwk thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// GenerateKey creates a new RSA key pair for a tenant and stores it with the
// given status. The private half is encrypted before it touches the database.
//
// status is 'active' for a tenant's first key and 'next' when pre-publishing a
// rotation candidate.
func (s *SigningKeyService) GenerateKey(ctx context.Context, tenantID int64, status string) (*SigningKey, error) {
	if status != KeyStatusActive && status != KeyStatusNext {
		return nil, fmt.Errorf("generate signing key: invalid initial status %q", status)
	}

	priv, err := rsa.GenerateKey(rand.Reader, signingKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}

	pubPEM, err := encodePublicKeyPEM(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	privPEM, err := encodePrivateKeyPEM(priv)
	if err != nil {
		return nil, err
	}
	privEnc, err := s.box.Encrypt(privPEM)
	if err != nil {
		return nil, fmt.Errorf("encrypt signing private key: %w", err)
	}

	kid, err := thumbprintKID(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	// activated_at is set only for a key that is signing from birth; a 'next' key
	// gets it when rotation promotes it.
	var activatedAt *time.Time
	if status == KeyStatusActive {
		now := time.Now().UTC()
		activatedAt = &now
	}

	key := &SigningKey{
		TenantID:    tenantID,
		KID:         kid,
		Algorithm:   AlgorithmRS256,
		Public:      &priv.PublicKey,
		Private:     priv,
		Status:      status,
		ActivatedAt: activatedAt,
	}

	err = s.pool.QueryRow(ctx, `
		INSERT INTO signing_keys (tenant_id, kid, algorithm, public_key, private_key_enc, status, activated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at`,
		tenantID, kid, AlgorithmRS256, pubPEM, privEnc, status, activatedAt,
	).Scan(&key.ID, &key.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert signing key: %w", err)
	}

	s.invalidate(tenantID)
	s.logger.Info().
		Int64("tenant_id", tenantID).
		Str("kid", kid).
		Str("status", status).
		Msg("generated JWT signing key")

	return key, nil
}

// EnsureTenantKey guarantees the tenant has an active signing key, generating one
// if it does not.
//
// This is the lazy-generation safety net. Keys are normally created with the
// tenant (admin CreateTenant) and backfilled for pre-existing tenants, but a
// tenant inserted by a path that predates this feature — a fixture, a manual SQL
// insert, a restored backup — would otherwise be unable to issue any token at
// all. Generating on demand degrades to a one-off ~100ms cost instead of a 500.
//
// Safe under concurrency: a lost race hits the one-active-key-per-tenant unique
// index, and the loser re-reads the winner's key rather than failing.
func (s *SigningKeyService) EnsureTenantKey(ctx context.Context, tenantID int64) (*SigningKey, error) {
	if key, err := s.ActiveKey(ctx, tenantID); err == nil {
		return key, nil
	} else if !errors.Is(err, ErrNoActiveSigningKey) {
		return nil, err
	}

	key, err := s.GenerateKey(ctx, tenantID, KeyStatusActive)
	if err == nil {
		return key, nil
	}

	// Only a unique-violation means another process won the race. Any other
	// failure — a SecretBox encryption error, an exhausted pool, RSA generation
	// failing — must surface: treating them all as a lost race would let a
	// concurrently-succeeding ActiveKey() swallow the real error and log a broken
	// encryption subsystem as routine contention.
	if !isUniqueViolation(err) {
		return nil, err
	}

	s.invalidate(tenantID)
	if existing, reErr := s.ActiveKey(ctx, tenantID); reErr == nil {
		s.logger.Debug().Int64("tenant_id", tenantID).Msg("signing key race lost — using the key that won")
		return existing, nil
	}
	return nil, err
}

// ---------------------------------------------------------------------------
// Lookup (cached)
// ---------------------------------------------------------------------------

// ActiveKey returns the tenant's signing key, with its private half loaded.
func (s *SigningKeyService) ActiveKey(ctx context.Context, tenantID int64) (*SigningKey, error) {
	set, err := s.keySet(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if set.active == nil {
		return nil, fmt.Errorf("tenant %d: %w", tenantID, ErrNoActiveSigningKey)
	}
	return set.active, nil
}

// PublicKeyByKID resolves a token's kid to a public key for verification.
//
// tenantID scopes the lookup so a kid belonging to tenant A can never be used to
// verify a token claiming tenant B — the cryptographic half of tenant isolation.
func (s *SigningKeyService) PublicKeyByKID(ctx context.Context, tenantID int64, kid string) (*rsa.PublicKey, error) {
	set, err := s.keySet(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	key, ok := set.byKID[kid]
	if !ok {
		// Re-read once before giving up: a key rotated in by another process may
		// not be in this process's cache yet, and rejecting a validly signed
		// token because of cache staleness would be an outage.
		s.invalidate(tenantID)
		if set, err = s.keySet(ctx, tenantID); err != nil {
			return nil, err
		}
		if key, ok = set.byKID[kid]; !ok {
			return nil, fmt.Errorf("kid %q: %w", kid, ErrUnknownKID)
		}
	}
	return key.Public, nil
}

// PublishableKeys returns the keys that belong in the tenant's JWKS: the active
// key, any pre-published next key, and retired keys still inside their grace
// window. Private halves are not loaded.
func (s *SigningKeyService) PublishableKeys(ctx context.Context, tenantID int64) ([]*SigningKey, error) {
	set, err := s.keySet(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return set.publishable, nil
}

// signingKeyLoadTimeout bounds a shared load. The load runs detached from the
// requesting context (see keySet), so it needs a deadline of its own or a stalled
// query would pin every waiter for that tenant indefinitely.
const signingKeyLoadTimeout = 10 * time.Second

// keySet returns the tenant's cached key set, loading it if absent or stale.
//
// Concurrent misses for the same tenant share a single load. The detail that
// makes sharing safe is that the shared load does not inherit the first caller's
// context: with a plain ctx, that caller disconnecting would cancel the load for
// everyone waiting behind it, converting one client hang-up into a burst of
// verification failures across unrelated requests.
func (s *SigningKeyService) keySet(ctx context.Context, tenantID int64) (*tenantKeySet, error) {
	s.mu.RLock()
	set, ok := s.cache[tenantID]
	s.mu.RUnlock()
	if ok && time.Since(set.loadedAt) < signingKeyCacheTTL {
		return set, nil
	}

	loaded, err, _ := s.loading.Do(strconv.FormatInt(tenantID, 10), func() (any, error) {
		loadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), signingKeyLoadTimeout)
		defer cancel()

		set, err := s.load(loadCtx, tenantID)
		if err != nil {
			return nil, err
		}

		// An empty set is not cached. A tenant id that resolves to no keys is
		// either broken (EnsureTenantKey repairs it on the next issue) or does
		// not exist — and the id reaching this far can come from an unverified
		// token claim, so caching those would let a caller cycling ids grow the
		// map without bound.
		if len(set.byKID) > 0 {
			s.mu.Lock()
			s.cache[tenantID] = set
			s.mu.Unlock()
		}
		return set, nil
	})
	if err != nil {
		return nil, err
	}
	set, ok = loaded.(*tenantKeySet)
	if !ok {
		return nil, fmt.Errorf("signing key cache: unexpected %T from shared load", loaded)
	}
	return set, nil
}

// load reads a tenant's keys from the database and decodes them.
func (s *SigningKeyService) load(ctx context.Context, tenantID int64) (*tenantKeySet, error) {
	// deleted_at IS NULL throughout: the table (migration 00033) carries
	// soft-delete columns and its kid uniqueness index is scoped that way, so
	// ignoring the column would let a soft-deleted key keep verifying tokens.
	rows, err := s.pool.Query(ctx, `
		SELECT id, kid, algorithm, public_key, private_key_enc, status,
		       created_at, activated_at, retired_at
		  FROM signing_keys
		 WHERE tenant_id = $1
		   AND deleted_at IS NULL
		   AND (status <> 'retired' OR retired_at > NOW() - $2::interval)
		 ORDER BY created_at DESC`,
		tenantID, fmt.Sprintf("%d seconds", int(RetiredKeyGrace.Seconds())),
	)
	if err != nil {
		return nil, fmt.Errorf("load signing keys: %w", err)
	}
	defer rows.Close()

	set := &tenantKeySet{
		byKID:    make(map[string]*SigningKey),
		loadedAt: time.Now(),
	}

	for rows.Next() {
		var (
			key     SigningKey
			pubPEM  string
			privEnc string
		)
		if err := rows.Scan(&key.ID, &key.KID, &key.Algorithm, &pubPEM, &privEnc,
			&key.Status, &key.CreatedAt, &key.ActivatedAt, &key.RetiredAt); err != nil {
			return nil, fmt.Errorf("scan signing key: %w", err)
		}
		key.TenantID = tenantID

		pub, err := decodePublicKeyPEM(pubPEM)
		if err != nil {
			// One corrupt row must not take down every other key for the tenant.
			s.logger.Error().Err(err).Str("kid", key.KID).Msg("skipping signing key with undecodable public key")
			continue
		}
		key.Public = pub

		// byKID and publishable get a public-only copy, and set.active gets a
		// separate struct that carries the private half. Sharing one struct
		// between them would mean the later `Private = priv` assignment mutated
		// the entry already handed to the JWKS path: JWKS() reads only .Public
		// so nothing reaches the wire, but PublishableKeys returns the slice
		// itself, and any future caller that logs, reflects over, or marshals it
		// would export private key material. Keeping the split makes that class
		// of leak impossible rather than merely absent today.
		pubOnly := key
		pubOnly.Private = nil
		set.byKID[key.KID] = &pubOnly
		set.publishable = append(set.publishable, &pubOnly)

		// Only the active key needs its private half, so it is the only one we
		// decrypt — a retired key's private material has no remaining use.
		if key.Status == KeyStatusActive {
			privPEM, err := s.box.Decrypt(privEnc)
			if err != nil {
				return nil, fmt.Errorf("decrypt signing private key (kid %s) — check JWT_SIGNING_KEY_ENCRYPTION_KEY: %w", key.KID, err)
			}
			priv, err := decodePrivateKeyPEM(privPEM)
			if err != nil {
				return nil, fmt.Errorf("decode signing private key (kid %s): %w", key.KID, err)
			}
			signer := key
			signer.Private = priv
			set.active = &signer
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate signing keys: %w", err)
	}
	return set, nil
}

// invalidate drops a tenant's cached keys so the next lookup re-reads them.
func (s *SigningKeyService) invalidate(tenantID int64) {
	s.mu.Lock()
	delete(s.cache, tenantID)
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Rotation
// ---------------------------------------------------------------------------

// PrepareRotation generates a 'next' key and publishes it without signing
// anything, which is the whole point: verifiers cache JWKS, so a key must appear
// in the published set before the first token signed with it arrives, or every
// verifier with a warm cache rejects that token until it refetches.
//
// Idempotent — an existing next key is returned rather than replaced.
func (s *SigningKeyService) PrepareRotation(ctx context.Context, tenantID int64) (*SigningKey, error) {
	set, err := s.keySet(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, k := range set.publishable {
		if k.Status == KeyStatusNext {
			return k, nil
		}
	}
	return s.GenerateKey(ctx, tenantID, KeyStatusNext)
}

// CompleteRotation promotes the tenant's 'next' key to 'active' and demotes the
// outgoing key to 'retired', keeping it published for RetiredKeyGrace so tokens
// signed before the switch stay verifiable.
//
// Runs in one transaction: a partial rotation could leave a tenant with no active
// key (unable to issue tokens) or two (violating the unique index). The retire
// must land before the promote, because the partial unique index permits only one
// active key at a time.
func (s *SigningKeyService) CompleteRotation(ctx context.Context, tenantID int64) (*SigningKey, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin rotation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var nextKID string
	err = tx.QueryRow(ctx,
		`SELECT kid FROM signing_keys
		  WHERE tenant_id = $1 AND status = 'next' AND deleted_at IS NULL`, tenantID,
	).Scan(&nextKID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("no 'next' signing key to promote — call PrepareRotation first and let verifiers cache it")
	}
	if err != nil {
		return nil, fmt.Errorf("find next signing key: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`UPDATE signing_keys SET status = 'retired', retired_at = NOW(), updated_at = NOW()
		  WHERE tenant_id = $1 AND status = 'active' AND deleted_at IS NULL`, tenantID); err != nil {
		return nil, fmt.Errorf("retire outgoing signing key: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE signing_keys SET status = 'active', activated_at = NOW(), updated_at = NOW()
		  WHERE tenant_id = $1 AND kid = $2 AND deleted_at IS NULL`, tenantID, nextKID); err != nil {
		return nil, fmt.Errorf("promote next signing key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit rotation: %w", err)
	}

	s.invalidate(tenantID)
	s.logger.Warn().
		Int64("tenant_id", tenantID).
		Str("kid", nextKID).
		Dur("retired_key_published_for", RetiredKeyGrace).
		Msg("rotated JWT signing key")

	return s.ActiveKey(ctx, tenantID)
}

// CollectGarbage deletes retired keys whose grace window has elapsed. Without
// this, every rotation leaves a row behind forever and the published JWKS grows
// without bound, making verifiers download more keys on every refresh.
//
// A hard DELETE, deliberately, even though the table carries a deleted_at column
// and the house default is soft-delete. The row's whole payload is an encrypted
// private key: retaining it after it can no longer verify anything keeps signing
// material at rest for zero benefit. Nothing audits against these rows (rotation
// events go to the audit log instead), so there is no trail to preserve.
//
// The DELETE is scoped to an explicit tenant list. Every other DML in this file
// is tenant-scoped, and a signing-key delete is the last statement that should
// be the exception: an unscoped sweep makes the blast radius of any mistake in
// the predicate — a future edit to the grace expression, a shortened
// RetiredKeyGrace shipped in a rolling deploy — every tenant at once instead of
// one. Passing no tenants is a programming error rather than a silent
// delete-everything; CollectGarbageAllTenants is the deliberate way to sweep.
//
// Tenants without a live active key are skipped. Deleting the last verifiable
// key a tenant has would fail every outstanding token it issued, and a tenant in
// that state is already broken in a way GC must not make permanent.
//
// Returns the number of keys deleted.
func (s *SigningKeyService) CollectGarbage(ctx context.Context, tenantIDs ...int64) (int64, error) {
	if len(tenantIDs) == 0 {
		return 0, ErrNoTenantsToCollect
	}

	tag, err := s.pool.Exec(ctx, `
		DELETE FROM signing_keys k
		 WHERE k.status = 'retired'
		   AND k.retired_at IS NOT NULL
		   AND k.retired_at < NOW() - $1::interval
		   AND k.tenant_id = ANY($2)
		   AND EXISTS (
		       SELECT 1 FROM signing_keys a
		        WHERE a.tenant_id = k.tenant_id
		          AND a.status = 'active'
		          AND a.deleted_at IS NULL
		   )`,
		fmt.Sprintf("%d seconds", int(RetiredKeyGrace.Seconds())), tenantIDs,
	)
	if err != nil {
		return 0, fmt.Errorf("collect retired signing keys: %w", err)
	}
	n := tag.RowsAffected()
	if n > 0 {
		// Only the tenants named here can have lost a key, so drop exactly those
		// cache entries instead of flushing every tenant's set.
		s.mu.Lock()
		for _, id := range tenantIDs {
			delete(s.cache, id)
		}
		s.mu.Unlock()
		s.logger.Info().
			Int64("deleted", n).
			Int("tenants", len(tenantIDs)).
			Msg("garbage-collected retired signing keys")
	}
	return n, nil
}

// CollectGarbageAllTenants sweeps every tenant that currently holds an expired
// retired key. It resolves that list first so the DELETE stays tenant-scoped and
// the number of affected tenants is known and logged, rather than discovered
// after the fact from a row count.
func (s *SigningKeyService) CollectGarbageAllTenants(ctx context.Context) (int64, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT tenant_id
		  FROM signing_keys
		 WHERE status = 'retired'
		   AND retired_at IS NOT NULL
		   AND retired_at < NOW() - $1::interval`,
		fmt.Sprintf("%d seconds", int(RetiredKeyGrace.Seconds())),
	)
	if err != nil {
		return 0, fmt.Errorf("find tenants with expired signing keys: %w", err)
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return 0, fmt.Errorf("scan tenant id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate tenants with expired signing keys: %w", err)
	}
	if len(ids) == 0 {
		return 0, nil
	}
	return s.CollectGarbage(ctx, ids...)
}

// BackfillAllTenants gives every active tenant without one an active signing key.
// Called at startup so tenants that predate this feature can issue RS256 tokens
// immediately rather than paying lazy generation on their next login.
func (s *SigningKeyService) BackfillAllTenants(ctx context.Context) (int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT t.id
		  FROM tenants t
		 WHERE t.is_active = true
		   AND NOT EXISTS (
		       SELECT 1 FROM signing_keys k
		        WHERE k.tenant_id = t.id AND k.status = 'active' AND k.deleted_at IS NULL
		   )`)
	if err != nil {
		return 0, fmt.Errorf("find tenants needing a signing key: %w", err)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan tenant id: %w", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate tenants: %w", err)
	}

	created := 0
	for _, id := range ids {
		if _, err := s.GenerateKey(ctx, id, KeyStatusActive); err != nil {
			// Keep going: one tenant's failure should not deny keys to the rest.
			s.logger.Error().Err(err).Int64("tenant_id", id).Msg("signing key backfill failed for tenant")
			continue
		}
		created++
	}
	return created, nil
}

// ---------------------------------------------------------------------------
// JWKS
// ---------------------------------------------------------------------------

// JWKS returns the tenant's public keys as a JSON Web Key Set, ready to serialise
// at /tenants/{slug}/.well-known/jwks.json.
//
// Only public halves are ever placed in a jose.JSONWebKey here. Handing an
// *rsa.PrivateKey to go-jose would serialise the private fields (d, p, q, …) into
// the published document — the single worst failure this feature could have, and
// why a test asserts the endpoint's body contains none of them.
func (s *SigningKeyService) JWKS(ctx context.Context, tenantID int64) (*jose.JSONWebKeySet, error) {
	keys, err := s.PublishableKeys(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	set := &jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(keys))}
	for _, k := range keys {
		set.Keys = append(set.Keys, jose.JSONWebKey{
			Key:       k.Public, // public only — never k.Private
			KeyID:     k.KID,
			Algorithm: k.Algorithm,
			Use:       "sig",
		})
	}
	return set, nil
}

// ---------------------------------------------------------------------------
// PEM helpers
// ---------------------------------------------------------------------------

func encodePublicKeyPEM(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

func decodePublicKeyPEM(s string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("public key is not valid PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, want *rsa.PublicKey", parsed)
	}
	return pub, nil
}

func encodePrivateKeyPEM(priv *rsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("marshal private key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func decodePrivateKeyPEM(s string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("private key is not valid PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	priv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, want *rsa.PrivateKey", parsed)
	}
	return priv, nil
}
