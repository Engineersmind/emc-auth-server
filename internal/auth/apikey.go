package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

const (
	// APIKeyPrefix is prepended to every raw API key for easy identification.
	APIKeyPrefix = "emck_"
	// apiKeyRawBytes is the number of random bytes before base64 encoding.
	apiKeyRawBytes = 32
)

// APIKeyService manages API key lifecycle for machine-to-machine authentication.
type APIKeyService struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger
}

// NewAPIKeyService creates an APIKeyService.
func NewAPIKeyService(pool *pgxpool.Pool, logger zerolog.Logger) *APIKeyService {
	return &APIKeyService{pool: pool, logger: logger}
}

// APIKeyResult is returned by CreateAPIKey — the raw key is shown exactly once.
type APIKeyResult struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	RawKey      string    `json:"key"`           // shown once — never stored
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
}

// APIKeySummary is returned by ListAPIKeys — raw key is never included.
type APIKeySummary struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Permissions []string   `json:"permissions"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

// APIKeyIdentity is resolved by AuthenticateAPIKey — acts like a user identity.
type APIKeyIdentity struct {
	KeyID       uuid.UUID
	TenantID    uuid.UUID
	Name        string
	Permissions []string
}

// CreateAPIKey generates a new API key for the given tenant.
// The raw key is returned exactly once and is never stored — only its SHA-256 hash.
func (s *APIKeyService) CreateAPIKey(ctx context.Context, tenantID uuid.UUID, name string, permissions []string) (*APIKeyResult, error) {
	if name == "" {
		return nil, fmt.Errorf("API key name is required")
	}
	if permissions == nil {
		permissions = []string{}
	}

	// Generate raw key: "emck_" + base64url(32 random bytes)
	buf := make([]byte, apiKeyRawBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate API key: %w", err)
	}
	rawKey := APIKeyPrefix + base64.RawURLEncoding.EncodeToString(buf)

	// Store SHA-256 hash — never the raw key.
	keyHash := HashToken(rawKey) // reuse existing SHA-256 helper from tokens.go

	var keyID uuid.UUID
	var createdAt time.Time
	err := s.pool.QueryRow(ctx, `
		INSERT INTO api_keys (id, tenant_id, name, key_hash, permissions, created_at)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, NOW())
		RETURNING id, created_at
	`, tenantID, name, keyHash, permissions).Scan(&keyID, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("insert api_key: %w", err)
	}

	return &APIKeyResult{
		ID:          keyID.String(),
		Name:        name,
		RawKey:      rawKey,
		Permissions: permissions,
		CreatedAt:   createdAt,
	}, nil
}

// ListAPIKeys returns all active (not revoked) API keys for a tenant.
// The raw key is never included in the response.
func (s *APIKeyService) ListAPIKeys(ctx context.Context, tenantID uuid.UUID) ([]APIKeySummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, permissions, last_used_at, created_at
		FROM api_keys
		WHERE tenant_id = $1 AND revoked_at IS NULL
		ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list api_keys: %w", err)
	}
	defer rows.Close()

	var keys []APIKeySummary
	for rows.Next() {
		var k APIKeySummary
		var id uuid.UUID
		if err := rows.Scan(&id, &k.Name, &k.Permissions, &k.LastUsedAt, &k.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan api_key: %w", err)
		}
		k.ID = id.String()
		if k.Permissions == nil {
			k.Permissions = []string{}
		}
		keys = append(keys, k)
	}
	if keys == nil {
		keys = []APIKeySummary{}
	}
	return keys, rows.Err()
}

// RevokeAPIKey marks an API key as revoked. Only keys belonging to the given
// tenant can be revoked (tenant isolation).
func (s *APIKeyService) RevokeAPIKey(ctx context.Context, tenantID uuid.UUID, keyID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE api_keys
		SET revoked_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL
	`, keyID, tenantID)
	if err != nil {
		return fmt.Errorf("revoke api_key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("API key not found or already revoked")
	}
	return nil
}

// AuthenticateAPIKey validates a raw API key and returns the key identity.
// It also updates last_used_at atomically (best-effort — failure does not block auth).
func (s *APIKeyService) AuthenticateAPIKey(ctx context.Context, rawKey string) (*APIKeyIdentity, error) {
	if rawKey == "" {
		return nil, fmt.Errorf("API key required")
	}

	keyHash := HashToken(rawKey)

	var keyID, tenantID uuid.UUID
	var name string
	var permissions []string
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, permissions
		FROM api_keys
		WHERE key_hash = $1 AND revoked_at IS NULL
	`, keyHash).Scan(&keyID, &tenantID, &name, &permissions)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("invalid API key")
		}
		return nil, fmt.Errorf("lookup api_key: %w", err)
	}

	if permissions == nil {
		permissions = []string{}
	}

	// Best-effort last_used_at update — don't fail auth if this errors.
	if _, err := s.pool.Exec(ctx, `
		UPDATE api_keys SET last_used_at = NOW() WHERE id = $1
	`, keyID); err != nil {
		s.logger.Warn().Err(err).Str("key_id", keyID.String()).Msg("failed to update last_used_at")
	}

	return &APIKeyIdentity{
		KeyID:       keyID,
		TenantID:    tenantID,
		Name:        name,
		Permissions: permissions,
	}, nil
}
