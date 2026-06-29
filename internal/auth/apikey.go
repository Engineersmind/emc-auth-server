package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

const (
	APIKeyPrefix   = "emck_"
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
	RawKey      string    `json:"key"`
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

// APIKeyIdentity is resolved by AuthenticateAPIKey.
type APIKeyIdentity struct {
	KeyID       int64
	TenantID    int64
	Name        string
	Permissions []string
}

// CreateAPIKey generates a new API key for the given tenant.
func (s *APIKeyService) CreateAPIKey(ctx context.Context, tenantID int64, name string, permissions []string) (*APIKeyResult, error) {
	if name == "" {
		return nil, fmt.Errorf("API key name is required")
	}
	if permissions == nil {
		permissions = []string{}
	}

	buf := make([]byte, apiKeyRawBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate API key: %w", err)
	}
	rawKey := APIKeyPrefix + base64.RawURLEncoding.EncodeToString(buf)

	keyHash := HashToken(rawKey)

	var keyID int64
	var createdAt time.Time
	err := s.pool.QueryRow(ctx, `
		INSERT INTO api_keys (tenant_id, name, key_hash, permissions, created_at)
		VALUES ($1, $2, $3, $4, NOW())
		RETURNING id, created_at
	`, tenantID, name, keyHash, permissions).Scan(&keyID, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("insert api_key: %w", err)
	}

	return &APIKeyResult{
		ID:          strconv.FormatInt(keyID, 10),
		Name:        name,
		RawKey:      rawKey,
		Permissions: permissions,
		CreatedAt:   createdAt,
	}, nil
}

// ListAPIKeys returns all active API keys for a tenant.
func (s *APIKeyService) ListAPIKeys(ctx context.Context, tenantID int64) ([]APIKeySummary, error) {
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
		var id int64
		if err := rows.Scan(&id, &k.Name, &k.Permissions, &k.LastUsedAt, &k.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan api_key: %w", err)
		}
		k.ID = strconv.FormatInt(id, 10)
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

// RevokeAPIKey marks an API key as revoked.
func (s *APIKeyService) RevokeAPIKey(ctx context.Context, tenantID, keyID int64) error {
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
func (s *APIKeyService) AuthenticateAPIKey(ctx context.Context, rawKey string) (*APIKeyIdentity, error) {
	if rawKey == "" {
		return nil, fmt.Errorf("API key required")
	}

	keyHash := HashToken(rawKey)

	var keyID, tenantID int64
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

	if _, err := s.pool.Exec(ctx, `
		UPDATE api_keys SET last_used_at = NOW() WHERE id = $1
	`, keyID); err != nil {
		s.logger.Warn().Err(err).Str("key_id", strconv.FormatInt(keyID, 10)).Msg("failed to update last_used_at")
	}

	return &APIKeyIdentity{
		KeyID:       keyID,
		TenantID:    tenantID,
		Name:        name,
		Permissions: permissions,
	}, nil
}
