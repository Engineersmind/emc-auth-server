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
	// AgentKeyPrefix is prepended to every raw agent key.
	AgentKeyPrefix = "emc_agent_"
	// agentKeyRawBytes is the number of random bytes before base64 encoding.
	agentKeyRawBytes = 32
)

// AgentService manages agent registration and authentication.
type AgentService struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger
}

// NewAgentService creates an AgentService.
func NewAgentService(pool *pgxpool.Pool, logger zerolog.Logger) *AgentService {
	return &AgentService{pool: pool, logger: logger}
}

// AgentRegistrationResult is returned by RegisterAgent — the raw key is shown exactly once.
type AgentRegistrationResult struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	AgentType    string    `json:"agent_type"`
	Capabilities []string  `json:"capabilities"`
	RawKey       string    `json:"key"` // shown once — never stored
	KeyPrefix    string    `json:"key_prefix"`
	CreatedAt    time.Time `json:"created_at"`
}

// AgentSummary is returned by ListAgents — raw key is never included.
type AgentSummary struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	AgentType    string     `json:"agent_type"`
	Capabilities []string   `json:"capabilities"`
	KeyPrefix    string     `json:"key_prefix"`
	LastUsedAt   *time.Time `json:"last_used_at"`
	CreatedAt    time.Time  `json:"created_at"`
}

// AgentIdentity is resolved by AuthenticateAgent — acts like a machine identity.
type AgentIdentity struct {
	AgentID      uuid.UUID
	TenantID     uuid.UUID
	Name         string
	AgentType    string
	Capabilities []string
}

// RegisterAgent creates a new agent registration for the given tenant.
// The raw key is returned exactly once and is never stored — only its SHA-256 hash.
func (s *AgentService) RegisterAgent(ctx context.Context, tenantID uuid.UUID, name, agentType string, capabilities []string) (*AgentRegistrationResult, error) {
	if name == "" {
		return nil, fmt.Errorf("agent name is required")
	}
	validTypes := map[string]bool{"llm": true, "tool": true, "orchestrator": true, "service": true}
	if !validTypes[agentType] {
		return nil, fmt.Errorf("agent_type must be one of: llm, tool, orchestrator, service")
	}
	if capabilities == nil {
		capabilities = []string{}
	}

	// Generate raw key: "emc_agent_" + base64url(32 random bytes)
	buf := make([]byte, agentKeyRawBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate agent key: %w", err)
	}
	rawKey := AgentKeyPrefix + base64.RawURLEncoding.EncodeToString(buf)

	// Store SHA-256 hash — never the raw key.
	keyHash := HashToken(rawKey)
	// Store a prefix for display: first 16 chars of the raw key.
	keyPrefix := rawKey[:16] + "..."

	var agentID uuid.UUID
	var createdAt time.Time
	err := s.pool.QueryRow(ctx, `
		INSERT INTO agent_registrations
		    (tenant_id, name, agent_type, capabilities, key_hash, key_prefix, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		RETURNING id, created_at
	`, tenantID, name, agentType, capabilities, keyHash, keyPrefix).Scan(&agentID, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("insert agent_registration: %w", err)
	}

	return &AgentRegistrationResult{
		ID:           agentID.String(),
		Name:         name,
		AgentType:    agentType,
		Capabilities: capabilities,
		RawKey:       rawKey,
		KeyPrefix:    keyPrefix,
		CreatedAt:    createdAt,
	}, nil
}

// ListAgents returns all active (not revoked) agent registrations for a tenant.
func (s *AgentService) ListAgents(ctx context.Context, tenantID uuid.UUID) ([]AgentSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, agent_type, capabilities, key_prefix, last_used_at, created_at
		FROM agent_registrations
		WHERE tenant_id = $1 AND revoked_at IS NULL
		ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list agent_registrations: %w", err)
	}
	defer rows.Close()

	var agents []AgentSummary
	for rows.Next() {
		var a AgentSummary
		var id uuid.UUID
		if err := rows.Scan(&id, &a.Name, &a.AgentType, &a.Capabilities, &a.KeyPrefix, &a.LastUsedAt, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan agent_registration: %w", err)
		}
		a.ID = id.String()
		if a.Capabilities == nil {
			a.Capabilities = []string{}
		}
		agents = append(agents, a)
	}
	if agents == nil {
		agents = []AgentSummary{}
	}
	return agents, rows.Err()
}

// RevokeAgent marks an agent registration as revoked. Only agents belonging to the given
// tenant can be revoked (tenant isolation).
func (s *AgentService) RevokeAgent(ctx context.Context, tenantID uuid.UUID, agentID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE agent_registrations
		SET revoked_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL
	`, agentID, tenantID)
	if err != nil {
		return fmt.Errorf("revoke agent_registration: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("agent not found or already revoked")
	}
	return nil
}

// AuthenticateAgent validates a raw agent key and returns the agent identity.
// It also updates last_used_at atomically (best-effort — failure does not block auth).
func (s *AgentService) AuthenticateAgent(ctx context.Context, rawKey string) (*AgentIdentity, error) {
	if rawKey == "" {
		return nil, fmt.Errorf("agent key required")
	}

	keyHash := HashToken(rawKey)

	var agentID, tenantID uuid.UUID
	var name, agentType string
	var capabilities []string
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, agent_type, capabilities
		FROM agent_registrations
		WHERE key_hash = $1 AND revoked_at IS NULL
	`, keyHash).Scan(&agentID, &tenantID, &name, &agentType, &capabilities)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("invalid agent key")
		}
		return nil, fmt.Errorf("lookup agent_registration: %w", err)
	}

	if capabilities == nil {
		capabilities = []string{}
	}

	// Best-effort last_used_at update — don't fail auth if this errors.
	if _, err := s.pool.Exec(ctx, `
		UPDATE agent_registrations SET last_used_at = NOW() WHERE id = $1
	`, agentID); err != nil {
		s.logger.Warn().Err(err).Str("agent_id", agentID.String()).Msg("failed to update agent last_used_at")
	}

	return &AgentIdentity{
		AgentID:      agentID,
		TenantID:     tenantID,
		Name:         name,
		AgentType:    agentType,
		Capabilities: capabilities,
	}, nil
}
