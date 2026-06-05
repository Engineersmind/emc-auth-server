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

// AgentWithStats includes audit-derived activity metrics (08-03).
type AgentWithStats struct {
	AgentSummary
	RequestCount int        `json:"request_count"`       // total audit events attributed to this agent
	LastActive   *time.Time `json:"last_active"`         // most recent audit event timestamp
}

// AgentAnalysis holds 24h risk-scoring data for a single agent (08-04).
type AgentAnalysis struct {
	AgentID       string  `json:"agent_id"`
	AgentName     string  `json:"agent_name"`
	AgentType     string  `json:"agent_type"`
	RequestCount  int     `json:"request_count_24h"`   // total audit events in last 24h
	RateLimitHits int     `json:"rate_limit_hits_24h"` // events with action containing "rate_limit"
	UniqueIPs     int     `json:"unique_ips_24h"`      // distinct IP addresses seen
	OffHoursCount int     `json:"off_hours_count_24h"` // requests outside 08:00–20:00 UTC
	RiskScore     int     `json:"risk_score"`          // 0–100 composite score
	RiskFactors   []string `json:"risk_factors"`        // human-readable reasons for elevated score
}

// AgentIdentity is resolved by AuthenticateAgent — acts like a machine identity.
type AgentIdentity struct {
	AgentID      uuid.UUID
	TenantID     uuid.UUID
	Name         string
	AgentType    string
	Capabilities []string
}

// AnalyzeAgents returns 24h risk analysis for all active agents in a tenant (08-04).
// Risk score (0–100) is computed from weighted signals:
//   - Volume:          >1000 requests/24h          → +30
//   - Rate-limit hits: >10 rate_limit events/24h   → +25
//   - Unique IPs:      >5 distinct IPs/24h         → +25
//   - Off-hours:       >20% requests off-hours     → +20
func (s *AgentService) AnalyzeAgents(ctx context.Context, tenantID uuid.UUID) ([]AgentAnalysis, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
		    a.id,
		    a.name,
		    a.agent_type,
		    COUNT(al.id)                                                        AS request_count,
		    COUNT(al.id) FILTER (WHERE al.action LIKE '%rate_limit%')           AS rate_limit_hits,
		    COUNT(DISTINCT al.ip_address) FILTER (WHERE al.ip_address <> '')    AS unique_ips,
		    COUNT(al.id) FILTER (
		        WHERE EXTRACT(HOUR FROM al.created_at AT TIME ZONE 'UTC') < 8
		           OR EXTRACT(HOUR FROM al.created_at AT TIME ZONE 'UTC') >= 20
		    )                                                                    AS off_hours_count
		FROM agent_registrations a
		LEFT JOIN audit_logs al
		    ON al.agent_id = a.id
		    AND al.created_at >= NOW() - INTERVAL '24 hours'
		WHERE a.tenant_id = $1 AND a.revoked_at IS NULL
		GROUP BY a.id, a.name, a.agent_type
		ORDER BY a.created_at DESC
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("analyze agents: %w", err)
	}
	defer rows.Close()

	var result []AgentAnalysis
	for rows.Next() {
		var a AgentAnalysis
		var id uuid.UUID
		if err := rows.Scan(&id, &a.AgentName, &a.AgentType,
			&a.RequestCount, &a.RateLimitHits, &a.UniqueIPs, &a.OffHoursCount); err != nil {
			return nil, fmt.Errorf("scan agent analysis: %w", err)
		}
		a.AgentID = id.String()

		// Compute risk score and collect explanatory factors.
		score := 0
		var factors []string

		if a.RequestCount > 1000 {
			score += 30
			factors = append(factors, fmt.Sprintf("high volume: %d requests in 24h", a.RequestCount))
		}
		if a.RateLimitHits > 10 {
			score += 25
			factors = append(factors, fmt.Sprintf("rate-limit hits: %d events in 24h", a.RateLimitHits))
		}
		if a.UniqueIPs > 5 {
			score += 25
			factors = append(factors, fmt.Sprintf("many source IPs: %d distinct addresses in 24h", a.UniqueIPs))
		}
		if a.RequestCount > 0 && a.OffHoursCount*100/a.RequestCount > 20 {
			score += 20
			factors = append(factors, fmt.Sprintf("off-hours activity: %d%% of requests outside 08:00–20:00 UTC",
				a.OffHoursCount*100/a.RequestCount))
		}
		if score > 100 {
			score = 100
		}
		if factors == nil {
			factors = []string{}
		}
		a.RiskScore = score
		a.RiskFactors = factors

		result = append(result, a)
	}
	if result == nil {
		result = []AgentAnalysis{}
	}
	return result, rows.Err()
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

// ListAgentsWithStats returns all active agent registrations with audit-derived metrics (08-03).
// request_count and last_active are pulled from audit_logs.agent_id associations.
func (s *AgentService) ListAgentsWithStats(ctx context.Context, tenantID uuid.UUID) ([]AgentWithStats, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
		    a.id, a.name, a.agent_type, a.capabilities, a.key_prefix, a.last_used_at, a.created_at,
		    COUNT(al.id)            AS request_count,
		    MAX(al.created_at)      AS last_active
		FROM agent_registrations a
		LEFT JOIN audit_logs al ON al.agent_id = a.id
		WHERE a.tenant_id = $1 AND a.revoked_at IS NULL
		GROUP BY a.id, a.name, a.agent_type, a.capabilities, a.key_prefix, a.last_used_at, a.created_at
		ORDER BY a.created_at DESC
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list agents with stats: %w", err)
	}
	defer rows.Close()

	var agents []AgentWithStats
	for rows.Next() {
		var a AgentWithStats
		var id uuid.UUID
		if err := rows.Scan(
			&id, &a.Name, &a.AgentType, &a.Capabilities, &a.KeyPrefix, &a.LastUsedAt, &a.CreatedAt,
			&a.RequestCount, &a.LastActive,
		); err != nil {
			return nil, fmt.Errorf("scan agent with stats: %w", err)
		}
		a.ID = id.String()
		if a.Capabilities == nil {
			a.Capabilities = []string{}
		}
		agents = append(agents, a)
	}
	if agents == nil {
		agents = []AgentWithStats{}
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
