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
	// ClientIDPrefix is prepended to every generated client_id so they are
	// immediately recognisable and distinguishable from other token types.
	ClientIDPrefix = "app_"

	clientIDBytes     = 16 // 16 random bytes → 22-char base64url client_id
	clientSecretBytes = 32 // 32 random bytes → 43-char base64url client_secret
)

// ErrInvalidClient is returned when client_id or client_secret do not match a
// live application record.
var ErrInvalidClient = errors.New("invalid client credentials")

// ApplicationService manages OAuth2 client application lifecycle.
// Each tenant registers applications that receive a client_id / client_secret pair.
// The raw client_secret is returned once at creation and never stored — only its
// SHA-256 hash is persisted (same policy as API keys and refresh tokens).
type ApplicationService struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger
}

// NewApplicationService constructs an ApplicationService.
func NewApplicationService(pool *pgxpool.Pool, logger zerolog.Logger) *ApplicationService {
	return &ApplicationService{pool: pool, logger: logger}
}

// AppResult is returned by CreateApplication. ClientSecret is shown exactly once.
type AppResult struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	CreatedAt    time.Time `json:"created_at"`
}

// AppSummary is returned by ListApplications — no secret ever included.
type AppSummary struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	ClientID  string    `json:"client_id"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateApplication registers a new application for a tenant and returns its
// client credentials. The raw client_secret must be stored by the caller; it
// cannot be recovered after this call.
func (s *ApplicationService) CreateApplication(ctx context.Context, tenantID int64, name string) (*AppResult, error) {
	if name == "" {
		return nil, fmt.Errorf("application name is required")
	}

	cidbuf := make([]byte, clientIDBytes)
	if _, err := rand.Read(cidbuf); err != nil {
		return nil, fmt.Errorf("generate client_id: %w", err)
	}
	clientID := ClientIDPrefix + base64.RawURLEncoding.EncodeToString(cidbuf)

	secbuf := make([]byte, clientSecretBytes)
	if _, err := rand.Read(secbuf); err != nil {
		return nil, fmt.Errorf("generate client_secret: %w", err)
	}
	rawSecret := base64.RawURLEncoding.EncodeToString(secbuf)
	secretHash := HashToken(rawSecret)

	var rowID int64
	var createdAt time.Time
	err := s.pool.QueryRow(ctx, `
		INSERT INTO oauth_clients
		    (tenant_id, name, client_id, client_secret_hash, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		RETURNING id, created_at
	`, tenantID, name, clientID, secretHash).Scan(&rowID, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("insert application: %w", err)
	}

	return &AppResult{
		ID:           strconv.FormatInt(rowID, 10),
		Name:         name,
		ClientID:     clientID,
		ClientSecret: rawSecret,
		CreatedAt:    createdAt,
	}, nil
}

// ListApplications returns all active applications for a tenant, without secrets.
func (s *ApplicationService) ListApplications(ctx context.Context, tenantID int64) ([]AppSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, client_id, created_at
		FROM   oauth_clients
		WHERE  tenant_id = $1 AND deleted_at IS NULL
		ORDER  BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list applications: %w", err)
	}
	defer rows.Close()

	apps := []AppSummary{}
	for rows.Next() {
		var a AppSummary
		var id int64
		if err := rows.Scan(&id, &a.Name, &a.ClientID, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan application: %w", err)
		}
		a.ID = strconv.FormatInt(id, 10)
		apps = append(apps, a)
	}
	return apps, rows.Err()
}

// DeactivateApplication soft-deletes an application by setting deleted_at.
// The application's client_id immediately stops being accepted on login/register.
func (s *ApplicationService) DeactivateApplication(ctx context.Context, tenantID, appID int64) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE oauth_clients
		SET    deleted_at = NOW()
		WHERE  id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`, appID, tenantID)
	if err != nil {
		return fmt.Errorf("deactivate application: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("application not found")
	}
	return nil
}

// ValidateClientID confirms that a client_id belongs to the given tenant and is
// active. Returns the application's row id so callers can stamp it into the JWT.
func (s *ApplicationService) ValidateClientID(ctx context.Context, tenantID int64, clientID string) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `
		SELECT id
		FROM   oauth_clients
		WHERE  tenant_id = $1 AND client_id = $2 AND deleted_at IS NULL
	`, tenantID, clientID).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("invalid client_id")
		}
		return 0, fmt.Errorf("validate client_id: %w", err)
	}
	return id, nil
}

// AuthenticateClient validates client_id + client_secret for the
// client_credentials grant. Returns the tenant id and application row id.
func (s *ApplicationService) AuthenticateClient(ctx context.Context, clientID, clientSecret string) (tenantID, appID int64, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT id, tenant_id
		FROM   oauth_clients
		WHERE  client_id = $1 AND client_secret_hash = $2 AND deleted_at IS NULL
	`, clientID, HashToken(clientSecret)).Scan(&appID, &tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, 0, ErrInvalidClient
		}
		return 0, 0, fmt.Errorf("authenticate client: %w", err)
	}
	return tenantID, appID, nil
}
