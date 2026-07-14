package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// Supported social login providers (issue #64). Microsoft/GitHub become
// additional entries here — the schema and flow are already provider-generic.
const (
	ProviderGoogle = "google"
)

var supportedProviders = map[string]bool{
	ProviderGoogle: true,
}

// ErrProviderNotSupported is returned when the provider path segment is not a
// known social login provider.
var ErrProviderNotSupported = errors.New("identity provider not supported")

// ErrProviderNotConfigured is returned when an application has no enabled
// configuration for the requested provider.
var ErrProviderNotConfigured = errors.New("identity provider not configured for this application")

// ErrInvalidRedirectURI is returned when a redirect target is not an exact
// member of the application's redirect allow-list.
var ErrInvalidRedirectURI = errors.New("redirect_uri is not in the application's allow-list")

// maxRedirectAllowEntries bounds the allow-list size so a misbehaving admin
// call cannot store unbounded arrays.
const maxRedirectAllowEntries = 20

// IdentityProviderService manages per-application social login provider
// credentials (identity_provider_configs). Client secrets are AES-256-GCM
// encrypted at rest via SecretBox and never returned by any read API.
type IdentityProviderService struct {
	pool   *pgxpool.Pool
	box    *SecretBox
	logger zerolog.Logger
}

// NewIdentityProviderService constructs an IdentityProviderService.
func NewIdentityProviderService(pool *pgxpool.Pool, box *SecretBox, logger zerolog.Logger) *IdentityProviderService {
	return &IdentityProviderService{pool: pool, box: box, logger: logger}
}

// ProviderConfigDetail is the public representation of one provider config —
// the client secret is never included.
type ProviderConfigDetail struct {
	ID            string    `json:"id"`
	Provider      string    `json:"provider"`
	ClientID      string    `json:"client_id"`
	Enabled       bool      `json:"enabled"`
	RedirectAllow []string  `json:"redirect_allow"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// UpsertProviderConfigInput is the payload for creating or updating a
// provider config. ClientSecret may be empty on update to keep the stored
// secret unchanged; it is required when no config exists yet.
type UpsertProviderConfigInput struct {
	Provider      string
	ClientID      string
	ClientSecret  string
	Enabled       bool
	RedirectAllow []string
}

// validateRedirectAllow enforces that every allow-list entry is an absolute
// http(s) URL without a fragment. Entries are stored verbatim — matching at
// login time is exact string equality (open-redirect prevention, issue #64).
func validateRedirectAllow(entries []string) error {
	if len(entries) > maxRedirectAllowEntries {
		return fmt.Errorf("redirect_allow: at most %d entries allowed", maxRedirectAllowEntries)
	}
	for _, e := range entries {
		u, err := url.Parse(e)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("redirect_allow entry %q must be an absolute http(s) URL", e)
		}
		if u.Fragment != "" || strings.Contains(e, "#") {
			return fmt.Errorf("redirect_allow entry %q must not contain a fragment", e)
		}
	}
	return nil
}

// UpsertConfig creates or updates the provider config for one application.
// The application must belong to tenantID (enforced in SQL, not trusted from
// the caller). An empty ClientSecret on update preserves the stored secret.
func (s *IdentityProviderService) UpsertConfig(ctx context.Context, tenantID, appID int64, in UpsertProviderConfigInput) (*ProviderConfigDetail, error) {
	if !supportedProviders[in.Provider] {
		return nil, ErrProviderNotSupported
	}
	if in.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if in.RedirectAllow == nil {
		in.RedirectAllow = []string{}
	}
	if err := validateRedirectAllow(in.RedirectAllow); err != nil {
		return nil, err
	}

	// The application must exist, be active, and belong to the caller's tenant.
	var appExists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM oauth_clients
			WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		)
	`, appID, tenantID).Scan(&appExists)
	if err != nil {
		return nil, fmt.Errorf("verify application: %w", err)
	}
	if !appExists {
		return nil, ErrAppNotFound
	}

	var secretEnc string
	if in.ClientSecret != "" {
		secretEnc, err = s.box.Encrypt(in.ClientSecret)
		if err != nil {
			return nil, fmt.Errorf("encrypt client secret: %w", err)
		}
	} else {
		// Keep the existing secret — only valid when a config already exists.
		err = s.pool.QueryRow(ctx, `
			SELECT client_secret_enc FROM identity_provider_configs
			WHERE application_id = $1 AND provider = $2
		`, appID, in.Provider).Scan(&secretEnc)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, fmt.Errorf("client_secret is required when creating a provider config")
			}
			return nil, fmt.Errorf("load existing secret: %w", err)
		}
	}

	var d ProviderConfigDetail
	var id int64
	err = s.pool.QueryRow(ctx, `
		INSERT INTO identity_provider_configs
		    (tenant_id, application_id, provider, client_id, client_secret_enc, enabled, redirect_allow)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (application_id, provider) DO UPDATE
		SET client_id         = EXCLUDED.client_id,
		    client_secret_enc = EXCLUDED.client_secret_enc,
		    enabled           = EXCLUDED.enabled,
		    redirect_allow    = EXCLUDED.redirect_allow,
		    updated_at        = NOW()
		RETURNING id, provider, client_id, enabled, redirect_allow, created_at, updated_at
	`, tenantID, appID, in.Provider, in.ClientID, secretEnc, in.Enabled, in.RedirectAllow).
		Scan(&id, &d.Provider, &d.ClientID, &d.Enabled, &d.RedirectAllow, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("upsert provider config: %w", err)
	}
	d.ID = strconv.FormatInt(id, 10)
	return &d, nil
}

// ListConfigs returns all provider configs for one application, secrets excluded.
func (s *IdentityProviderService) ListConfigs(ctx context.Context, tenantID, appID int64) ([]ProviderConfigDetail, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, provider, client_id, enabled, redirect_allow, created_at, updated_at
		FROM   identity_provider_configs
		WHERE  application_id = $1 AND tenant_id = $2
		ORDER  BY provider
	`, appID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list provider configs: %w", err)
	}
	defer rows.Close()

	configs := []ProviderConfigDetail{}
	for rows.Next() {
		var d ProviderConfigDetail
		var id int64
		if err := rows.Scan(&id, &d.Provider, &d.ClientID, &d.Enabled, &d.RedirectAllow, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan provider config: %w", err)
		}
		d.ID = strconv.FormatInt(id, 10)
		configs = append(configs, d)
	}
	return configs, rows.Err()
}

// DeleteConfig removes the provider config for one application.
func (s *IdentityProviderService) DeleteConfig(ctx context.Context, tenantID, appID int64, provider string) error {
	if !supportedProviders[provider] {
		return ErrProviderNotSupported
	}
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM identity_provider_configs
		WHERE application_id = $1 AND tenant_id = $2 AND provider = $3
	`, appID, tenantID, provider)
	if err != nil {
		return fmt.Errorf("delete provider config: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrProviderNotConfigured
	}
	return nil
}

// flowConfig is the decrypted provider config used by the login flow itself.
// Never serialized; the plaintext secret lives only in memory for the duration
// of one auth-URL build or one code exchange.
type flowConfig struct {
	ClientID      string
	ClientSecret  string
	RedirectAllow []string
}

// getFlowConfig loads and decrypts the enabled provider config for one
// application. Returns ErrProviderNotConfigured when absent OR disabled —
// callers must not distinguish the two (no enumeration of tenant setups).
func (s *IdentityProviderService) getFlowConfig(ctx context.Context, appID int64, provider string) (*flowConfig, error) {
	var cfg flowConfig
	var secretEnc string
	err := s.pool.QueryRow(ctx, `
		SELECT client_id, client_secret_enc, redirect_allow
		FROM   identity_provider_configs
		WHERE  application_id = $1 AND provider = $2 AND enabled = true
	`, appID, provider).Scan(&cfg.ClientID, &secretEnc, &cfg.RedirectAllow)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrProviderNotConfigured
		}
		return nil, fmt.Errorf("load provider config: %w", err)
	}
	cfg.ClientSecret, err = s.box.Decrypt(secretEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt provider client secret: %w", err)
	}
	return &cfg, nil
}

// ErrIdentityNotFound is returned when the user has no linked identity for
// the given provider.
var ErrIdentityNotFound = errors.New("identity not found")

// ErrLastLoginMethod is returned when unlinking would leave the user with no
// way to log in at all (no password credentials and no other identity).
var ErrLastLoginMethod = errors.New("cannot unlink the user's only login method")

// UserIdentityDetail is one linked external identity of a user. The provider
// subject is included (it is a pseudonymous identifier, not a credential).
type UserIdentityDetail struct {
	ID            string    `json:"id"`
	Provider      string    `json:"provider"`
	ProviderEmail *string   `json:"provider_email"`
	CreatedAt     time.Time `json:"created_at"`
}

// ListUserIdentities returns the external identities linked to one user,
// scoped to the caller's tenant.
func (s *IdentityProviderService) ListUserIdentities(ctx context.Context, tenantID, userID int64) ([]UserIdentityDetail, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ui.id, ui.provider, ui.provider_email, ui.created_at
		FROM   user_identities ui
		JOIN   users u ON u.id = ui.user_id
		WHERE  ui.user_id = $1 AND u.tenant_id = $2 AND u.deleted_at IS NULL
		ORDER  BY ui.provider
	`, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list user identities: %w", err)
	}
	defer rows.Close()

	identities := []UserIdentityDetail{}
	for rows.Next() {
		var d UserIdentityDetail
		var id int64
		if err := rows.Scan(&id, &d.Provider, &d.ProviderEmail, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan user identity: %w", err)
		}
		d.ID = strconv.FormatInt(id, 10)
		identities = append(identities, d)
	}
	return identities, rows.Err()
}

// UnlinkUserIdentity removes one linked identity from a user. Refuses when it
// is the user's ONLY login method (no user_credentials row and no other
// identity) — that would strand the account with no way to authenticate.
//
// The guard and the DELETE run in one transaction with the user row locked
// FOR UPDATE: concurrent unlinks on the same user serialize on that lock, so
// two requests can never both pass the guard and jointly strip the account of
// every login method (including unlinks of two DIFFERENT providers).
func (s *IdentityProviderService) UnlinkUserIdentity(ctx context.Context, tenantID, userID int64, provider string) error {
	if !supportedProviders[provider] {
		return ErrProviderNotSupported
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin unlink tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var hasPassword bool
	var identityCount int
	err = tx.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM user_credentials WHERE user_id = u.id),
		       (SELECT COUNT(*) FROM user_identities WHERE user_id = u.id)
		FROM   users u
		WHERE  u.id = $1 AND u.tenant_id = $2 AND u.deleted_at IS NULL
		FOR UPDATE OF u
	`, userID, tenantID).Scan(&hasPassword, &identityCount)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrIdentityNotFound
		}
		return fmt.Errorf("check login methods: %w", err)
	}
	if !hasPassword && identityCount <= 1 {
		return ErrLastLoginMethod
	}

	tag, err := tx.Exec(ctx, `
		DELETE FROM user_identities
		WHERE user_id = $1 AND tenant_id = $2 AND provider = $3
	`, userID, tenantID, provider)
	if err != nil {
		return fmt.Errorf("unlink identity: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrIdentityNotFound
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit unlink: %w", err)
	}
	return nil
}

// resolveRedirect picks the post-login redirect target. An empty requested
// value is allowed only when the allow-list has exactly one entry (it becomes
// the default); otherwise the request must match one entry exactly.
func resolveRedirect(requested string, allow []string) (string, error) {
	if requested == "" {
		if len(allow) == 1 {
			return allow[0], nil
		}
		return "", ErrInvalidRedirectURI
	}
	for _, a := range allow {
		if requested == a {
			return requested, nil
		}
	}
	return "", ErrInvalidRedirectURI
}
