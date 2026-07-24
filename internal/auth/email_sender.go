package auth

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/mailer"
)

// ---------------------------------------------------------------------------
// White-label email senders (issue #63 follow-on)
//
// Transactional email (MFA codes) resolves its sender on a priority basis:
//
//	application-level sender → tenant-level sender → global SMTP_FROM (env)
//
// Owners/super_admins manage the rows; the SMTP password is stored
// AES-256-GCM encrypted with the server encryption key and never returned by
// any API. A resolution miss (no rows) means the global sender — the feature
// is pure opt-in.
// ---------------------------------------------------------------------------

// ErrSenderNotFound is returned when no sender row exists for the requested scope.
var ErrSenderNotFound = errors.New("email sender settings not found")

// ErrInvalidSender is returned when sender settings fail validation.
var ErrInvalidSender = errors.New("from_address is required and must be valid; smtp providers require smtp_host, sendgrid providers require an api_key")

// SenderProviderSMTP and SenderProviderSendGrid are the supported providers.
const (
	SenderProviderSMTP     = "smtp"
	SenderProviderSendGrid = "sendgrid"
)

// EmailSenderSettings is the API representation of one sender row. The SMTP
// password is write-only: HasPassword reports whether one is stored.
type EmailSenderSettings struct {
	TenantID      string     `json:"tenant_id"`
	ApplicationID *string    `json:"application_id,omitempty"` // nil = tenant-level
	Provider      string     `json:"provider"`                 // "smtp" | "sendgrid"
	FromAddress   string     `json:"from_address"`
	SMTPHost      string     `json:"smtp_host"`
	SMTPPort      int        `json:"smtp_port"`
	SMTPUsername  string     `json:"smtp_username"`
	HasPassword   bool       `json:"has_password"`
	HasAPIKey     bool       `json:"has_api_key"` // sendgrid: an API key is stored
	TLSMode       string     `json:"tls_mode"`
	FromName      string     `json:"from_name"`
	ReplyTo       string     `json:"reply_to"`
	ProductName   string     `json:"product_name"`
	LogoURL       string     `json:"logo_url"`
	SubjectPrefix string     `json:"subject_prefix"`
	IsActive      bool       `json:"is_active"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
}

// UpsertSenderInput is the write payload for sender settings.
type UpsertSenderInput struct {
	// Provider selects the transport ("smtp" | "sendgrid"); empty defaults to "smtp".
	Provider     string
	FromAddress  string
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	// SMTPPassword empty on update = keep the stored password.
	SMTPPassword string
	// APIKey is the SendGrid API key (provider="sendgrid"); empty on update =
	// keep the stored key.
	APIKey        string
	TLSMode       string
	FromName      string
	ReplyTo       string
	ProductName   string
	LogoURL       string
	SubjectPrefix string
	IsActive      *bool
}

// EmailSenderService manages white-label sender settings and resolves the
// effective sender per (tenant, application).
type EmailSenderService struct {
	pool   *pgxpool.Pool
	encKey []byte
	logger zerolog.Logger
}

// NewEmailSenderService creates an EmailSenderService. encKey is the shared
// 32-byte server encryption key (same as TOTP secret encryption).
func NewEmailSenderService(pool *pgxpool.Pool, encKey []byte, logger zerolog.Logger) *EmailSenderService {
	return &EmailSenderService{pool: pool, encKey: encKey, logger: logger}
}

// validate checks an upsert payload. hasStoredSecret reports whether the target
// row already has a stored password/api-key, so an update may omit the secret.
func (in *UpsertSenderInput) validate(hasStoredSecret bool) error {
	if in.Provider == "" {
		in.Provider = SenderProviderSMTP
	}
	if in.Provider != SenderProviderSMTP && in.Provider != SenderProviderSendGrid {
		return ErrInvalidSender
	}
	if in.FromAddress == "" {
		return ErrInvalidSender
	}
	if _, err := mail.ParseAddress(in.FromAddress); err != nil {
		return ErrInvalidSender
	}
	switch in.Provider {
	case SenderProviderSMTP:
		if in.SMTPHost == "" {
			return ErrInvalidSender
		}
		if in.SMTPPort <= 0 || in.SMTPPort > 65535 {
			in.SMTPPort = 587
		}
	case SenderProviderSendGrid:
		// SendGrid needs an API key: either supplied now or already stored.
		if in.APIKey == "" && !hasStoredSecret {
			return ErrInvalidSender
		}
		if in.SMTPPort <= 0 || in.SMTPPort > 65535 {
			in.SMTPPort = 587
		}
	}
	return nil
}

// Upsert creates or updates the sender for a scope (appRowID nil =
// tenant-level). An empty SMTPPassword on an existing row keeps the stored
// password; on a new row it stores an empty password (unauthenticated relay).
func (s *EmailSenderService) Upsert(ctx context.Context, tenantID int64, appRowID *int64, in UpsertSenderInput, updatedBy *int64) (*EmailSenderSettings, error) {
	// Whether the target row already holds a secret decides if a sendgrid update
	// may omit the API key. A miss (ErrSenderNotFound) means "no stored secret".
	existing, err := s.Get(ctx, tenantID, appRowID)
	hasStoredSecret := false
	if err == nil {
		hasStoredSecret = existing.HasPassword || existing.HasAPIKey
	} else if !errors.Is(err, ErrSenderNotFound) {
		return nil, err
	}

	if err := in.validate(hasStoredSecret); err != nil {
		return nil, err
	}

	passwordEnc := ""
	if in.SMTPPassword != "" {
		enc, err := encryptAESGCM(s.encKey, in.SMTPPassword)
		if err != nil {
			return nil, fmt.Errorf("encrypt smtp password: %w", err)
		}
		passwordEnc = enc
	}
	apiKeyEnc := ""
	if in.APIKey != "" {
		enc, err := encryptAESGCM(s.encKey, in.APIKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt api key: %w", err)
		}
		apiKeyEnc = enc
	}

	isActive := true
	if in.IsActive != nil {
		isActive = *in.IsActive
	}

	// Partial unique indexes (tenant-level vs per-app) can't both be named in
	// one ON CONFLICT clause, so do a scoped UPDATE first and INSERT on miss.
	// Empty password/api-key on UPDATE keeps the stored secret.
	tag, err := s.pool.Exec(ctx, `
		UPDATE email_sender_settings
		SET provider      = $3,
		    from_address  = $4,
		    smtp_host     = $5,
		    smtp_port     = $6,
		    smtp_username = $7,
		    smtp_password_enc = CASE WHEN $8 = '' THEN smtp_password_enc ELSE $8 END,
		    api_key_enc   = CASE WHEN $9 = '' THEN api_key_enc ELSE $9 END,
		    is_active     = $10,
		    updated_by    = $11,
		    tls_mode      = $12,
		    from_name     = $13,
		    reply_to      = $14,
		    product_name  = $15,
		    logo_url      = $16,
		    subject_prefix = $17,
		    updated_at    = NOW()
		WHERE tenant_id = $1 AND application_id IS NOT DISTINCT FROM $2
	`, tenantID, appRowID, in.Provider, in.FromAddress, in.SMTPHost, in.SMTPPort, in.SMTPUsername, passwordEnc, apiKeyEnc, isActive, updatedBy,
		in.TLSMode, in.FromName, in.ReplyTo, in.ProductName, in.LogoURL, in.SubjectPrefix)
	if err != nil {
		return nil, fmt.Errorf("update email sender: %w", err)
	}
	if tag.RowsAffected() == 0 {
		_, err = s.pool.Exec(ctx, `
			INSERT INTO email_sender_settings
			  (tenant_id, application_id, provider, from_address, smtp_host, smtp_port, smtp_username, smtp_password_enc, api_key_enc, is_active, updated_by,
			   tls_mode, from_name, reply_to, product_name, logo_url, subject_prefix)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		`, tenantID, appRowID, in.Provider, in.FromAddress, in.SMTPHost, in.SMTPPort, in.SMTPUsername, passwordEnc, apiKeyEnc, isActive, updatedBy,
			in.TLSMode, in.FromName, in.ReplyTo, in.ProductName, in.LogoURL, in.SubjectPrefix)
		if err != nil {
			return nil, fmt.Errorf("insert email sender: %w", err)
		}
	}

	return s.Get(ctx, tenantID, appRowID)
}

// Get returns the sender for one exact scope (no fallback).
func (s *EmailSenderService) Get(ctx context.Context, tenantID int64, appRowID *int64) (*EmailSenderSettings, error) {
	var (
		out       EmailSenderSettings
		appID     *int64
		hasPw     string
		hasAPIKey string
		updatedAt time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT application_id, provider, from_address, COALESCE(smtp_host, ''), smtp_port, smtp_username, smtp_password_enc, api_key_enc, is_active, updated_at,
		       tls_mode, from_name, reply_to, product_name, logo_url, subject_prefix
		FROM email_sender_settings
		WHERE tenant_id = $1 AND application_id IS NOT DISTINCT FROM $2
	`, tenantID, appRowID).Scan(&appID, &out.Provider, &out.FromAddress, &out.SMTPHost, &out.SMTPPort, &out.SMTPUsername, &hasPw, &hasAPIKey, &out.IsActive, &updatedAt,
		&out.TLSMode, &out.FromName, &out.ReplyTo, &out.ProductName, &out.LogoURL, &out.SubjectPrefix)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSenderNotFound
		}
		return nil, fmt.Errorf("load email sender: %w", err)
	}
	out.TenantID = strconv.FormatInt(tenantID, 10)
	if appID != nil {
		idStr := strconv.FormatInt(*appID, 10)
		out.ApplicationID = &idStr
	}
	out.HasPassword = hasPw != ""
	out.HasAPIKey = hasAPIKey != ""
	out.UpdatedAt = &updatedAt
	return &out, nil
}

// Delete removes the sender for one exact scope. Deleting a missing row is
// reported so admins notice typos (404), unlike the idempotent MFA reset.
func (s *EmailSenderService) Delete(ctx context.Context, tenantID int64, appRowID *int64) error {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM email_sender_settings
		WHERE tenant_id = $1 AND application_id IS NOT DISTINCT FROM $2
	`, tenantID, appRowID)
	if err != nil {
		return fmt.Errorf("delete email sender: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrSenderNotFound
	}
	return nil
}

// Resolve returns the effective sender for a send: the application's own row
// if one exists (and is active), else the tenant-level row, else nil — nil
// means "use the global server sender". One query resolves the whole chain:
// rows matching the app sort before the tenant-level row.
func (s *EmailSenderService) Resolve(ctx context.Context, tenantID int64, appRowID *int64) (*mailer.SMTPConfig, error) {
	var (
		provider, from, host, username, passwordEnc, apiKeyEnc   string
		tlsMode, fromName, replyTo, productName, logoURL, prefix string
		port                                                     int
	)
	err := s.pool.QueryRow(ctx, `
		SELECT provider, from_address, COALESCE(smtp_host, ''), smtp_port, smtp_username, smtp_password_enc, api_key_enc,
		       tls_mode, from_name, reply_to, product_name, logo_url, subject_prefix
		FROM email_sender_settings
		WHERE tenant_id = $1
		  AND is_active = true
		  AND (application_id IS NULL OR application_id = $2)
		ORDER BY application_id ASC NULLS LAST
		LIMIT 1
	`, tenantID, appRowID).Scan(&provider, &from, &host, &port, &username, &passwordEnc, &apiKeyEnc,
		&tlsMode, &fromName, &replyTo, &productName, &logoURL, &prefix)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // global sender
		}
		return nil, fmt.Errorf("resolve email sender: %w", err)
	}

	password := ""
	if passwordEnc != "" {
		password, err = decryptAESGCM(s.encKey, passwordEnc)
		if err != nil {
			return nil, fmt.Errorf("decrypt smtp password: %w", err)
		}
	}
	apiKey := ""
	if apiKeyEnc != "" {
		apiKey, err = decryptAESGCM(s.encKey, apiKeyEnc)
		if err != nil {
			return nil, fmt.Errorf("decrypt api key: %w", err)
		}
	}
	return &mailer.SMTPConfig{
		Provider:      provider,
		From:          from,
		Host:          host,
		Port:          port,
		Username:      username,
		Password:      password,
		APIKey:        apiKey,
		TLSMode:       tlsMode,
		FromName:      fromName,
		ReplyTo:       replyTo,
		ProductName:   productName,
		LogoURL:       logoURL,
		SubjectPrefix: prefix,
	}, nil
}
