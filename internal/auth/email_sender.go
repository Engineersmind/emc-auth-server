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
var ErrInvalidSender = errors.New("from_address and smtp_host are required, and from_address must be a valid email")

// EmailSenderSettings is the API representation of one sender row. The SMTP
// password is write-only: HasPassword reports whether one is stored.
type EmailSenderSettings struct {
	TenantID      string     `json:"tenant_id"`
	ApplicationID *string    `json:"application_id,omitempty"` // nil = tenant-level
	FromAddress   string     `json:"from_address"`
	SMTPHost      string     `json:"smtp_host"`
	SMTPPort      int        `json:"smtp_port"`
	SMTPUsername  string     `json:"smtp_username"`
	HasPassword   bool       `json:"has_password"`
	IsActive      bool       `json:"is_active"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
}

// UpsertSenderInput is the write payload for sender settings.
type UpsertSenderInput struct {
	FromAddress  string
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	// SMTPPassword empty on update = keep the stored password.
	SMTPPassword string
	IsActive     *bool
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

// validate checks an upsert payload.
func (in *UpsertSenderInput) validate() error {
	if in.FromAddress == "" || in.SMTPHost == "" {
		return ErrInvalidSender
	}
	if _, err := mail.ParseAddress(in.FromAddress); err != nil {
		return ErrInvalidSender
	}
	if in.SMTPPort <= 0 || in.SMTPPort > 65535 {
		in.SMTPPort = 587
	}
	return nil
}

// Upsert creates or updates the sender for a scope (appRowID nil =
// tenant-level). An empty SMTPPassword on an existing row keeps the stored
// password; on a new row it stores an empty password (unauthenticated relay).
func (s *EmailSenderService) Upsert(ctx context.Context, tenantID int64, appRowID *int64, in UpsertSenderInput, updatedBy *int64) (*EmailSenderSettings, error) {
	if err := in.validate(); err != nil {
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

	isActive := true
	if in.IsActive != nil {
		isActive = *in.IsActive
	}

	// Partial unique indexes (tenant-level vs per-app) can't both be named in
	// one ON CONFLICT clause, so do a scoped UPDATE first and INSERT on miss.
	tag, err := s.pool.Exec(ctx, `
		UPDATE email_sender_settings
		SET from_address  = $3,
		    smtp_host     = $4,
		    smtp_port     = $5,
		    smtp_username = $6,
		    smtp_password_enc = CASE WHEN $7 = '' THEN smtp_password_enc ELSE $7 END,
		    is_active     = $8,
		    updated_by    = $9,
		    updated_at    = NOW()
		WHERE tenant_id = $1 AND application_id IS NOT DISTINCT FROM $2
	`, tenantID, appRowID, in.FromAddress, in.SMTPHost, in.SMTPPort, in.SMTPUsername, passwordEnc, isActive, updatedBy)
	if err != nil {
		return nil, fmt.Errorf("update email sender: %w", err)
	}
	if tag.RowsAffected() == 0 {
		_, err = s.pool.Exec(ctx, `
			INSERT INTO email_sender_settings
			  (tenant_id, application_id, from_address, smtp_host, smtp_port, smtp_username, smtp_password_enc, is_active, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`, tenantID, appRowID, in.FromAddress, in.SMTPHost, in.SMTPPort, in.SMTPUsername, passwordEnc, isActive, updatedBy)
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
		updatedAt time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT application_id, from_address, smtp_host, smtp_port, smtp_username, smtp_password_enc, is_active, updated_at
		FROM email_sender_settings
		WHERE tenant_id = $1 AND application_id IS NOT DISTINCT FROM $2
	`, tenantID, appRowID).Scan(&appID, &out.FromAddress, &out.SMTPHost, &out.SMTPPort, &out.SMTPUsername, &hasPw, &out.IsActive, &updatedAt)
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
		from, host, username, passwordEnc string
		port                              int
	)
	err := s.pool.QueryRow(ctx, `
		SELECT from_address, smtp_host, smtp_port, smtp_username, smtp_password_enc
		FROM email_sender_settings
		WHERE tenant_id = $1
		  AND is_active = true
		  AND (application_id IS NULL OR application_id = $2)
		ORDER BY application_id ASC NULLS LAST
		LIMIT 1
	`, tenantID, appRowID).Scan(&from, &host, &port, &username, &passwordEnc)
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
	return &mailer.SMTPConfig{
		From:     from,
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
	}, nil
}
