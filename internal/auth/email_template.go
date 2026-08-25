package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/mailer"
)

// ---------------------------------------------------------------------------
// Per-scope email templates (Auth0-style). Each transactional email has a
// built-in default (in the mailer package) that a tenant or application may
// override in the DB. Resolution priority matches the sender chain:
//
//	application template → tenant template → built-in default
//
// A resolution miss (no row) returns nil — the caller passes nil to the mailer,
// which then renders the built-in default.
// ---------------------------------------------------------------------------

// ErrTemplateNotFound is returned when no template row exists for a scope+type.
var ErrTemplateNotFound = errors.New("email template not found")

// ErrInvalidTemplateType is returned for an unknown template type.
var ErrInvalidTemplateType = errors.New("unknown email template type")

// ErrInvalidTemplate is returned when template content fails validation.
var ErrInvalidTemplate = errors.New("template subject and html body are required and must be valid Go templates")

// EmailTemplate is the API representation of one template row.
type EmailTemplate struct {
	TenantID      string     `json:"tenant_id"`
	ApplicationID *string    `json:"application_id,omitempty"` // nil = tenant-level
	TemplateType  string     `json:"template_type"`
	Subject       string     `json:"subject"`
	HTMLBody      string     `json:"html_body"`
	TextBody      string     `json:"text_body"`
	IsActive      bool       `json:"is_active"`
	IsDefault     bool       `json:"is_default"` // true when returned from the built-in fallback
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
}

// UpsertTemplateInput is the write payload for a template.
type UpsertTemplateInput struct {
	Subject  string
	HTMLBody string
	TextBody string
	IsActive *bool
}

// EmailTemplateService manages per-scope templates and resolves the effective
// template for a send.
type EmailTemplateService struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger
}

// NewEmailTemplateService creates an EmailTemplateService.
func NewEmailTemplateService(pool *pgxpool.Pool, logger zerolog.Logger) *EmailTemplateService {
	return &EmailTemplateService{pool: pool, logger: logger}
}

func (in *UpsertTemplateInput) validate() error {
	t := mailer.Template{Subject: in.Subject, HTML: in.HTMLBody, Text: in.TextBody}
	if err := t.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTemplate, err)
	}
	return nil
}

// Resolve returns the effective template for a send, or nil when no active
// override exists (caller uses the built-in default). App row wins over tenant.
func (s *EmailTemplateService) Resolve(ctx context.Context, tenantID int64, appRowID *int64, tt mailer.TemplateType) (*mailer.Template, error) {
	var subject, html, text string
	err := s.pool.QueryRow(ctx, `
		SELECT subject, html_body, text_body
		FROM email_templates
		WHERE tenant_id = $1
		  AND template_type = $3
		  AND is_active = true
		  AND (application_id IS NULL OR application_id = $2)
		ORDER BY application_id ASC NULLS LAST
		LIMIT 1
	`, tenantID, appRowID, string(tt)).Scan(&subject, &html, &text)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // built-in default
		}
		return nil, fmt.Errorf("resolve email template: %w", err)
	}
	return &mailer.Template{Subject: subject, HTML: html, Text: text}, nil
}

// Upsert creates or updates a template for a scope+type.
func (s *EmailTemplateService) Upsert(ctx context.Context, tenantID int64, appRowID *int64, tt mailer.TemplateType, in UpsertTemplateInput, updatedBy *int64) (*EmailTemplate, error) {
	if !mailer.ValidTemplateType(tt) {
		return nil, ErrInvalidTemplateType
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	isActive := true
	if in.IsActive != nil {
		isActive = *in.IsActive
	}

	// Scoped UPDATE first, INSERT on miss (partial unique indexes can't share an
	// ON CONFLICT target), mirroring EmailSenderService.Upsert.
	tag, err := s.pool.Exec(ctx, `
		UPDATE email_templates
		SET subject = $4, html_body = $5, text_body = $6, is_active = $7, updated_by = $8, updated_at = NOW()
		WHERE tenant_id = $1 AND application_id IS NOT DISTINCT FROM $2 AND template_type = $3
	`, tenantID, appRowID, string(tt), in.Subject, in.HTMLBody, in.TextBody, isActive, updatedBy)
	if err != nil {
		return nil, fmt.Errorf("update email template: %w", err)
	}
	if tag.RowsAffected() == 0 {
		_, err = s.pool.Exec(ctx, `
			INSERT INTO email_templates (tenant_id, application_id, template_type, subject, html_body, text_body, is_active, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, tenantID, appRowID, string(tt), in.Subject, in.HTMLBody, in.TextBody, isActive, updatedBy)
		if err != nil {
			return nil, fmt.Errorf("insert email template: %w", err)
		}
	}
	return s.Get(ctx, tenantID, appRowID, tt)
}

// Get returns the stored template for one exact scope+type, or the built-in
// default (IsDefault=true) when no row exists.
func (s *EmailTemplateService) Get(ctx context.Context, tenantID int64, appRowID *int64, tt mailer.TemplateType) (*EmailTemplate, error) {
	if !mailer.ValidTemplateType(tt) {
		return nil, ErrInvalidTemplateType
	}
	var (
		out       EmailTemplate
		appID     *int64
		updatedAt time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT application_id, subject, html_body, text_body, is_active, updated_at
		FROM email_templates
		WHERE tenant_id = $1 AND application_id IS NOT DISTINCT FROM $2 AND template_type = $3
	`, tenantID, appRowID, string(tt)).Scan(&appID, &out.Subject, &out.HTMLBody, &out.TextBody, &out.IsActive, &updatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Return the built-in default so admins can see/seed the editor.
			def, _ := mailer.BuiltinTemplate(tt)
			return &EmailTemplate{
				TenantID:     strconv.FormatInt(tenantID, 10),
				TemplateType: string(tt),
				Subject:      def.Subject,
				HTMLBody:     def.HTML,
				TextBody:     def.Text,
				IsActive:     true,
				IsDefault:    true,
			}, nil
		}
		return nil, fmt.Errorf("load email template: %w", err)
	}
	out.TenantID = strconv.FormatInt(tenantID, 10)
	out.TemplateType = string(tt)
	if appID != nil {
		idStr := strconv.FormatInt(*appID, 10)
		out.ApplicationID = &idStr
	}
	out.UpdatedAt = &updatedAt

	// A SUPPRESSION row — inactive with empty bodies — holds no content of its
	// own. It exists to say "do not send this", which is how a new application
	// starts (migration 00073), and Resolve already ignores it so the built-in
	// default is what would go out once it is enabled.
	//
	// Fill the editor from that default rather than returning the empty strings
	// literally. Otherwise the admin UI shows a blank subject and body for every
	// template on a new application, and the operator has to retype content that
	// already exists — or worse, saves the blank as their template.
	//
	// IsDefault stays true: the content IS the maintained default, so the UI
	// correctly offers "customise" rather than "reset", and enabling without
	// editing keeps receiving upstream improvements.
	if !out.IsActive && out.Subject == "" && out.HTMLBody == "" {
		if def, ok := mailer.BuiltinTemplate(tt); ok {
			out.Subject = def.Subject
			out.HTMLBody = def.HTML
			out.TextBody = def.Text
			out.IsDefault = true
		}
	}
	return &out, nil
}

// Delete removes a template override for one exact scope+type (reverting to the
// built-in default). A missing row is reported so admins notice typos.
func (s *EmailTemplateService) Delete(ctx context.Context, tenantID int64, appRowID *int64, tt mailer.TemplateType) error {
	if !mailer.ValidTemplateType(tt) {
		return ErrInvalidTemplateType
	}
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM email_templates
		WHERE tenant_id = $1 AND application_id IS NOT DISTINCT FROM $2 AND template_type = $3
	`, tenantID, appRowID, string(tt))
	if err != nil {
		return fmt.Errorf("delete email template: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrTemplateNotFound
	}
	return nil
}

// List returns, for every known template type, the stored override if present
// otherwise the built-in default — so an admin sees the full set at a glance.
func (s *EmailTemplateService) List(ctx context.Context, tenantID int64, appRowID *int64) ([]EmailTemplate, error) {
	out := make([]EmailTemplate, 0, len(mailer.AllTemplateTypes))
	for _, tt := range mailer.AllTemplateTypes {
		t, err := s.Get(ctx, tenantID, appRowID, tt)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, nil
}

// ResolveTemplate is a helper for send paths: resolve the override, degrading to
// nil (built-in default) on any error so a bad template never blocks a send.
func (s *EmailTemplateService) ResolveTemplate(ctx context.Context, tenantID int64, appRowID *int64, tt mailer.TemplateType) *mailer.Template {
	if s == nil {
		return nil
	}
	tmpl, err := s.Resolve(ctx, tenantID, appRowID, tt)
	if err != nil {
		s.logger.Warn().Err(err).Str("type", string(tt)).Int64("tenant_id", tenantID).Msg("template resolution failed — using built-in default")
		return nil
	}
	return tmpl
}

// IsTypeEnabled reports whether a template type is enabled for a scope — i.e.
// whether the email should be sent at all. A stored row with is_active=false at
// the resolved scope (application → tenant) suppresses the send entirely; when
// no row exists the type is enabled (the built-in default is sent). On any
// lookup error it degrades to enabled, so a transient DB issue never silently
// blocks a login-critical email. A nil service is enabled (no suppression).
func (s *EmailTemplateService) IsTypeEnabled(ctx context.Context, tenantID int64, appRowID *int64, tt mailer.TemplateType) bool {
	if s == nil {
		return true
	}
	var isActive bool
	err := s.pool.QueryRow(ctx, `
		SELECT is_active
		FROM email_templates
		WHERE tenant_id = $1
		  AND template_type = $3
		  AND (application_id IS NULL OR application_id = $2)
		ORDER BY application_id ASC NULLS LAST
		LIMIT 1
	`, tenantID, appRowID, string(tt)).Scan(&isActive)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return true // no override stored → send the built-in default
		}
		s.logger.Warn().Err(err).Str("type", string(tt)).Int64("tenant_id", tenantID).Msg("template enabled-check failed — defaulting to enabled")
		return true
	}
	return isActive
}
