package saml

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/url"
	"time"

	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// SAMLConfig holds per-tenant SAML IdP configuration.
type SAMLConfig struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	EntityID    string    `json:"entity_id"`
	SSOURL      string    `json:"sso_url"`
	Certificate string    `json:"certificate"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// SPMetadata is the XML structure for SP metadata.
type SPMetadata struct {
	XMLName         xml.Name        `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID        string          `xml:"entityID,attr"`
	SPSSODescriptor SPSSODescriptor `xml:"SPSSODescriptor"`
}

// SPSSODescriptor describes the SP SSO capabilities.
type SPSSODescriptor struct {
	AuthnRequestsSigned  bool       `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned bool       `xml:"WantAssertionsSigned,attr"`
	AssertionConsumerService ACSService `xml:"AssertionConsumerService"`
}

// ACSService describes the Assertion Consumer Service endpoint.
type ACSService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    string `xml:"index,attr"`
}

// User is a lightweight user record returned by JIT provisioning.
type User struct {
	ID       string
	Email    string
	TenantID string
	Role     string
}

// Service provides SAML config storage, metadata generation, and JIT provisioning.
type Service struct {
	pool    *pgxpool.Pool
	baseURL string
	logger  zerolog.Logger
}

// New creates a new SAML Service.
func New(pool *pgxpool.Pool, baseURL string, logger zerolog.Logger) *Service {
	return &Service{pool: pool, baseURL: baseURL, logger: logger}
}

// GetConfig retrieves the SAML IdP configuration for a tenant.
func (s *Service) GetConfig(ctx context.Context, tenantID string) (*SAMLConfig, error) {
	tid, err := strconv.ParseInt(tenantID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant_id %q: %w", tenantID, err)
	}
	var cfg SAMLConfig
	err = s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, entity_id, sso_url, certificate, created_at, updated_at
		FROM saml_configs WHERE tenant_id = $1`, tid,
	).Scan(&cfg.ID, &cfg.TenantID, &cfg.EntityID, &cfg.SSOURL, &cfg.Certificate,
		&cfg.CreatedAt, &cfg.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("saml config not found for tenant: %w", err)
	}
	return &cfg, nil
}

// UpsertConfig creates or updates the SAML IdP configuration for a tenant.
func (s *Service) UpsertConfig(ctx context.Context, tenantID string, req SAMLConfig) (*SAMLConfig, error) {
	tid, err := strconv.ParseInt(tenantID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant_id %q: %w", tenantID, err)
	}
	var cfg SAMLConfig
	err = s.pool.QueryRow(ctx, `
		INSERT INTO saml_configs (tenant_id, entity_id, sso_url, certificate)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id) DO UPDATE
		SET entity_id = EXCLUDED.entity_id, sso_url = EXCLUDED.sso_url,
		    certificate = EXCLUDED.certificate, updated_at = NOW()
		RETURNING id, tenant_id, entity_id, sso_url, certificate, created_at, updated_at`,
		tid, req.EntityID, req.SSOURL, req.Certificate,
	).Scan(&cfg.ID, &cfg.TenantID, &cfg.EntityID, &cfg.SSOURL, &cfg.Certificate,
		&cfg.CreatedAt, &cfg.UpdatedAt)
	return &cfg, err
}

// GenerateMetadata returns SP metadata XML for the given tenant.
func (s *Service) GenerateMetadata(tenantID string) ([]byte, error) {
	acsURL := s.baseURL + "/saml/acs?tenant=" + url.QueryEscape(tenantID)
	entityID := s.baseURL + "/saml/metadata?tenant=" + url.QueryEscape(tenantID)

	meta := SPMetadata{
		EntityID: entityID,
		SPSSODescriptor: SPSSODescriptor{
			AuthnRequestsSigned:  false,
			WantAssertionsSigned: true,
			AssertionConsumerService: ACSService{
				Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
				Location: acsURL,
				Index:    "1",
			},
		},
	}

	out, err := xml.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}
	return out, nil
}

// BuildAuthnRequest creates a base64-encoded SAMLRequest for SP-initiated SSO.
func (s *Service) BuildAuthnRequest(tenantID, ssoURL string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate request id: %w", err)
	}
	id := "_" + base64.URLEncoding.EncodeToString(b)[:20]
	acsURL := s.baseURL + "/saml/acs?tenant=" + url.QueryEscape(tenantID)
	entityID := s.baseURL + "/saml/metadata?tenant=" + url.QueryEscape(tenantID)

	authnReq := fmt.Sprintf(`<?xml version="1.0"?>
<samlp:AuthnRequest
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="%s"
  Version="2.0"
  IssueInstant="%s"
  Destination="%s"
  AssertionConsumerServiceURL="%s"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>%s</saml:Issuer>
</samlp:AuthnRequest>`,
		id,
		time.Now().UTC().Format(time.RFC3339),
		ssoURL,
		acsURL,
		entityID,
	)

	return base64.StdEncoding.EncodeToString([]byte(authnReq)), nil
}

// ParseACSResponse parses a base64-encoded SAMLResponse and extracts the NameID.
//
// NOTE: This is a simplified parser — it does NOT verify the IdP signature.
// In production, use a library that performs full XML signature validation
// (e.g., crewjam/saml or russellhaering/gosaml2). Signature verification is
// a known gap and must be addressed before handling real IdP assertions.
func (s *Service) ParseACSResponse(samlResponse string) (email string, attrs map[string]string, err error) {
	xmlBytes, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode SAMLResponse: %w", err)
	}

	// Minimal XML structs for extracting the NameID from the Assertion.
	type nameID struct {
		Value string `xml:",chardata"`
	}
	type subject struct {
		NameID nameID `xml:"NameID"`
	}
	type assertion struct {
		Subject subject `xml:"Subject"`
	}
	type responseDoc struct {
		Assertion assertion `xml:"Assertion"`
	}

	var resp responseDoc
	if xmlErr := xml.Unmarshal(xmlBytes, &resp); xmlErr != nil {
		return "", nil, fmt.Errorf("failed to parse SAMLResponse XML: %w", xmlErr)
	}

	email = resp.Assertion.Subject.NameID.Value
	if email == "" {
		return "", nil, fmt.Errorf("NameID (email) not found in SAMLResponse")
	}

	return email, map[string]string{}, nil
}

// FindOrCreateUser performs JIT provisioning: looks up a user by tenant+email,
// creating one if not found. The created user has no usable password (SAML-only login).
func (s *Service) FindOrCreateUser(ctx context.Context, tenantID, email string) (*User, error) {
	tenantIDInt, err := strconv.ParseInt(tenantID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant_id: %w", err)
	}

	// Try to find existing user.
	var userID int64
	var roleName string
	err = s.pool.QueryRow(ctx, `
		SELECT u.id, COALESCE(r.name, '')
		FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.tenant_id = $1 AND u.email = $2 AND u.is_active = true AND u.deleted_at IS NULL
	`, tenantIDInt, email).Scan(&userID, &roleName)
	if err == nil {
		return &User{ID: strconv.FormatInt(userID, 10), Email: email, TenantID: tenantID, Role: roleName}, nil
	}
	if err != pgx.ErrNoRows {
		return nil, fmt.Errorf("lookup user: %w", err)
	}

	// User not found — JIT provision.
	// Fetch default (non-system) role for the tenant.
	var roleID *int64
	var tempRoleID int64
	err = s.pool.QueryRow(ctx,
		`SELECT id, name FROM roles WHERE tenant_id = $1 AND is_system = false AND deleted_at IS NULL ORDER BY name LIMIT 1`,
		tenantIDInt,
	).Scan(&tempRoleID, &roleName)
	if err == nil {
		roleID = &tempRoleID
	} else if err != pgx.ErrNoRows {
		return nil, fmt.Errorf("fetch default role: %w", err)
	}

	// Insert user + a locked credential row (random bytes — cannot be used for password login).
	// users.id is GENERATED ALWAYS AS IDENTITY — do not supply an explicit value.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	err = tx.QueryRow(ctx, `
		INSERT INTO users (tenant_id, email, first_name, last_name, role_id, is_active)
		VALUES ($1, $2, '', '', $3, true)
		RETURNING id
	`, tenantIDInt, email, roleID).Scan(&userID)
	if err != nil {
		return nil, fmt.Errorf("insert JIT user: %w", err)
	}

	// Generate a random unusable password hash so the user_credentials row exists
	// but cannot be used for password-based login.
	randomBytes := make([]byte, 32)
	if _, randErr := rand.Read(randomBytes); randErr != nil {
		return nil, fmt.Errorf("generate random credential: %w", randErr)
	}
	lockedHash := "saml:" + base64.StdEncoding.EncodeToString(randomBytes)

	_, err = tx.Exec(ctx, `
		INSERT INTO user_credentials (user_id, tenant_id, password_hash)
		VALUES ($1, $2, $3)
	`, userID, tenantIDInt, lockedHash)
	if err != nil {
		return nil, fmt.Errorf("insert JIT credentials: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit JIT provision: %w", err)
	}

	userIDStr := strconv.FormatInt(userID, 10)
	s.logger.Info().Str("user_id", userIDStr).Str("email", email).
		Str("tenant_id", tenantID).Msg("saml: JIT provisioned new user")

	return &User{ID: userIDStr, Email: email, TenantID: tenantID, Role: roleName}, nil
}
