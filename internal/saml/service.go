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
	AuthnRequestsSigned      bool       `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned     bool       `xml:"WantAssertionsSigned,attr"`
	AssertionConsumerService ACSService `xml:"AssertionConsumerService"`
}

// ACSService describes the Assertion Consumer Service endpoint.
type ACSService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    string `xml:"index,attr"`
}

// Service provides SAML config storage and SP metadata/AuthnRequest
// generation. There is deliberately no response-parsing or JIT provisioning
// here: GHSA-jv2c-x735-vff7 (L-01) removed the dormant implementation because
// it minted sessions from assertions whose IdP signature was never verified.
// ACS returns 501 until signature verification is implemented end to end.
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
