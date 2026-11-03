package auth

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// Database-free checks of the organisation building blocks. These run in every
// environment, including CI without Postgres, so the identifier and validation
// rules cannot regress silently.

func TestOrganizationPublicIDShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		id, err := newOrganizationPublicID()
		if err != nil {
			t.Fatalf("newOrganizationPublicID() error = %v", err)
		}
		if !organizationPublicIDRe.MatchString(id) {
			t.Fatalf("id %q does not match the public id format the database enforces", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q in 200 draws", id)
		}
		seen[id] = true
	}
	inv, err := newInvitationPublicID()
	if err != nil || !strings.HasPrefix(inv, "inv_") || len(inv) != 24 {
		t.Errorf("newInvitationPublicID() = %q, %v; want inv_ + 20 characters", inv, err)
	}
}

func TestOrganizationSlugRule(t *testing.T) {
	good := []string{"a", "acme", "acme-corp", "a1", strings.Repeat("a", 63)}
	bad := []string{"", "-a", "a-", "Acme", "acme corp", "acme_corp", strings.Repeat("a", 64), "é"}
	for _, s := range good {
		if !organizationSlugRe.MatchString(s) {
			t.Errorf("slug %q refused, want accepted", s)
		}
	}
	for _, s := range bad {
		if organizationSlugRe.MatchString(s) {
			t.Errorf("slug %q accepted, want refused", s)
		}
	}
	if got := NormalizeOrganizationSlug("  ACME  "); got != "acme" {
		t.Errorf("NormalizeOrganizationSlug = %q, want acme", got)
	}
}

func TestOrganizationRefTellsIDFromSlug(t *testing.T) {
	if byID, v := organizationRefArgs("org_AbCdEfGhIjKlMnOpQrSt"); !byID || v != "org_AbCdEfGhIjKlMnOpQrSt" {
		t.Errorf("public id resolved as slug")
	}
	// A slug that merely starts with "org_" is still a slug (and an invalid one).
	if byID, v := organizationRefArgs(" Org-Acme "); byID || v != "org-acme" {
		t.Errorf("slug ref = %v/%q, want slug org-acme", byID, v)
	}
}

func TestOrganizationMetadataBound(t *testing.T) {
	if _, err := validateOrganizationMetadata(nil); err != nil {
		t.Errorf("nil metadata error = %v, want accepted as {}", err)
	}
	big := map[string]any{"blob": strings.Repeat("x", maxOrganizationMetadataBytes)}
	if _, err := validateOrganizationMetadata(big); err != ErrInvalidOrganizationMetadata {
		t.Errorf("oversized metadata error = %v, want ErrInvalidOrganizationMetadata", err)
	}
}

func TestEscapeLike(t *testing.T) {
	if got := escapeLike(`50%_off\`); got != `50\%\_off\\` {
		t.Errorf("escapeLike = %q", got)
	}
}

func TestPageParamsAreBounded(t *testing.T) {
	p := PageParams{Limit: 10_000, Offset: -5}.normalised()
	if p.Limit != maxOrganizationPageSize || p.Offset != 0 {
		t.Errorf("normalised = %+v, want limit capped and offset floored", p)
	}
	if d := (PageParams{}).normalised(); d.Limit != defaultOrganizationPageSize {
		t.Errorf("default limit = %d", d.Limit)
	}
}

func TestInvitationStatus(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	cases := []struct {
		exp               time.Time
		accepted, revoked *time.Time
		want              string
	}{
		{future, nil, nil, InvitationStatusPending},
		{past, nil, nil, InvitationStatusExpired},
		{future, &now, nil, InvitationStatusAccepted},
		{future, nil, &now, InvitationStatusRevoked},
		{past, &now, nil, InvitationStatusAccepted},
	}
	for _, c := range cases {
		if got := invitationStatus(c.exp, c.accepted, c.revoked); got != c.want {
			t.Errorf("invitationStatus = %s, want %s", got, c.want)
		}
	}
}

func TestLooksLikeJWT(t *testing.T) {
	if !looksLikeJWT("a.b.c") || looksLikeJWT("abcdef0123") || looksLikeJWT("a.b") {
		t.Error("looksLikeJWT misclassified")
	}
}

// The wire contract for every application that has not opted in: a token
// without an organisation must not carry a single org_* key, not even an empty
// one, so relying parties see a byte-identical payload shape.
func TestClaimsWithoutOrganizationOmitEveryOrgKey(t *testing.T) {
	raw, err := json.Marshal(&Claims{UserID: "1", TenantID: "2", Email: "a@b.c", Role: "viewer", Permissions: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"org_`) {
		t.Errorf("payload %s carries an org_* key with no organisation", raw)
	}
	with, _ := json.Marshal(&Claims{OrgID: "org_x", OrgName: "acme", OrgRoles: []string{"admin"}, OrgPermissions: []string{"docs:approve"}})
	for _, k := range []string{`"org_id"`, `"org_name"`, `"org_roles"`, `"org_permissions"`} {
		if !strings.Contains(string(with), k) {
			t.Errorf("payload %s is missing %s", with, k)
		}
	}
}

// A nil or switched-off service must behave as mode "off" without touching
// the database — that is what lets every caller skip a nil check.
func TestDisabledOrganizationServiceIsOff(t *testing.T) {
	var nilSvc *OrganizationService
	if nilSvc.Enabled() {
		t.Error("nil service reports enabled")
	}
	off := NewOrganizationService(nil, nil, false, zerologNop())
	for _, svc := range []*OrganizationService{nilSvc, off} {
		mode, err := svc.ApplicationMode(t.Context(), 42)
		if err != nil || mode != OrganizationsModeOff {
			t.Errorf("ApplicationMode = %q, %v; want off", mode, err)
		}
		dec, err := svc.DecideOrganization(t.Context(), 1, 42, "acme", false)
		if err != nil || dec.OrgRowID != nil || len(dec.Choices) != 0 || dec.applies {
			t.Errorf("DecideOrganization = %+v, %v; want no organisation", dec, err)
		}
	}
	if _, err := off.CreateOrganization(t.Context(), OrganizationScope{}, CreateOrganizationInput{}); err != ErrOrganizationsDisabled {
		t.Errorf("CreateOrganization error = %v, want ErrOrganizationsDisabled", err)
	}
}

func zerologNop() zerolog.Logger { return zerolog.Nop() }
