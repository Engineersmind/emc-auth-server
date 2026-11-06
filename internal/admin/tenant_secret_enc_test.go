package admin_test

import (
	"context"
	"strings"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// GHSA-4x5m-3gph-938r: when a SecretBox with a real key is wired, CreateTenant
// must store the tenant's jwt_secret ONLY as jwt_secret_enc — the plaintext
// column carries "", never a usable key — and the ciphertext must decrypt back
// to a real secret. Without this test a refactor could quietly write the
// plaintext column again and nothing would notice until a database leak.
func TestCreateTenant_EncryptsJWTSecretAtRest(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	box, err := auth.NewSecretBox(
		strings.Repeat("ab", 32), "test", "TEST_JWT_SIGNING_KEY_ENCRYPTION_KEY",
		testhelper.TestLogger())
	if err != nil {
		t.Fatalf("NewSecretBox: %v", err)
	}
	f.svc.WithSecretBox(box)

	res, err := f.svc.CreateTenant(ctx, admin.CreateTenantInput{
		Name: "Enc Co", Slug: uniqueSlug("enc"), OwnerEmail: "owner@enc.example",
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	var jwtSecret string
	var jwtSecretEnc *string
	if err := f.pool.QueryRow(ctx,
		`SELECT COALESCE(jwt_secret, ''), jwt_secret_enc FROM tenants WHERE slug = $1`,
		res.Tenant.Slug,
	).Scan(&jwtSecret, &jwtSecretEnc); err != nil {
		t.Fatalf("read tenant row: %v", err)
	}

	if jwtSecret != "" {
		t.Errorf("jwt_secret = %q, want \"\" — plaintext must never be stored when a box is wired", jwtSecret)
	}
	if jwtSecretEnc == nil || *jwtSecretEnc == "" {
		t.Fatalf("jwt_secret_enc = %v, want populated ciphertext", jwtSecretEnc)
	}
	plain, err := box.Decrypt(*jwtSecretEnc)
	if err != nil {
		t.Fatalf("jwt_secret_enc does not decrypt under the box key: %v", err)
	}
	if len(plain) != 64 {
		t.Errorf("decrypted jwt_secret length = %d, want 64 (32-byte hex secret)", len(plain))
	}
}

// The inverse contract: without a SecretBox the service writes plaintext as it
// always has — tests and embedders without an encryption key keep working.
func TestCreateTenant_NoSecretBoxKeepsPlaintext(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	res, err := f.svc.CreateTenant(ctx, admin.CreateTenantInput{
		Name: "Plain Co", Slug: uniqueSlug("plain"), OwnerEmail: "owner@plain.example",
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	var jwtSecret string
	var jwtSecretEnc *string
	if err := f.pool.QueryRow(ctx,
		`SELECT COALESCE(jwt_secret, ''), jwt_secret_enc FROM tenants WHERE slug = $1`,
		res.Tenant.Slug,
	).Scan(&jwtSecret, &jwtSecretEnc); err != nil {
		t.Fatalf("read tenant row: %v", err)
	}
	if jwtSecret == "" {
		t.Error("jwt_secret empty with no box wired — plaintext path must still work")
	}
	if jwtSecretEnc != nil && *jwtSecretEnc != "" {
		t.Error("jwt_secret_enc populated without a box — ciphertext should only come from Encrypt")
	}
}
