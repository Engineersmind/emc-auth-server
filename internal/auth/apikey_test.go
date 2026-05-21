package auth_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// newAPIKeyService creates an APIKeyService backed by a real DB with seed data.
func newAPIKeyService(t *testing.T) (*auth.APIKeyService, context.Context, uuid.UUID) {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()

	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	svc := auth.NewAPIKeyService(pool, logger)
	return svc, ctx, store.SeedTenantID
}

func TestAPIKeyService_CreateAndAuthenticate(t *testing.T) {
	svc, ctx, tenantID := newAPIKeyService(t)

	result, err := svc.CreateAPIKey(ctx, tenantID, "ci-service", []string{"read:data"})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	if result == nil {
		t.Fatal("CreateAPIKey() result is nil")
	}
	if !strings.HasPrefix(result.RawKey, auth.APIKeyPrefix) {
		t.Errorf("CreateAPIKey() RawKey = %q, want prefix %q", result.RawKey, auth.APIKeyPrefix)
	}
	if result.ID == "" {
		t.Error("CreateAPIKey() ID is empty")
	}
	if result.Name != "ci-service" {
		t.Errorf("CreateAPIKey() Name = %q, want %q", result.Name, "ci-service")
	}

	identity, err := svc.AuthenticateAPIKey(ctx, result.RawKey)
	if err != nil {
		t.Fatalf("AuthenticateAPIKey() error = %v", err)
	}
	if identity.Name != "ci-service" {
		t.Errorf("AuthenticateAPIKey() Name = %q, want %q", identity.Name, "ci-service")
	}

	found := false
	for _, p := range identity.Permissions {
		if p == "read:data" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("AuthenticateAPIKey() Permissions = %v, expected to contain \"read:data\"", identity.Permissions)
	}
}

func TestAPIKeyService_ListKeys(t *testing.T) {
	svc, ctx, tenantID := newAPIKeyService(t)

	_, err := svc.CreateAPIKey(ctx, tenantID, "key-one", []string{"read:data"})
	if err != nil {
		t.Fatalf("CreateAPIKey() key-one error = %v", err)
	}
	_, err = svc.CreateAPIKey(ctx, tenantID, "key-two", []string{"write:data"})
	if err != nil {
		t.Fatalf("CreateAPIKey() key-two error = %v", err)
	}

	keys, err := svc.ListAPIKeys(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("ListAPIKeys() len = %d, want 2", len(keys))
	}

	// APIKeySummary must not include a raw key field.
	// (Verified by type — no RawKey field exists on APIKeySummary.)
	for _, k := range keys {
		if k.ID == "" {
			t.Error("ListAPIKeys() returned key with empty ID")
		}
		if k.Name == "" {
			t.Error("ListAPIKeys() returned key with empty Name")
		}
	}
}

func TestAPIKeyService_RevokeKey(t *testing.T) {
	svc, ctx, tenantID := newAPIKeyService(t)

	result, err := svc.CreateAPIKey(ctx, tenantID, "revoke-me", []string{"read:data"})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	rawKey := result.RawKey
	keyID, err := uuid.Parse(result.ID)
	if err != nil {
		t.Fatalf("parse key ID: %v", err)
	}

	if err := svc.RevokeAPIKey(ctx, tenantID, keyID); err != nil {
		t.Fatalf("RevokeAPIKey() error = %v", err)
	}

	_, err = svc.AuthenticateAPIKey(ctx, rawKey)
	if err == nil {
		t.Fatal("AuthenticateAPIKey() after revoke expected error, got nil")
	}
}

func TestAPIKeyService_AuthenticateAPIKey_EmptyKey(t *testing.T) {
	svc, ctx, _ := newAPIKeyService(t)

	_, err := svc.AuthenticateAPIKey(ctx, "")
	if err == nil {
		t.Fatal("AuthenticateAPIKey() expected error for empty key, got nil")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("AuthenticateAPIKey() error = %q, want to contain \"required\"", err.Error())
	}
}

func TestAPIKeyService_AuthenticateAPIKey_InvalidKey(t *testing.T) {
	svc, ctx, _ := newAPIKeyService(t)

	_, err := svc.AuthenticateAPIKey(ctx, "emck_fakefakefake")
	if err == nil {
		t.Fatal("AuthenticateAPIKey() expected error for invalid key, got nil")
	}
}
