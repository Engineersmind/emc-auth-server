package audit

import (
	"testing"
	"time"
)

func baseEvent() Event {
	tid := int64(7)
	uid := int64(42)
	return Event{
		TenantID:     &tid,
		UserID:       &uid,
		Action:       ActionAuthLogin,
		AuthMethod:   AuthMethodPassword,
		ResourceType: "user",
		RequestID:    "req_abc",
		createdAt:    time.UnixMicro(1_700_000_000_000_000).UTC(),
	}
}

func TestChainHash_Deterministic(t *testing.T) {
	e := baseEvent()
	h1 := chainHash("prev", e, StatusSuccess, 200)
	h2 := chainHash("prev", e, StatusSuccess, 200)
	if h1 != h2 {
		t.Fatalf("chainHash not deterministic: %s != %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("expected 64-hex sha256, got %d chars", len(h1))
	}
}

func TestChainHash_LinksToPrev(t *testing.T) {
	e := baseEvent()
	if chainHash("prevA", e, StatusSuccess, 200) == chainHash("prevB", e, StatusSuccess, 200) {
		t.Error("hash must change when prev_hash changes (chain linkage)")
	}
}

func TestChainHash_SkeletonChangesHash(t *testing.T) {
	e := baseEvent()
	base := chainHash("p", e, StatusSuccess, 200)
	if chainHash("p", e, StatusFailure, 200) == base {
		t.Error("status must be part of the hash")
	}
	if chainHash("p", e, StatusSuccess, 401) == base {
		t.Error("http_status must be part of the hash")
	}
	e2 := baseEvent()
	e2.Action = ActionAuthLoginFailed
	if chainHash("p", e2, StatusSuccess, 200) == base {
		t.Error("action must be part of the hash")
	}
}

// The critical compliance property: PII / erasable fields are NOT part of the
// hash, so GDPR pseudonymization can scrub them without breaking verification.
func TestChainHash_IgnoresPII(t *testing.T) {
	e := baseEvent()
	e.ActorEmail = "alice@example.com"
	e.IPAddress = "203.0.113.9"
	e.UserAgent = "Mozilla/5.0 Chrome/120"
	e.Metadata = map[string]any{"browser": "Chrome", "location": map[string]any{"city": "Berlin"}}
	withPII := chainHash("p", e, StatusSuccess, 200)

	erased := baseEvent()
	erased.ActorEmail = "[erased]"
	erased.IPAddress = ""
	erased.UserAgent = "[erased]"
	erased.Metadata = nil
	afterErase := chainHash("p", erased, StatusSuccess, 200)

	if withPII != afterErase {
		t.Errorf("PII must not affect the chain hash (erasure would break verification): %s != %s", withPII, afterErase)
	}
}
