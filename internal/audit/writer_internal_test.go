// Pure-logic tests for the writer's safety layer — no DB, package-internal so
// they can exercise the unexported redaction/serialization helpers directly.
package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildMetadataEmpty(t *testing.T) {
	if got := buildMetadata(nil); got != "{}" {
		t.Fatalf("nil metadata = %q, want {}", got)
	}
	if got := buildMetadata(map[string]any{}); got != "{}" {
		t.Fatalf("empty metadata = %q, want {}", got)
	}
}

func TestBuildMetadataRedactsSecrets(t *testing.T) {
	in := map[string]any{
		"reason":        "invalid_credentials",
		"password":      "hunter2",
		"client_secret": "cs_live_abc",
		"api_key":       "emck_xyz",
		"nested": map[string]any{
			"refresh_token": "rt_should_vanish",
			"http_route":    "/api/v1/auth/login",
		},
		"list": []any{
			map[string]any{"totp_secret": "JBSWY3DP", "keep": "yes"},
		},
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(buildMetadata(in)), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Non-sensitive values survive.
	if out["reason"] != "invalid_credentials" {
		t.Errorf("reason = %v, want invalid_credentials", out["reason"])
	}
	// Top-level secrets redacted.
	for _, k := range []string{"password", "client_secret", "api_key"} {
		if out[k] != "[REDACTED]" {
			t.Errorf("%s = %v, want [REDACTED]", k, out[k])
		}
	}
	// Nested map secrets redacted, siblings preserved.
	nested, ok := out["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested is not an object: %v", out["nested"])
	}
	if nested["refresh_token"] != "[REDACTED]" {
		t.Errorf("nested.refresh_token = %v, want [REDACTED]", nested["refresh_token"])
	}
	if nested["http_route"] != "/api/v1/auth/login" {
		t.Errorf("nested.http_route lost: %v", nested["http_route"])
	}
	// Secrets inside slices of maps redacted too.
	list, ok := out["list"].([]any)
	if !ok || len(list) == 0 {
		t.Fatalf("list is not a non-empty array: %v", out["list"])
	}
	item, ok := list[0].(map[string]any)
	if !ok {
		t.Fatalf("list[0] is not an object: %v", list[0])
	}
	if item["totp_secret"] != "[REDACTED]" {
		t.Errorf("list[0].totp_secret = %v, want [REDACTED]", item["totp_secret"])
	}
	if item["keep"] != "yes" {
		t.Errorf("list[0].keep lost: %v", item["keep"])
	}

	// Defence in depth: the raw serialized form must contain none of the secrets.
	raw := buildMetadata(in)
	for _, secret := range []string{"hunter2", "cs_live_abc", "emck_xyz", "rt_should_vanish", "JBSWY3DP"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("serialized metadata leaked secret %q: %s", secret, raw)
		}
	}
}

func TestBuildMetadataSizeCap(t *testing.T) {
	big := strings.Repeat("x", maxMetadataBytes*2)
	out := buildMetadata(map[string]any{"blob": big})
	if len(out) > maxMetadataBytes {
		t.Fatalf("capped metadata is %d bytes, want <= %d", len(out), maxMetadataBytes)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("truncation marker is not valid json: %v", err)
	}
	if parsed["_truncated"] != true {
		t.Fatalf("expected _truncated marker, got %v", parsed)
	}
}
