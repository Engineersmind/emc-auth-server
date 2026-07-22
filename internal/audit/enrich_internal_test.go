package audit

import "testing"

func TestParseUA(t *testing.T) {
	tests := []struct {
		name       string
		ua         string
		wantBrowse string
		wantOS     string
		wantMobile bool
		wantDevice string
	}{
		{
			name:       "chrome on mac desktop",
			ua:         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			wantBrowse: "Chrome",
			wantOS:     "Intel Mac OS X 10_15_7",
			wantMobile: false,
			wantDevice: "desktop",
		},
		{
			name:       "safari on iphone mobile",
			ua:         "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			wantBrowse: "Safari",
			wantMobile: true,
			wantDevice: "mobile",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseUA(tt.ua)
			if got == nil {
				t.Fatal("parseUA returned nil for a real UA string")
			}
			if b, _ := got["browser"].(string); b != tt.wantBrowse {
				t.Errorf("browser = %q, want %q", b, tt.wantBrowse)
			}
			if m, _ := got["is_mobile"].(bool); m != tt.wantMobile {
				t.Errorf("is_mobile = %v, want %v", m, tt.wantMobile)
			}
			if d, _ := got["device_type"].(string); d != tt.wantDevice {
				t.Errorf("device_type = %q, want %q", d, tt.wantDevice)
			}
			if _, ok := got["browser_version"]; !ok {
				t.Error("browser_version missing")
			}
		})
	}
}

func TestParseUA_Empty(t *testing.T) {
	if got := parseUA(""); got != nil {
		t.Errorf("parseUA(\"\") = %v, want nil", got)
	}
}

func TestPrivateOrInvalidIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", false},              // public
		{"203.0.113.42", false},         // public (documentation range, still parses as global)
		{"192.168.1.10", true},          // private
		{"10.0.0.1", true},              // private
		{"127.0.0.1", true},             // loopback
		{"::1", true},                   // loopback v6
		{"", true},                      // invalid
		{"not-an-ip", true},             // invalid
		{"2606:4700:4700::1111", false}, // public v6
	}
	for _, tt := range tests {
		if got := PrivateOrInvalidIP(tt.ip); got != tt.want {
			t.Errorf("PrivateOrInvalidIP(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

// enrichedMetadata must not overwrite a caller-set key and must add parsed UA.
func TestEnrichedMetadata_MergesWithoutOverride(t *testing.T) {
	l := &Logger{} // no geo resolver → UA-only enrichment
	e := Event{
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Metadata:  map[string]any{"browser": "caller-set", "http_route": "/login"},
	}
	got := l.enrichedMetadata(e)
	if got["browser"] != "caller-set" {
		t.Errorf("caller browser was overwritten: %v", got["browser"])
	}
	if got["http_route"] != "/login" {
		t.Errorf("existing key lost: %v", got["http_route"])
	}
	if _, ok := got["os"]; !ok {
		t.Error("parsed os not added")
	}
}
