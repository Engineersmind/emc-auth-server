package auth_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

func TestNormalizeServerIP(t *testing.T) {
	ok := map[string]string{
		"203.0.113.10":           "203.0.113.10/32",
		" 203.0.113.10 ":         "203.0.113.10/32",
		"203.0.113.0/28":         "203.0.113.0/28",
		"203.0.113.77/24":        "203.0.113.0/24", // host bits masked
		"10.1.2.3":               "10.1.2.3/32",    // same-VPC backends are legitimate
		"2001:db8::1":            "2001:db8::1/128",
		"2001:db8:abcd::/48":     "2001:db8:abcd::/48",
		"::ffff:203.0.113.10":    "203.0.113.10/32", // IPv4-mapped → IPv4
		"::ffff:203.0.113.0/120": "203.0.113.0/24",
	}
	for in, want := range ok {
		got, err := auth.NormalizeServerIP(in)
		if err != nil {
			t.Errorf("%q: unexpected error %v", in, err)
			continue
		}
		if got.String() != want {
			t.Errorf("%q: got %s, want %s", in, got, want)
		}
	}

	bad := []string{
		"", "not-an-ip", "203.0.113.0/23", "0.0.0.0/0", "0.0.0.0", "::", "::/0",
		"2001:db8::/47", "224.0.0.1", "ff02::1", "fe80::1%eth0", "203.0.113.10/33",
	}
	for _, in := range bad {
		if _, err := auth.NormalizeServerIP(in); err == nil {
			t.Errorf("%q: accepted, want an error", in)
		}
	}
}

func TestNormalizeServerIPs_DedupesAndBounds(t *testing.T) {
	got, err := auth.NormalizeServerIPs([]auth.AppServerIPInput{
		{CIDR: "203.0.113.10", Description: "primary NAT"},
		{CIDR: "203.0.113.10/32", Description: "duplicate"},
		{CIDR: "203.0.113.0/28"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Description != "primary NAT" {
		t.Fatalf("got %+v, want the duplicate dropped and the first description kept", got)
	}

	if _, err := auth.NormalizeServerIPs([]auth.AppServerIPInput{{CIDR: "0.0.0.0/0"}}); !errors.Is(err, auth.ErrInvalidServerIP) {
		t.Fatalf("want ErrInvalidServerIP, got %v", err)
	}

	many := make([]auth.AppServerIPInput, auth.MaxAppServerIPs+1)
	for i := range many {
		many[i] = auth.AppServerIPInput{CIDR: fmt.Sprintf("203.0.%d.%d", i/250, i%250+1)}
	}
	if _, err := auth.NormalizeServerIPs(many); !errors.Is(err, auth.ErrInvalidServerIP) {
		t.Fatalf("%d entries: want ErrInvalidServerIP, got %v", len(many), err)
	}
}

func TestServerTrust_AllowsIP(t *testing.T) {
	tr := auth.ServerTrust{Prefixes: []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/28"),
		netip.MustParsePrefix("2001:db8::/64"),
	}}
	for ip, want := range map[string]bool{
		"203.0.113.5":        true,
		"::ffff:203.0.113.5": true,
		"203.0.113.16":       false,
		"2001:db8::42":       true,
		"2001:db8:1::42":     false,
		"garbage":            false,
		"":                   false,
		"203.0.113.5:443":    false,
	} {
		if got := tr.AllowsIP(ip); got != want {
			t.Errorf("AllowsIP(%q) = %v, want %v", ip, got, want)
		}
	}
	if (auth.ServerTrust{}).HasServerIPs() {
		t.Error("an empty trust has no server IPs")
	}
}

// Integration: database round trip, ownership, snapshot.
func TestAppTrustService_SetGetLookup(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	logger := testhelper.TestLogger()
	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	app, err := auth.NewApplicationService(pool, logger).CreateApplication(ctx, tenantID,
		fmt.Sprintf("s2s-trust-%d", time.Now().UnixNano()), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appID, _ := strconv.ParseInt(app.ID, 10, 64)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth_clients WHERE id = $1`, appID)
	})

	svc := auth.NewAppTrustService(pool, logger)

	// Defaults: nothing trusted, nothing in the snapshot.
	got, err := svc.GetServerTrust(ctx, tenantID, appID)
	if err != nil {
		t.Fatalf("GetServerTrust: %v", err)
	}
	if got.TrustForwardedIP || len(got.ServerIPs) != 0 {
		t.Fatalf("new application must trust nothing, got %+v", got)
	}
	if err := svc.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if _, ok := svc.Lookup(app.ClientID); ok {
		t.Fatal("an application with nothing configured must not be in the snapshot")
	}

	on := true
	ips := []auth.AppServerIPInput{{CIDR: "203.0.113.10", Description: "nat-a"}, {CIDR: "198.51.100.0/28"}}
	got, err = svc.SetServerTrust(ctx, tenantID, appID, &on, &ips)
	if err != nil {
		t.Fatalf("SetServerTrust: %v", err)
	}
	if !got.TrustForwardedIP || len(got.ServerIPs) != 2 || got.ServerIPs[0].CIDR != "203.0.113.10/32" {
		t.Fatalf("after set: %+v", got)
	}

	// Applied to the snapshot on this instance immediately.
	tr, ok := svc.Lookup(app.ClientID)
	if !ok || !tr.TrustForwardedIP || tr.ApplicationID != appID || tr.TenantID != tenantID {
		t.Fatalf("snapshot after set: %+v ok=%v", tr, ok)
	}
	if !tr.AllowsIP("198.51.100.7") || tr.AllowsIP("198.51.100.99") {
		t.Fatalf("snapshot ranges wrong: %+v", tr.Prefixes)
	}

	// A nil list leaves the list alone when only the flag changes.
	off := false
	got, err = svc.SetServerTrust(ctx, tenantID, appID, &off, nil)
	if err != nil {
		t.Fatalf("SetServerTrust flag only: %v", err)
	}
	if got.TrustForwardedIP || len(got.ServerIPs) != 2 {
		t.Fatalf("flag-only update must keep the list: %+v", got)
	}

	// Invalid input changes nothing.
	bad := []auth.AppServerIPInput{{CIDR: "0.0.0.0/0"}}
	if _, err := svc.SetServerTrust(ctx, tenantID, appID, nil, &bad); !errors.Is(err, auth.ErrInvalidServerIP) {
		t.Fatalf("want ErrInvalidServerIP, got %v", err)
	}
	if got, _ := svc.GetServerTrust(ctx, tenantID, appID); len(got.ServerIPs) != 2 {
		t.Fatalf("a rejected update must not change the list: %+v", got)
	}

	// Another tenant cannot read or change it.
	if _, err := svc.GetServerTrust(ctx, tenantID+100000, appID); !errors.Is(err, auth.ErrAppNotFound) {
		t.Fatalf("cross-tenant get: want ErrAppNotFound, got %v", err)
	}
	if _, err := svc.SetServerTrust(ctx, tenantID+100000, appID, &on, nil); !errors.Is(err, auth.ErrAppNotFound) {
		t.Fatalf("cross-tenant set: want ErrAppNotFound, got %v", err)
	}

	// Clearing everything removes the application from the snapshot.
	empty := []auth.AppServerIPInput{}
	if _, err := svc.SetServerTrust(ctx, tenantID, appID, &off, &empty); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, ok := svc.Lookup(app.ClientID); ok {
		t.Fatal("a cleared application must leave the snapshot")
	}

	// A suspended application loses its exemptions.
	if _, err := svc.SetServerTrust(ctx, tenantID, appID, &on, &ips); err != nil {
		t.Fatalf("re-set: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE oauth_clients SET is_active = false WHERE id = $1`, appID); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if err := svc.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if _, ok := svc.Lookup(app.ClientID); ok {
		t.Fatal("a suspended application must leave the snapshot")
	}
}
