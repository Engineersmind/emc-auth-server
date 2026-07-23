// Package enrich provides concrete implementations of the audit package's
// optional enrichment interfaces that depend on external data files/libraries
// the audit package should not import directly.
//
// GeoIPResolver wraps a MaxMind GeoLite2/GeoIP2-City database and satisfies
// audit.GeoResolver. It is constructed only when a database path is configured;
// when the path is empty the server runs with geo enrichment disabled and no
// GeoIP dependency is exercised at runtime.
package enrich

import (
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"

	"github.com/engineersmind/emc-auth-server/internal/audit"
)

// GeoIPResolver resolves IPs to a coarse location via a MaxMind City database.
// The underlying *geoip2.Reader is safe for concurrent use.
type GeoIPResolver struct {
	reader *geoip2.Reader
}

// NewGeoIPResolver opens the MaxMind City database at path. A nil resolver is
// returned (with nil error) when path is empty — the caller then simply omits
// audit.WithGeoIP and geo enrichment stays off.
func NewGeoIPResolver(path string) (*GeoIPResolver, error) {
	if path == "" {
		return nil, nil
	}
	reader, err := geoip2.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open geoip database %q: %w", path, err)
	}
	return &GeoIPResolver{reader: reader}, nil
}

// Lookup implements audit.GeoResolver. Private/invalid IPs and misses return
// ok=false so no bogus location is attached.
func (g *GeoIPResolver) Lookup(ipStr string) (audit.GeoInfo, bool) {
	if g == nil || g.reader == nil {
		return audit.GeoInfo{}, false
	}
	if audit.PrivateOrInvalidIP(ipStr) {
		return audit.GeoInfo{}, false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return audit.GeoInfo{}, false
	}
	rec, err := g.reader.City(ip)
	if err != nil || rec == nil {
		return audit.GeoInfo{}, false
	}
	info := audit.GeoInfo{
		CountryCode: rec.Country.IsoCode,
		Country:     rec.Country.Names["en"],
		City:        rec.City.Names["en"],
		TimeZone:    rec.Location.TimeZone,
		Latitude:    rec.Location.Latitude,
		Longitude:   rec.Location.Longitude,
	}
	// A record with no usable fields is treated as a miss.
	if info.CountryCode == "" && info.City == "" && info.Latitude == 0 && info.Longitude == 0 {
		return audit.GeoInfo{}, false
	}
	return info, true
}

// Close releases the database file handle. Safe on a nil resolver.
func (g *GeoIPResolver) Close() error {
	if g == nil || g.reader == nil {
		return nil
	}
	return g.reader.Close()
}
