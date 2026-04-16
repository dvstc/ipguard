package sources

import (
	"context"

	"github.com/dvstc/ipguard/tgeo"
)

// Source is the interface that geolocation data providers implement
// to supply IP-to-country ranges for TGEO compilation.
type Source interface {
	Name() string
	Priority() int // higher value = preferred on conflict
	Fetch(ctx context.Context) ([]tgeo.IPRange, error)
}

// RIRSource extends Source with additional ASN-to-country data
// needed by the BGP source to map autonomous system numbers to countries.
type RIRSource interface {
	Source
	FetchWithASN(ctx context.Context) ([]tgeo.IPRange, ASNCountryMap, error)
}

// ASNCountryMap maps autonomous system numbers to their registered country codes.
type ASNCountryMap map[uint32]string
