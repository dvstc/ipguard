package ipguard

import "time"

// GeoMode controls how geographic filtering is applied.
type GeoMode int

const (
	// GeoDisabled means no geographic filtering (zero value).
	GeoDisabled GeoMode = iota
	// GeoAllow only allows connections from listed countries.
	GeoAllow
	// GeoBlock blocks connections from listed countries.
	GeoBlock
)

// Reason constants returned by Guard.IsBlocked.
// Whitelisted IPs return (false, ""), not a reason string,
// because they are allowed rather than blocked.
const (
	ReasonBlacklist = "blacklist"
	ReasonAutoBan   = "auto_ban"
	ReasonPermaBan  = "permanent_ban"
	ReasonGeo       = "geo"
	ReasonInvalidIP = "invalid_ip"
)

// Config controls the behavior of a Guard instance. Zero values disable
// each feature: an empty Config produces a guard that blocks nothing.
//
//   - Whitelist/Blacklist: CIDR notation ("10.0.0.0/8") or bare IPs ("1.2.3.4")
//   - MaxRetry == 0: auto-ban disabled
//   - GeoMode == GeoDisabled: no geographic filtering
type Config struct {
	Whitelist []string // IPs/CIDRs that are never blocked
	Blacklist []string // IPs/CIDRs that are always blocked

	MaxRetry int           // failures within FindTime to trigger a ban (0 = disabled)
	FindTime time.Duration // sliding window for counting failures
	BanTime  time.Duration // how long an auto-ban lasts

	MaxTrackedIPs int // max IPs tracked for auto-ban (0 = default 1,000,000)

	PermaBanAfter    int           // auto-promote to permanent after N bans (0 = disabled)
	RecidivismWindow time.Duration // how long ban history is remembered (0 = forever)

	GeoMode      GeoMode  // GeoDisabled, GeoAllow, or GeoBlock
	GeoCountries []string // ISO 3166-1 alpha-2 country codes
}

const defaultMaxTrackedIPs = 1_000_000

func (c Config) autoBanEnabled() bool {
	return c.MaxRetry > 0
}

func (c Config) maxTrackedIPs() int {
	if c.MaxTrackedIPs > 0 {
		return c.MaxTrackedIPs
	}
	return defaultMaxTrackedIPs
}

func (c Config) geoEnabled() bool {
	return c.GeoMode != GeoDisabled && len(c.GeoCountries) > 0
}
