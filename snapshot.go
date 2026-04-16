package ipguard

import "time"

// BanRecord represents a single active ban entry.
type BanRecord struct {
	IP        string
	BannedAt  time.Time
	ExpiresAt time.Time // zero value for permanent bans
	Failures  int
	Permanent bool
	BanCount  int
	Country   string // derived from current GeoLookup, "" if unavailable
}

// Stats holds cumulative counters for guard activity since the last summary reset.
type Stats struct {
	BlacklistBlocks int64
	AutoBanBlocks   int64
	PermaBanBlocks  int64
	GeoBlocks       int64
	ActiveBans      int // total: temp + permanent
	PermanentBans   int // subset of ActiveBans that are permanent
	BanHistorySize  int // number of IPs in recidivism tracking
}

// Snapshot is a read-only point-in-time view of the guard's state,
// suitable for dashboard integration.
type Snapshot struct {
	Config   Config
	Bans     []BanRecord
	Stats    Stats
	GeoReady bool
}

// Snapshot returns a consistent, read-only view of the guard's current state.
func (g *Guard) Snapshot() Snapshot {
	if g == nil {
		return Snapshot{}
	}

	g.mu.RLock()
	cfg := g.cfg
	permaBans := 0
	var bans []BanRecord
	for ip, rec := range g.records {
		if rec.bannedAt != nil {
			br := BanRecord{
				IP:        ip,
				BannedAt:  *rec.bannedAt,
				Failures:  cfg.MaxRetry,
				Permanent: rec.permanent,
			}
			if rec.permanent {
				permaBans++
			} else {
				br.ExpiresAt = rec.bannedAt.Add(cfg.BanTime)
			}
			if memo, ok := g.banHistory[ip]; ok {
				br.BanCount = memo.count
			}
			bans = append(bans, br)
		}
	}
	historySize := len(g.banHistory)
	g.mu.RUnlock()

	for i := range bans {
		bans[i].Country = g.lookupCountry(bans[i].IP)
	}

	g.summaryMu.Lock()
	s := g.stats
	g.summaryMu.Unlock()

	return Snapshot{
		Config: cfg,
		Bans:   bans,
		Stats: Stats{
			BlacklistBlocks: s.blacklist,
			AutoBanBlocks:   s.autoBan,
			PermaBanBlocks:  s.permaBan,
			GeoBlocks:       s.geo,
			ActiveBans:      len(bans),
			PermanentBans:   permaBans,
			BanHistorySize:  historySize,
		},
		GeoReady: g.geo.Load() != nil,
	}
}
