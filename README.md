# IPGuard

IPGuard is a Go library for TCP-level IP filtering with auto-banning, whitelist/blacklist, and geographic blocking. It drops unwanted connections at the listener level before any protocol handshake, using zero non-stdlib dependencies.

## Installation

```bash
go get github.com/dvstc/ipguard
```

## Packages

- **`ipguard`** (root) — core guard logic: `Config`, `Guard`, `IsBlocked`, `RecordFailure`, `WrapListener`, `Snapshot`, hooks, functional options
- **`ipguard/tgeo`** — TGEO binary format: `Encode`/`Decode`, `Table` (fast IPv4-to-country lookup), `Compile`, `Merge`, `VerifyAndWrite`, `Meta`
- **`ipguard/tgeo/sources`** — geolocation data fetchers: `RIR` (NRO delegation), `BGP` (CAIDA RouteViews), `DBIP` (DB-IP Lite CSV)

## Usage

### Minimal: Blacklist + WrapListener

```go
import "github.com/dvstc/ipguard"

g, err := ipguard.New(ipguard.Config{
    Blacklist: []string{"203.0.113.0/24", "198.51.100.50"},
})
if err != nil {
    log.Fatal(err)
}
defer g.Close()

ln, _ := net.Listen("tcp", ":8080")
guarded := g.WrapListener(ln, "http")
// guarded.Accept() silently drops blacklisted connections
http.Serve(guarded, handler)
```

### Full: Auto-Ban + Geo + Hooks

```go
import (
    "github.com/dvstc/ipguard"
    "github.com/dvstc/ipguard/tgeo"
)

table, _ := tgeo.LoadTable("/data/geoip/iploc.bin")

g, err := ipguard.New(ipguard.Config{
    Whitelist:    []string{"10.0.0.0/8"},
    Blacklist:    []string{"203.0.113.0/24"},
    MaxRetry:     5,
    FindTime:     10 * time.Minute,
    BanTime:      1 * time.Hour,
    GeoMode:      ipguard.GeoBlock,
    GeoCountries: []string{"CN", "RU"},
},
    ipguard.WithGeo(table),
    ipguard.WithHooks(&ipguard.Hooks{
        OnBanned: func(e ipguard.BanEvent) {
            log.Printf("banned %s after %d failures", e.IP, e.Failures)
        },
    }),
    ipguard.WithLogger(log.Default()),
)
if err != nil {
    log.Fatal(err)
}
defer g.Close()
g.Start(context.Background())

// Record failures from your auth layer
g.RecordFailure(clientIP, "https")

// Check blocking without WrapListener
if blocked, reason := g.IsBlocked(clientIP); blocked {
    log.Printf("blocked %s: %s", clientIP, reason)
}

// Hot-swap geo data without restart
newTable, _ := tgeo.LoadTable("/data/geoip/iploc-v2.bin")
g.SetGeoLookup(newTable)
```

### Recidivist Escalation (Permanent Bans)

IPs that are repeatedly banned can be automatically promoted to permanent bans. The consumer owns persistence - IPGuard signals via hooks, and the consumer stores/restores via functional options.

```go
import "github.com/dvstc/ipguard"

// Load previously persisted permanent bans from your database
permaBannedIPs := loadFromDB() // returns []string

g, err := ipguard.New(ipguard.Config{
    MaxRetry:         5,
    FindTime:         10 * time.Minute,
    BanTime:          1 * time.Hour,
    PermaBanAfter:    3,                // promote to permanent after 3 bans
    RecidivismWindow: 24 * time.Hour,   // forget ban history after 24h of good behavior
},
    ipguard.WithPermaBans(permaBannedIPs),
    ipguard.WithGeo(table),
    ipguard.WithHooks(&ipguard.Hooks{
        OnBanned: func(e ipguard.BanEvent) {
            log.Printf("temp ban %s (country=%s, ban #%d)", e.IP, e.Country, e.BanCount)
        },
        OnPermaBanned: func(e ipguard.PermaBanEvent) {
            log.Printf("PERMANENT ban %s (country=%s, ban #%d)", e.IP, e.Country, e.BanCount)
            saveToDB(e.IP) // persist for next restart
        },
        OnUnbanned: func(e ipguard.UnbanEvent) {
            if e.Reason == "manual" {
                removeFromDB(e.IP) // operator cleared the ban
            }
        },
        OnWarning: func(msg string, data map[string]string) {
            // Fired when permanent ban count exceeds 10,000 (rate-limited to 1/hr)
            log.Printf("WARNING: %s — top country: %s (%s IPs)",
                msg, data["top_country"], data["top_country_count"])
        },
    }),
)
if err != nil {
    log.Fatal(err)
}
defer g.Close()
g.Start(context.Background())

// Manual promotion is also supported
g.PermaBan("203.0.113.50")

// Unban clears both the ban and its history
g.Unban("203.0.113.50")

// Snapshot includes permanent ban status and geo enrichment
snap := g.Snapshot()
for _, ban := range snap.Bans {
    fmt.Printf("ip=%s permanent=%v country=%s ban_count=%d\n",
        ban.IP, ban.Permanent, ban.Country, ban.BanCount)
}
fmt.Printf("active=%d permanent=%d history=%d\n",
    snap.Stats.ActiveBans, snap.Stats.PermanentBans, snap.Stats.BanHistorySize)
```

### Producing TGEO Data

```go
import (
    "github.com/dvstc/ipguard/tgeo"
    "github.com/dvstc/ipguard/tgeo/sources"
)

ctx := context.Background()

// Fetch from public data sources
rir := &sources.RIR{}
ranges, asnMap, _ := rir.FetchWithASN(ctx)

bgp := &sources.BGP{ASNMap: asnMap}
bgpRanges, _ := bgp.Fetch(ctx)

dbip := &sources.DBIP{}
dbipRanges, _ := dbip.Fetch(ctx)

// Merge with priority-based conflict resolution
merged, stats := tgeo.Merge(map[string]tgeo.SourceData{
    rir.Name():  {Ranges: ranges, Priority: rir.Priority()},
    bgp.Name():  {Ranges: bgpRanges, Priority: bgp.Priority()},
    dbip.Name(): {Ranges: dbipRanges, Priority: dbip.Priority()},
})

// Compile to TGEO binary
result, _ := tgeo.Compile(merged)

// result.GzipData   — compressed binary, ready to serve/store
// result.Checksum   — "sha256:..." for integrity verification
// result.EntryCount — number of IPv4 ranges
// result.Countries  — number of distinct country codes
```

### Applying a TGEO Update

```go
import "github.com/dvstc/ipguard/tgeo"

// After downloading compressed TGEO data and its checksum:
err := tgeo.VerifyAndWrite(compressed, meta.Checksum, "/data/geoip/iploc.bin")
if err != nil {
    log.Fatal(err)
}

// Load and hot-swap into a running guard
table, _ := tgeo.LoadTable("/data/geoip/iploc.bin")
guard.SetGeoLookup(table)
```

## Design

See [DESIGN.md](DESIGN.md) for the full API surface, TGEO binary format specification, evaluation order, and architectural decisions.

## License

MIT
