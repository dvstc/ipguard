# IPGuard

IPGuard is a Go library for IP filtering with auto-banning, whitelist/blacklist, geographic blocking, HTTP middleware with trusted proxy support, and PROXY protocol v1/v2 decoding. It filters unwanted traffic at both the TCP listener and HTTP handler levels, extracting real client IPs behind reverse proxies and load balancers, using zero non-stdlib dependencies.

## Installation

```bash
go get github.com/dvstc/ipguard
```

## Packages

- **`ipguard`** (root) — core guard logic: `Config`, `Guard`, `IsBlocked`, `RecordFailure`, `WrapListener`, `WrapHandler`, `WrapErrorLog`, `WrapListenerProxyProto`, `Snapshot`, hooks, functional options
- **`ipguard/tgeo`** — TGEO binary format: `Encode`/`Decode`, `Table`/`LoadTableFromBytes` (fast IPv4-to-country lookup), `Compile`, `Merge`, `VerifyAndWrite`, `Meta`
- **`ipguard/tgeo/fetch`** — curated table loader: `fetch.Table(ctx)` downloads a pre-compiled TGEO file with HTTP conditional request caching
- **`ipguard/tgeo/sources`** — geolocation data fetchers: `RIR` (NRO delegation), `BGP` (CAIDA RouteViews), `DBIP` (DB-IP Lite CSV), with built-in HTTP conditional request caching

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

### HTTP Middleware

`WrapHandler` wraps an `http.Handler` with IP filtering. It extracts the real client IP from reverse proxy headers with trusted proxy validation, blocks requests from banned/blacklisted IPs with 403, and optionally records failures based on HTTP response status codes.

**Direct (no proxy):**

```go
guarded, err := guard.WrapHandler(handler)
if err != nil {
    log.Fatal(err)
}
http.ListenAndServe(":8080", guarded)
```

**Behind HAProxy (HTTP mode):**

HAProxy in HTTP mode (`mode http`) adds `X-Forwarded-For` by default. Trust the HAProxy IP(s) and read the header:

```go
guarded, err := guard.WrapHandler(handler,
    ipguard.WithTrustedProxies("10.0.0.1/32"),  // HAProxy frontend IP
    ipguard.WithIPHeader("X-Forwarded-For"),
    ipguard.WithFailureCodes(401, 404),
)
```

Corresponding HAProxy config:

```
frontend http_front
    bind *:80
    option forwardfor
    default_backend app

backend app
    server go_app 10.0.0.2:8080 check
```

**Behind nginx:**

```go
guarded, err := guard.WrapHandler(handler,
    ipguard.WithTrustedProxies("10.0.0.0/8", "172.16.0.0/12"),
    ipguard.WithIPHeader("X-Forwarded-For"),
)
```

**Behind Cloudflare:**

```go
guarded, err := guard.WrapHandler(handler,
    ipguard.WithTrustedProxies(
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ),
    ipguard.WithIPHeader("CF-Connecting-IP"),
    ipguard.WithFailureCodes(401, 404),
)
```

**With auto-failure recording:**

When `WithFailureCodes` is set, the middleware automatically calls `RecordFailure` when the inner handler responds with one of the configured status codes. This lets IPGuard auto-ban IPs that repeatedly trigger 401/404/etc. without any manual wiring.

### TLS Error Interception

`WrapErrorLog` intercepts TLS handshake failures from `http.Server.ErrorLog` and feeds them into the auto-ban pipeline. This catches scanners that probe with bad TLS connections (unsupported versions, missing SNI, garbage bytes) before any HTTP request is formed -- the gap between `WrapListener` and `WrapHandler`.

**Minimal (forwards to guard's logger):**

```go
srv := &http.Server{
    Handler:  handler,
    ErrorLog: guard.WrapErrorLog(nil),
}
```

**With fallback (preserves log level):**

```go
errorLog := slog.NewLogLogger(logger.Handler(), slog.LevelError)
srv := &http.Server{
    Handler:  handler,
    ErrorLog: guard.WrapErrorLog(errorLog),
}
```

The `fallback` logger receives all messages (TLS and non-TLS) at the consumer's chosen level. TLS handshake errors additionally trigger `RecordFailure`, so the same IP hitting `MaxRetry` bad handshakes within `FindTime` gets auto-banned and `WrapListener` drops all future TCP connections.

### PROXY Protocol (TCP)

`WrapListenerProxyProto` wraps a `net.Listener` to decode PROXY protocol v1/v2 headers from trusted load balancers. Use this for non-HTTP services (SSH, SMTP, game servers, etc.) behind L4 load balancers that speak PROXY protocol.

**Behind HAProxy (TCP mode with PROXY protocol):**

HAProxy in TCP mode (`mode tcp`) can send PROXY protocol headers to preserve the real client IP. This is the standard approach for non-HTTP services like SSH, SMTP, or game servers behind a load balancer.

```go
ln, _ := net.Listen("tcp", ":2222")
guarded, err := guard.WrapListenerProxyProto(ln, "ssh",
    []string{"10.0.0.1/32"},  // HAProxy frontend IP
)
if err != nil {
    log.Fatal(err)
}
for {
    conn, err := guarded.Accept()
    if err != nil {
        break
    }
    // conn.RemoteAddr() returns the real client IP from the PROXY header
    go handleSSH(conn)
}
```

Corresponding HAProxy config:

```
frontend ssh_front
    bind *:22
    mode tcp
    default_backend ssh_back

backend ssh_back
    mode tcp
    server go_app 10.0.0.2:2222 send-proxy-v2 check
```

Supports auto-detection of v1 (text) and v2 (binary) PROXY headers. Use `send-proxy` in HAProxy for v1 or `send-proxy-v2` for v2. Connections from non-trusted sources pass through without PROXY header parsing, using `RemoteAddr` directly for filtering.

### Geo Data: Curated (Recommended)

The simplest way to get geo blocking working. Downloads a pre-compiled TGEO table from the [ipguard-geofeed](https://github.com/dvstc/ipguard-geofeed) service (a Cloudflare Worker backed by R2). Uses HTTP conditional requests so subsequent calls only transfer data when the upstream file has changed.

```go
import "github.com/dvstc/ipguard/tgeo/fetch"

table, err := fetch.Table(ctx)
if err != nil {
    log.Fatal(err)
}
guard.SetGeoLookup(table)
```

To check the current feed version without downloading, query the metadata endpoint:

```
GET https://your-r2-domain.example.com/meta.json

{
  "version": "1",
  "published_at": "2026-04-17T12:00:00Z",
  "checksum": "sha256:...",
  "size": 4823041,
  "download_url": "https://your-r2-domain.example.com/latest.tgeo.gz",
  "sources": ["rir-nro", "bgp-caida", "dbip-lite"],
  "license": "CC-BY-4.0"
}
```

The response matches the `tgeo.Meta` struct.

### Geo Data: Custom Sources (Advanced)

For consumers who want to use their own sources, customize the pipeline, or add proprietary data. All source fetchers include HTTP conditional request caching by default (sends `If-None-Match` / `If-Modified-Since` headers to upstream servers).

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
