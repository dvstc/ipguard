package ipguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// GeoLookup is the interface for geographic IP lookups. The tgeo.Table
// type satisfies this interface, but any implementation will work.
type GeoLookup interface {
	LookupCountry(ip netip.Addr) string
}

// Logger is a minimal logging interface satisfied by *log.Logger.
type Logger interface {
	Printf(format string, v ...any)
}

// Option configures a Guard during construction.
type Option func(*Guard)

// WithHooks attaches event callbacks to the guard.
func WithHooks(h *Hooks) Option {
	return func(g *Guard) { g.hooks = h }
}

// WithGeo sets the initial GeoLookup implementation.
func WithGeo(gl GeoLookup) Option {
	return func(g *Guard) { g.geo.Store(&gl) }
}

// WithLogger sets the logger for block/ban/summary output.
func WithLogger(l Logger) Option {
	return func(g *Guard) { g.logger = l }
}

// WithClock overrides the time source (useful for testing).
func WithClock(fn func() time.Time) Option {
	return func(g *Guard) { g.now = fn }
}

// WithPermaBans loads a set of permanently banned IPs at construction time.
// These IPs are blocked immediately without expiry. This is used to restore
// permanent bans from consumer-managed persistence on startup.
// Pass WithClock before WithPermaBans if deterministic timestamps are needed.
func WithPermaBans(ips []string) Option {
	return func(g *Guard) {
		now := g.now()
		for _, ip := range ips {
			ip = normalizeIP(ip)
			bannedAt := now
			g.records[ip] = &ipRecord{bannedAt: &bannedAt, permanent: true}
		}
	}
}

type ipRecord struct {
	failures  []time.Time
	bannedAt  *time.Time
	permanent bool
}

type banMemo struct {
	count   int
	lastBan time.Time
}

type blockCounter struct {
	count   int64
	firstAt time.Time
	lastLog time.Time
}

type guardStats struct {
	blacklist   int64
	autoBan     int64
	permaBan    int64
	geo         int64
	newBans     int64
	expiredBans int64
}

// Guard provides IP filtering with whitelist/blacklist, auto-banning,
// and optional geographic filtering. It is safe for concurrent use.
type Guard struct {
	cfg Config

	whitelistNets []net.IPNet
	blacklistNets []net.IPNet

	mu         sync.RWMutex
	records    map[string]*ipRecord
	banHistory map[string]*banMemo

	geo atomic.Pointer[GeoLookup]

	hooks  *Hooks
	logger Logger
	now    func() time.Time

	blockCounters   map[string]*blockCounter
	blockCountersMu sync.Mutex

	stats               guardStats
	summaryMu           sync.Mutex
	lastPermaBanWarning time.Time

	ctx    context.Context
	cancel context.CancelFunc
}

// New creates a Guard with the given configuration and options.
// Returns an error if the config contains invalid CIDRs or
// conflicting geo settings.
func New(cfg Config, opts ...Option) (*Guard, error) {
	ctx, cancel := context.WithCancel(context.Background())
	g := &Guard{
		cfg:           cfg,
		records:       make(map[string]*ipRecord),
		banHistory:    make(map[string]*banMemo),
		blockCounters: make(map[string]*blockCounter),
		now:           time.Now,
		ctx:           ctx,
		cancel:        cancel,
	}

	for _, opt := range opts {
		opt(g)
	}

	if len(cfg.Whitelist) > 0 {
		nets, err := parseCIDRList(cfg.Whitelist)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("whitelist: %w", err)
		}
		g.whitelistNets = nets
	}

	if len(cfg.Blacklist) > 0 {
		nets, err := parseCIDRList(cfg.Blacklist)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("blacklist: %w", err)
		}
		g.blacklistNets = nets
	}

	return g, nil
}

// IsBlocked checks whether an IP address should be blocked.
// Evaluation order: whitelist (bypass) -> blacklist -> permanent_ban -> auto_ban -> geo.
// Returns (blocked, reason) where reason is one of the Reason* constants.
func (g *Guard) IsBlocked(ip string) (bool, string) {
	if g == nil {
		return false, ""
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true, ReasonInvalidIP
	}
	if p4 := parsed.To4(); p4 != nil {
		parsed = p4
		ip = p4.String()
	}

	g.mu.RLock()
	cfg := g.cfg
	wlNets := g.whitelistNets
	blNets := g.blacklistNets

	if matchesAny(parsed, wlNets) {
		g.mu.RUnlock()
		return false, ""
	}

	if matchesAny(parsed, blNets) {
		g.mu.RUnlock()
		return true, ReasonBlacklist
	}

	rec, exists := g.records[ip]
	if exists && rec.bannedAt != nil {
		if rec.permanent {
			g.mu.RUnlock()
			return true, ReasonPermaBan
		}
		if cfg.autoBanEnabled() {
			now := g.now()
			if now.Sub(*rec.bannedAt) < cfg.BanTime {
				g.mu.RUnlock()
				return true, ReasonAutoBan
			}
		}
	}
	g.mu.RUnlock()

	if cfg.geoEnabled() {
		glp := g.geo.Load()
		if glp != nil {
			gl := *glp
			addr, err := netip.ParseAddr(ip)
			if err == nil {
				country := gl.LookupCountry(addr)
				switch cfg.GeoMode {
				case GeoAllow:
					if !containsStr(cfg.GeoCountries, country) {
						return true, ReasonGeo
					}
				case GeoBlock:
					if containsStr(cfg.GeoCountries, country) {
						return true, ReasonGeo
					}
				}
			}
		}
	}

	return false, ""
}

// RecordFailure records an authentication or handshake failure for an IP.
// When failures within FindTime reach MaxRetry, the IP is auto-banned.
func (g *Guard) RecordFailure(ip, transport string) {
	if g == nil {
		return
	}

	ip = normalizeIP(ip)

	now := g.now()
	g.mu.Lock()

	if !g.cfg.autoBanEnabled() {
		g.mu.Unlock()
		return
	}

	rec, exists := g.records[ip]
	if !exists {
		if len(g.records) >= g.cfg.maxTrackedIPs() {
			g.mu.Unlock()
			return
		}
		rec = &ipRecord{}
		g.records[ip] = rec
	}

	if rec.bannedAt != nil {
		g.mu.Unlock()
		return
	}

	cutoff := now.Add(-g.cfg.FindTime)
	var recent []time.Time
	for _, t := range rec.failures {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	rec.failures = recent

	count := len(rec.failures)
	max := g.cfg.MaxRetry

	if g.logger != nil {
		g.logger.Printf("FAILURE ip=%s count=%d/%d transport=%s", ip, count, max, transport)
	}

	var banEvent *BanEvent
	var permaBanEvent *PermaBanEvent
	if count >= max {
		bannedAt := now
		rec.bannedAt = &bannedAt
		rec.failures = nil

		banCount := 0
		if g.cfg.PermaBanAfter > 0 {
			memo := g.banHistory[ip]
			if memo == nil {
				memo = &banMemo{}
				g.banHistory[ip] = memo
			}
			memo.count++
			memo.lastBan = now
			banCount = memo.count

			if banCount >= g.cfg.PermaBanAfter {
				rec.permanent = true
				if g.logger != nil {
					g.logger.Printf("PERMABAN ip=%s ban_count=%d", ip, banCount)
				}
				if g.hooks != nil && g.hooks.OnPermaBanned != nil {
					permaBanEvent = &PermaBanEvent{IP: ip, Transport: transport, BanCount: banCount}
				}
			} else {
				if g.logger != nil {
					g.logger.Printf("BANNED  ip=%s failures=%d duration=%s ban_count=%d/%d", ip, max, g.cfg.BanTime, banCount, g.cfg.PermaBanAfter)
				}
				if g.hooks != nil && g.hooks.OnBanned != nil {
					banEvent = &BanEvent{IP: ip, Transport: transport, Failures: max, BanCount: banCount}
				}
			}
		} else {
			if g.logger != nil {
				g.logger.Printf("BANNED  ip=%s failures=%d duration=%s", ip, max, g.cfg.BanTime)
			}
			if g.hooks != nil && g.hooks.OnBanned != nil {
				banEvent = &BanEvent{IP: ip, Transport: transport, Failures: max}
			}
		}

		g.summaryMu.Lock()
		g.stats.newBans++
		g.summaryMu.Unlock()
	}
	g.mu.Unlock()

	if permaBanEvent != nil {
		permaBanEvent.Country = g.lookupCountry(ip)
		g.hooks.OnPermaBanned(*permaBanEvent)
	} else if banEvent != nil {
		banEvent.Country = g.lookupCountry(ip)
		g.hooks.OnBanned(*banEvent)
	}
}

// SetGeoLookup atomically replaces the geographic lookup implementation.
// This is used for hot-reloading geo data without restarting the guard.
func (g *Guard) SetGeoLookup(gl GeoLookup) {
	if g == nil {
		return
	}
	g.geo.Store(&gl)
}

// Start begins background cleanup and summary goroutines. The goroutines
// run until ctx is cancelled or Close is called.
func (g *Guard) Start(ctx context.Context) {
	if g == nil {
		return
	}
	go g.cleanupLoop(ctx)
	go g.summaryLoop(ctx)
}

// Close cancels background goroutines.
func (g *Guard) Close() {
	if g == nil {
		return
	}
	g.cancel()
}

// Reconfigure applies a new configuration to a running guard.
// Returns an error if the new config is invalid.
func (g *Guard) Reconfigure(cfg Config) error {
	if g == nil {
		return nil
	}

	var wlNets, blNets []net.IPNet
	if len(cfg.Whitelist) > 0 {
		var err error
		wlNets, err = parseCIDRList(cfg.Whitelist)
		if err != nil {
			return fmt.Errorf("whitelist: %w", err)
		}
	}
	if len(cfg.Blacklist) > 0 {
		var err error
		blNets, err = parseCIDRList(cfg.Blacklist)
		if err != nil {
			return fmt.Errorf("blacklist: %w", err)
		}
	}

	g.mu.Lock()
	g.cfg = cfg
	g.whitelistNets = wlNets
	g.blacklistNets = blNets
	g.mu.Unlock()

	return nil
}

// Unban manually removes a ban (temporary or permanent) for the given IP.
// Also clears the IP's ban history. Returns true if the IP was banned.
func (g *Guard) Unban(ip string) bool {
	if g == nil {
		return false
	}
	ip = normalizeIP(ip)

	g.mu.Lock()
	rec, exists := g.records[ip]
	if !exists || rec.bannedAt == nil {
		g.mu.Unlock()
		return false
	}
	delete(g.records, ip)
	delete(g.banHistory, ip)
	g.mu.Unlock()

	if g.hooks != nil && g.hooks.OnUnbanned != nil {
		g.hooks.OnUnbanned(UnbanEvent{IP: ip, Reason: "manual"})
	}
	return true
}

// PermaBan permanently bans an IP. If the IP is already permanently banned,
// this is a no-op (returns true without firing hooks). Works on IPs with
// an active temp ban, an expired ban, or no prior record.
func (g *Guard) PermaBan(ip string) bool {
	if g == nil {
		return false
	}
	ip = normalizeIP(ip)

	g.mu.Lock()
	rec, exists := g.records[ip]
	if exists && rec.permanent {
		g.mu.Unlock()
		return true
	}
	if !exists {
		now := g.now()
		rec = &ipRecord{bannedAt: &now, permanent: true}
		g.records[ip] = rec
	} else {
		if rec.bannedAt == nil {
			now := g.now()
			rec.bannedAt = &now
		}
		rec.permanent = true
	}
	g.mu.Unlock()

	country := g.lookupCountry(ip)
	if g.hooks != nil && g.hooks.OnPermaBanned != nil {
		g.hooks.OnPermaBanned(PermaBanEvent{IP: ip, Country: country})
	}
	return true
}

// WrapListener wraps a net.Listener so that connections from blocked IPs
// are dropped at the TCP level before any protocol handshake.
func (g *Guard) WrapListener(ln net.Listener, transport string) net.Listener {
	if g == nil {
		return ln
	}
	return &guardedListener{Listener: ln, guard: g, transport: transport}
}

func (g *Guard) logBlocked(ip, reason, transport string) {
	if g == nil {
		return
	}

	country := g.lookupCountry(ip)

	key := ip + ":" + reason
	g.blockCountersMu.Lock()
	bc, exists := g.blockCounters[key]
	now := g.now()
	if !exists {
		g.blockCounters[key] = &blockCounter{count: 1, firstAt: now, lastLog: now}
		g.blockCountersMu.Unlock()
		if g.logger != nil {
			g.logger.Printf("BLOCKED ip=%s reason=%s transport=%s country=%s", ip, reason, transport, country)
		}
		g.incrementStat(reason)
		if g.hooks != nil && g.hooks.OnBlocked != nil {
			g.hooks.OnBlocked(BlockEvent{IP: ip, Reason: reason, Transport: transport, Country: country})
		}
		return
	}
	bc.count++
	elapsed := now.Sub(bc.lastLog)
	if elapsed >= 60*time.Second {
		count := bc.count
		bc.count = 0
		bc.lastLog = now
		g.blockCountersMu.Unlock()
		if g.logger != nil {
			g.logger.Printf("BLOCKED ip=%s reason=%s transport=%s country=%s repeated=%d window=60s", ip, reason, transport, country, count)
		}
	} else {
		g.blockCountersMu.Unlock()
	}
	g.incrementStat(reason)
	if g.hooks != nil && g.hooks.OnBlocked != nil {
		g.hooks.OnBlocked(BlockEvent{IP: ip, Reason: reason, Transport: transport, Country: country})
	}
}

func (g *Guard) incrementStat(reason string) {
	g.summaryMu.Lock()
	defer g.summaryMu.Unlock()
	switch reason {
	case ReasonBlacklist:
		g.stats.blacklist++
	case ReasonAutoBan:
		g.stats.autoBan++
	case ReasonPermaBan:
		g.stats.permaBan++
	case ReasonGeo:
		g.stats.geo++
	}
}

func (g *Guard) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-g.ctx.Done():
			return
		case <-ticker.C:
			g.cleanup()
		}
	}
}

func (g *Guard) cleanup() {
	now := g.now()
	g.mu.Lock()

	if !g.cfg.autoBanEnabled() && !g.hasPermaBans() {
		g.mu.Unlock()
		return
	}

	var expiredIPs []string
	permCount := 0
	for ip, rec := range g.records {
		if rec.permanent {
			permCount++
			continue
		}
		if rec.bannedAt != nil {
			if now.Sub(*rec.bannedAt) >= g.cfg.BanTime {
				delete(g.records, ip)
				g.summaryMu.Lock()
				g.stats.expiredBans++
				g.summaryMu.Unlock()
				expiredIPs = append(expiredIPs, ip)
				continue
			}
		}
		cutoff := now.Add(-g.cfg.FindTime)
		var recent []time.Time
		for _, t := range rec.failures {
			if t.After(cutoff) {
				recent = append(recent, t)
			}
		}
		if len(recent) == 0 && rec.bannedAt == nil {
			delete(g.records, ip)
		} else {
			rec.failures = recent
		}
	}

	if g.cfg.RecidivismWindow > 0 {
		for ip, memo := range g.banHistory {
			if now.Sub(memo.lastBan) > g.cfg.RecidivismWindow {
				delete(g.banHistory, ip)
			}
		}
	}

	var topCountry string
	var topCount int
	fireWarning := permCount > 10_000 &&
		g.hooks != nil && g.hooks.OnWarning != nil &&
		now.Sub(g.lastPermaBanWarning) >= 1*time.Hour
	if fireWarning {
		g.lastPermaBanWarning = now
		countryCounts := make(map[string]int)
		for ip, rec := range g.records {
			if rec.permanent {
				c := g.lookupCountryLocked(ip)
				if c != "" {
					countryCounts[c]++
				}
			}
		}
		for c, n := range countryCounts {
			if n > topCount {
				topCountry = c
				topCount = n
			}
		}
	}
	g.mu.Unlock()

	if g.hooks != nil && g.hooks.OnUnbanned != nil {
		for _, ip := range expiredIPs {
			g.hooks.OnUnbanned(UnbanEvent{IP: ip, Reason: "expired"})
		}
	}

	if fireWarning {
		g.hooks.OnWarning("high permanent ban count", map[string]string{
			"count":             strconv.Itoa(permCount),
			"top_country":       topCountry,
			"top_country_count": strconv.Itoa(topCount),
		})
	}

	g.blockCountersMu.Lock()
	for key, bc := range g.blockCounters {
		if now.Sub(bc.lastLog) > 10*time.Minute {
			delete(g.blockCounters, key)
		}
	}
	g.blockCountersMu.Unlock()
}

func (g *Guard) hasPermaBans() bool {
	for _, rec := range g.records {
		if rec.permanent {
			return true
		}
	}
	return false
}

func (g *Guard) lookupCountryLocked(ip string) string {
	glp := g.geo.Load()
	if glp == nil {
		return ""
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	return (*glp).LookupCountry(addr)
}

func (g *Guard) summaryLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-g.ctx.Done():
			return
		case <-ticker.C:
			g.logSummary()
		}
	}
}

func (g *Guard) logSummary() {
	g.summaryMu.Lock()
	s := g.stats
	g.stats = guardStats{}
	g.summaryMu.Unlock()

	total := s.blacklist + s.autoBan + s.permaBan + s.geo
	if total == 0 && s.newBans == 0 && s.expiredBans == 0 {
		return
	}
	if g.logger != nil {
		g.logger.Printf("5m: %d blocked (blacklist=%d geo=%d auto_ban=%d perma_ban=%d), %d new bans, %d expired",
			total, s.blacklist, s.geo, s.autoBan, s.permaBan, s.newBans, s.expiredBans)
	}
}

func normalizeIP(ip string) string {
	if parsed := net.ParseIP(ip); parsed != nil {
		if p4 := parsed.To4(); p4 != nil {
			return p4.String()
		}
	}
	return ip
}

func (g *Guard) lookupCountry(ip string) string {
	glp := g.geo.Load()
	if glp == nil {
		return ""
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	return (*glp).LookupCountry(addr)
}

func parseCIDRList(entries []string) ([]net.IPNet, error) {
	var nets []net.IPNet
	for _, entry := range entries {
		if _, network, err := net.ParseCIDR(entry); err == nil {
			nets = append(nets, *network)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP or CIDR: %q", entry)
		}
		if ip4 := ip.To4(); ip4 != nil {
			nets = append(nets, net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)})
		} else {
			nets = append(nets, net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
		}
	}
	return nets, nil
}

func matchesAny(ip net.IP, nets []net.IPNet) bool {
	for i := range nets {
		if nets[i].Contains(ip) {
			return true
		}
	}
	return false
}

func containsStr(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}
