package ipguard

import (
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestGuard(t *testing.T, cfg Config, opts ...Option) *Guard {
	t.Helper()
	g, err := New(cfg, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	return g
}

type testGeoTable struct {
	entries   []uint32
	countries []uint16
	codes     []string
}

func (t *testGeoTable) LookupCountry(ip netip.Addr) string {
	if !ip.Is4() {
		return "ZZ"
	}
	b := ip.As4()
	target := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	lo, hi := 0, len(t.entries)-1
	for lo <= hi {
		mid := lo + (hi-lo)/2
		if t.entries[mid] <= target {
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if hi < 0 {
		return "ZZ"
	}
	return t.codes[t.countries[hi]]
}

func newTestGeoLookup() GeoLookup {
	return &testGeoTable{
		entries:   []uint32{0x01000000, 0x02000000, 0x03000000},
		countries: []uint16{0, 1, 2},
		codes:     []string{"US", "CN", "CA"},
	}
}

// --- Config validation tests ---

func TestNew_EmptyConfig(t *testing.T) {
	g := newTestGuard(t, Config{})
	blocked, reason := g.IsBlocked("1.2.3.4")
	if blocked {
		t.Errorf("empty config guard blocked IP, reason=%s", reason)
	}
}

func TestNew_InvalidCIDR(t *testing.T) {
	_, err := New(Config{Whitelist: []string{"not-a-cidr"}})
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNew_ValidCIDR(t *testing.T) {
	g := newTestGuard(t, Config{
		Whitelist: []string{"10.0.0.0/8", "192.168.1.100"},
	})
	if len(g.whitelistNets) != 2 {
		t.Errorf("expected 2 whitelist nets, got %d", len(g.whitelistNets))
	}
}

// --- Whitelist tests ---

func TestWhitelist(t *testing.T) {
	g := newTestGuard(t, Config{
		Whitelist: []string{"10.0.0.0/8", "192.168.1.100"},
		Blacklist: []string{"10.0.0.50"},
	})

	tests := []struct {
		name      string
		ip        string
		wantBlock bool
	}{
		{"ExactMatch", "192.168.1.100", false},
		{"CIDRMatch", "10.5.5.5", false},
		{"WhitelistBeatsBlacklist", "10.0.0.50", false},
		{"NotWhitelisted", "203.0.113.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, _ := g.IsBlocked(tt.ip)
			if blocked != tt.wantBlock {
				t.Errorf("IsBlocked(%s) = %v, want %v", tt.ip, blocked, tt.wantBlock)
			}
		})
	}
}

// --- Blacklist tests ---

func TestBlacklist(t *testing.T) {
	g := newTestGuard(t, Config{
		Blacklist: []string{"203.0.113.50", "198.51.100.0/24"},
	})

	tests := []struct {
		name       string
		ip         string
		wantBlock  bool
		wantReason string
	}{
		{"ExactMatch", "203.0.113.50", true, ReasonBlacklist},
		{"CIDRMatch", "198.51.100.99", true, ReasonBlacklist},
		{"NotBlacklisted", "8.8.8.8", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := g.IsBlocked(tt.ip)
			if blocked != tt.wantBlock {
				t.Errorf("IsBlocked(%s) = %v, want %v", tt.ip, blocked, tt.wantBlock)
			}
			if reason != tt.wantReason {
				t.Errorf("IsBlocked(%s) reason = %q, want %q", tt.ip, reason, tt.wantReason)
			}
		})
	}
}

// --- Auto-ban tests ---

func TestAutoBan_BelowThreshold(t *testing.T) {
	g := newTestGuard(t, Config{
		MaxRetry: 5, FindTime: 5 * time.Minute, BanTime: 1 * time.Hour,
	})
	for i := 0; i < 4; i++ {
		g.RecordFailure("1.2.3.4", "ssh")
	}
	blocked, _ := g.IsBlocked("1.2.3.4")
	if blocked {
		t.Error("should not be banned below threshold")
	}
}

func TestAutoBan_ExactThreshold(t *testing.T) {
	g := newTestGuard(t, Config{
		MaxRetry: 5, FindTime: 5 * time.Minute, BanTime: 1 * time.Hour,
	})
	for i := 0; i < 5; i++ {
		g.RecordFailure("1.2.3.4", "ssh")
	}
	blocked, reason := g.IsBlocked("1.2.3.4")
	if !blocked || reason != ReasonAutoBan {
		t.Errorf("expected blocked by auto_ban, got blocked=%v reason=%s", blocked, reason)
	}
}

func TestAutoBan_BanExpiry(t *testing.T) {
	g := newTestGuard(t, Config{
		MaxRetry: 3, FindTime: 5 * time.Minute, BanTime: 50 * time.Millisecond,
	})
	for i := 0; i < 3; i++ {
		g.RecordFailure("1.2.3.4", "ssh")
	}
	blocked, _ := g.IsBlocked("1.2.3.4")
	if !blocked {
		t.Fatal("should be banned")
	}
	time.Sleep(100 * time.Millisecond)
	blocked, _ = g.IsBlocked("1.2.3.4")
	if blocked {
		t.Error("ban should have expired")
	}
}

func TestAutoBan_FindTimeWindow(t *testing.T) {
	g := newTestGuard(t, Config{
		MaxRetry: 5, FindTime: 50 * time.Millisecond, BanTime: 1 * time.Hour,
	})

	for i := 0; i < 3; i++ {
		g.RecordFailure("1.2.3.4", "ssh")
	}
	time.Sleep(100 * time.Millisecond)
	for i := 0; i < 2; i++ {
		g.RecordFailure("1.2.3.4", "ssh")
	}
	blocked, _ := g.IsBlocked("1.2.3.4")
	if blocked {
		t.Error("should not be banned -- earlier failures expired outside find_time window")
	}
}

func TestAutoBan_Cleanup(t *testing.T) {
	g := newTestGuard(t, Config{
		MaxRetry: 2, FindTime: 50 * time.Millisecond, BanTime: 50 * time.Millisecond,
	})
	for i := 0; i < 100; i++ {
		ip := net.IPv4(10, 0, 0, byte(i)).String()
		g.RecordFailure(ip, "ssh")
		g.RecordFailure(ip, "ssh")
	}
	time.Sleep(100 * time.Millisecond)
	g.cleanup()
	g.mu.RLock()
	remaining := len(g.records)
	g.mu.RUnlock()
	if remaining != 0 {
		t.Errorf("expected 0 records after cleanup, got %d", remaining)
	}
}

func TestAutoBan_Disabled(t *testing.T) {
	g := newTestGuard(t, Config{})
	for i := 0; i < 100; i++ {
		g.RecordFailure("1.2.3.4", "ssh")
	}
	blocked, _ := g.IsBlocked("1.2.3.4")
	if blocked {
		t.Error("auto_ban disabled should not block")
	}
}

// --- Geo filtering tests ---

func TestGeo_AllowlistMode_Allowed(t *testing.T) {
	g := newTestGuard(t, Config{
		GeoMode: GeoAllow, GeoCountries: []string{"US", "CA"},
	}, WithGeo(newTestGeoLookup()))

	blocked, _ := g.IsBlocked("1.0.0.1")
	if blocked {
		t.Error("US should be allowed by allowlist")
	}
}

func TestGeo_AllowlistMode_Denied(t *testing.T) {
	g := newTestGuard(t, Config{
		GeoMode: GeoAllow, GeoCountries: []string{"US", "CA"},
	}, WithGeo(newTestGeoLookup()))

	blocked, reason := g.IsBlocked("2.0.0.1")
	if !blocked || reason != ReasonGeo {
		t.Errorf("CN should be denied, got blocked=%v reason=%s", blocked, reason)
	}
}

func TestGeo_BlocklistMode_Blocked(t *testing.T) {
	g := newTestGuard(t, Config{
		GeoMode: GeoBlock, GeoCountries: []string{"CN"},
	}, WithGeo(newTestGeoLookup()))

	blocked, reason := g.IsBlocked("2.0.0.1")
	if !blocked || reason != ReasonGeo {
		t.Errorf("CN should be blocked, got blocked=%v reason=%s", blocked, reason)
	}
}

func TestGeo_BlocklistMode_Allowed(t *testing.T) {
	g := newTestGuard(t, Config{
		GeoMode: GeoBlock, GeoCountries: []string{"CN"},
	}, WithGeo(newTestGeoLookup()))

	blocked, _ := g.IsBlocked("1.0.0.1")
	if blocked {
		t.Error("US should not be blocked by CN blocklist")
	}
}

func TestGeo_ZZ_AllowlistMode(t *testing.T) {
	g := newTestGuard(t, Config{
		GeoMode: GeoAllow, GeoCountries: []string{"US"},
	}, WithGeo(newTestGeoLookup()))

	blocked, reason := g.IsBlocked("250.0.0.1")
	if !blocked || reason != ReasonGeo {
		t.Errorf("unallocated (ZZ) should be blocked by US allowlist, got blocked=%v reason=%s", blocked, reason)
	}
}

func TestGeo_ZZ_BlocklistMode(t *testing.T) {
	g := newTestGuard(t, Config{
		GeoMode: GeoBlock, GeoCountries: []string{"CN"},
	}, WithGeo(newTestGeoLookup()))

	blocked, _ := g.IsBlocked("250.0.0.1")
	if blocked {
		t.Error("unallocated (ZZ) should not be blocked by CN blocklist")
	}
}

func TestGeo_NoData(t *testing.T) {
	g := newTestGuard(t, Config{
		GeoMode: GeoAllow, GeoCountries: []string{"US"},
	})

	blocked, _ := g.IsBlocked("1.2.3.4")
	if blocked {
		t.Error("no geo data loaded should not block")
	}
}

func TestGeo_Disabled(t *testing.T) {
	g := newTestGuard(t, Config{}, WithGeo(newTestGeoLookup()))

	blocked, _ := g.IsBlocked("1.0.0.1")
	if blocked {
		t.Error("geo disabled should not block")
	}
}

func TestGeo_WhitelistBypassesGeo(t *testing.T) {
	g := newTestGuard(t, Config{
		Whitelist:    []string{"2.0.0.1"},
		GeoMode:      GeoAllow,
		GeoCountries: []string{"US"},
	}, WithGeo(newTestGeoLookup()))

	blocked, _ := g.IsBlocked("2.0.0.1")
	if blocked {
		t.Error("whitelisted IP should bypass geo check")
	}
}

// --- Evaluation order test ---

func TestEvaluationOrder(t *testing.T) {
	g := newTestGuard(t, Config{
		Whitelist:    []string{"10.0.0.1"},
		Blacklist:    []string{"10.0.0.2", "5.0.0.1"},
		MaxRetry:     2,
		FindTime:     5 * time.Minute,
		BanTime:      1 * time.Hour,
		GeoMode:      GeoBlock,
		GeoCountries: []string{"CN"},
	}, WithGeo(newTestGeoLookup()))

	g.RecordFailure("5.0.0.1", "ssh")
	g.RecordFailure("5.0.0.1", "ssh")

	tests := []struct {
		name       string
		ip         string
		wantBlock  bool
		wantReason string
	}{
		{"WhitelistedAlways", "10.0.0.1", false, ""},
		{"BlacklistBeforeAutoBan", "10.0.0.2", true, ReasonBlacklist},
		{"BlacklistTakesPrecedence", "5.0.0.1", true, ReasonBlacklist},
		{"GeoBlocked", "2.0.0.1", true, ReasonGeo},
		{"Allowed", "1.0.0.1", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := g.IsBlocked(tt.ip)
			if blocked != tt.wantBlock {
				t.Errorf("IsBlocked(%s) = %v, want %v", tt.ip, blocked, tt.wantBlock)
			}
			if reason != tt.wantReason {
				t.Errorf("IsBlocked(%s) reason = %q, want %q", tt.ip, reason, tt.wantReason)
			}
		})
	}
}

// --- guardedListener tests ---

func TestGuardedListener_BlockedIPClosed(t *testing.T) {
	g := newTestGuard(t, Config{
		Blacklist: []string{"127.0.0.1"},
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	guarded := g.WrapListener(ln, "test")

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	go func() {
		time.Sleep(100 * time.Millisecond)
		ln.Close()
	}()

	_, acceptErr := guarded.Accept()
	if acceptErr == nil {
		t.Error("expected accept error after listener closed")
	}

	buf := make([]byte, 1)
	_, readErr := conn.Read(buf)
	if readErr == nil {
		t.Error("expected blocked connection to be closed")
	}
}

func TestGuardedListener_AllowedIPPassesThrough(t *testing.T) {
	g := newTestGuard(t, Config{
		Whitelist: []string{"127.0.0.1"},
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	guarded := g.WrapListener(ln, "test")

	go func() {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		conn.Write([]byte("hello"))
		conn.Close()
	}()

	accepted, err := guarded.Accept()
	if err != nil {
		t.Fatalf("expected accepted connection, got error: %v", err)
	}
	defer accepted.Close()

	buf := make([]byte, 5)
	n, _ := accepted.Read(buf)
	if string(buf[:n]) != "hello" {
		t.Errorf("expected 'hello', got %q", string(buf[:n]))
	}
}

func TestGuardedListener_AcceptError(t *testing.T) {
	g := newTestGuard(t, Config{
		Whitelist: []string{"127.0.0.1"},
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	guarded := g.WrapListener(ln, "test")
	ln.Close()

	_, acceptErr := guarded.Accept()
	if acceptErr == nil {
		t.Error("expected accept error after listener closed")
	}
}

// --- Nil receiver safety tests ---

func TestNilReceiver(t *testing.T) {
	var g *Guard

	blocked, reason := g.IsBlocked("1.2.3.4")
	if blocked {
		t.Errorf("nil guard should not block, reason=%s", reason)
	}

	g.RecordFailure("1.2.3.4", "ssh")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	wrapped := g.WrapListener(ln, "test")
	if wrapped != ln {
		t.Error("nil guard WrapListener should return listener unchanged")
	}

	g.Start(nil)
	g.Close()
}

// --- WrapListener nil-safety ---

func TestWrapListener_EmptyConfig(t *testing.T) {
	g := newTestGuard(t, Config{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	wrapped := g.WrapListener(ln, "test")
	if wrapped == ln {
		t.Error("even empty config should wrap (guard is non-nil)")
	}
}

// --- Auto-ban hook test ---

func TestAutoBan_HookCalled(t *testing.T) {
	var banEvents []BanEvent
	g := newTestGuard(t, Config{
		MaxRetry: 2, FindTime: 5 * time.Minute, BanTime: 1 * time.Hour,
	}, WithHooks(&Hooks{
		OnBanned: func(e BanEvent) { banEvents = append(banEvents, e) },
	}))

	g.RecordFailure("5.5.5.5", "ssh")
	g.RecordFailure("5.5.5.5", "ssh")

	if len(banEvents) != 1 {
		t.Fatalf("expected 1 ban event, got %d", len(banEvents))
	}
	if banEvents[0].IP != "5.5.5.5" {
		t.Errorf("ban event IP: %s", banEvents[0].IP)
	}
}

// --- RecordFailure on already-banned IP ---

func TestAutoBan_RecordFailureOnBannedIP(t *testing.T) {
	g := newTestGuard(t, Config{
		MaxRetry: 2, FindTime: 5 * time.Minute, BanTime: 1 * time.Hour,
	})

	g.RecordFailure("1.1.1.1", "ssh")
	g.RecordFailure("1.1.1.1", "ssh")

	blocked, _ := g.IsBlocked("1.1.1.1")
	if !blocked {
		t.Fatal("should be banned")
	}

	g.RecordFailure("1.1.1.1", "ssh")
	g.RecordFailure("1.1.1.1", "ssh")

	blocked, reason := g.IsBlocked("1.1.1.1")
	if !blocked || reason != ReasonAutoBan {
		t.Errorf("should still be banned, got blocked=%v reason=%s", blocked, reason)
	}
}

// --- Concurrent access test ---

func TestConcurrentAccess(t *testing.T) {
	g := newTestGuard(t, Config{
		Whitelist:    []string{"10.0.0.1"},
		Blacklist:    []string{"10.0.0.2"},
		MaxRetry:     5,
		FindTime:     5 * time.Minute,
		BanTime:      1 * time.Hour,
		GeoMode:      GeoBlock,
		GeoCountries: []string{"CN"},
	}, WithGeo(newTestGeoLookup()))

	var done atomic.Int64
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				g.IsBlocked("1.0.0.1")
				g.IsBlocked("2.0.0.1")
				g.IsBlocked("10.0.0.1")
				g.IsBlocked("10.0.0.2")
				g.RecordFailure("3.3.3.3", "ssh")
			}
			done.Add(1)
		}()
	}
	for done.Load() < 10 {
		time.Sleep(10 * time.Millisecond)
	}
}

// --- SetGeoLookup hot-swap test ---

func TestSetGeoLookup(t *testing.T) {
	g := newTestGuard(t, Config{
		GeoMode: GeoBlock, GeoCountries: []string{"CN"},
	})

	tableA := &testGeoTable{
		entries:   []uint32{0x02000000},
		countries: []uint16{0},
		codes:     []string{"US"},
	}
	g.SetGeoLookup(tableA)

	blocked, _ := g.IsBlocked("2.0.0.1")
	if blocked {
		t.Error("2.0.0.1 = US in table A, should not be blocked")
	}

	tableB := &testGeoTable{
		entries:   []uint32{0x02000000},
		countries: []uint16{0},
		codes:     []string{"CN"},
	}
	g.SetGeoLookup(tableB)

	blocked, reason := g.IsBlocked("2.0.0.1")
	if !blocked || reason != ReasonGeo {
		t.Errorf("2.0.0.1 = CN in table B, expected geo block, got blocked=%v reason=%s", blocked, reason)
	}
}

// --- Reconfigure test ---

func TestReconfigure(t *testing.T) {
	g := newTestGuard(t, Config{
		Blacklist: []string{"1.2.3.4"},
	})

	blocked, _ := g.IsBlocked("1.2.3.4")
	if !blocked {
		t.Fatal("should be blocked before reconfigure")
	}

	err := g.Reconfigure(Config{
		Blacklist: []string{"5.6.7.8"},
	})
	if err != nil {
		t.Fatal(err)
	}

	blocked, _ = g.IsBlocked("1.2.3.4")
	if blocked {
		t.Error("1.2.3.4 should no longer be blocked")
	}
	blocked, _ = g.IsBlocked("5.6.7.8")
	if !blocked {
		t.Error("5.6.7.8 should now be blocked")
	}
}

func TestReconfigure_InvalidCIDR(t *testing.T) {
	g := newTestGuard(t, Config{})

	err := g.Reconfigure(Config{Blacklist: []string{"not-a-cidr"}})
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

// --- Unban test ---

func TestUnban(t *testing.T) {
	var unbanEvents []UnbanEvent
	g := newTestGuard(t, Config{
		MaxRetry: 2, FindTime: 5 * time.Minute, BanTime: 1 * time.Hour,
	}, WithHooks(&Hooks{
		OnUnbanned: func(e UnbanEvent) { unbanEvents = append(unbanEvents, e) },
	}))

	g.RecordFailure("1.2.3.4", "ssh")
	g.RecordFailure("1.2.3.4", "ssh")

	blocked, _ := g.IsBlocked("1.2.3.4")
	if !blocked {
		t.Fatal("should be banned")
	}

	result := g.Unban("1.2.3.4")
	if !result {
		t.Error("Unban should return true")
	}

	blocked, _ = g.IsBlocked("1.2.3.4")
	if blocked {
		t.Error("should be unbanned")
	}

	if len(unbanEvents) != 1 {
		t.Fatalf("expected 1 unban event, got %d", len(unbanEvents))
	}
	if unbanEvents[0].Reason != "manual" {
		t.Errorf("expected manual reason, got %s", unbanEvents[0].Reason)
	}
}

func TestUnban_NotBanned(t *testing.T) {
	g := newTestGuard(t, Config{
		MaxRetry: 5, FindTime: 5 * time.Minute, BanTime: 1 * time.Hour,
	})

	result := g.Unban("1.2.3.4")
	if result {
		t.Error("Unban of non-banned IP should return false")
	}
}

// --- Snapshot test ---

func TestSnapshot(t *testing.T) {
	g := newTestGuard(t, Config{
		MaxRetry:     2,
		FindTime:     5 * time.Minute,
		BanTime:      1 * time.Hour,
		GeoMode:      GeoBlock,
		GeoCountries: []string{"CN"},
	}, WithGeo(newTestGeoLookup()))

	g.RecordFailure("1.1.1.1", "ssh")
	g.RecordFailure("1.1.1.1", "ssh")

	snap := g.Snapshot()
	if len(snap.Bans) != 1 {
		t.Fatalf("expected 1 ban, got %d", len(snap.Bans))
	}
	if snap.Bans[0].IP != "1.1.1.1" {
		t.Errorf("ban IP: %s", snap.Bans[0].IP)
	}
	if snap.Stats.ActiveBans != 1 {
		t.Errorf("active bans: %d", snap.Stats.ActiveBans)
	}
	if !snap.GeoReady {
		t.Error("geo should be ready")
	}
}

func TestSnapshot_NilGuard(t *testing.T) {
	var g *Guard
	snap := g.Snapshot()
	if len(snap.Bans) != 0 {
		t.Error("nil guard snapshot should have no bans")
	}
}

// --- Bug reproduction tests ---

func TestBug_H2_HookDeadlock_RecordFailure(t *testing.T) {
	done := make(chan struct{})
	go func() {
		var g *Guard
		g, _ = New(Config{
			MaxRetry: 2, FindTime: 5 * time.Minute, BanTime: 1 * time.Hour,
		}, WithHooks(&Hooks{
			OnBanned: func(e BanEvent) {
				// This calls g.mu.RLock() while RecordFailure holds g.mu.Lock()
				g.Snapshot()
			},
		}))
		defer g.Close()
		g.RecordFailure("1.2.3.4", "ssh")
		g.RecordFailure("1.2.3.4", "ssh")
		close(done)
	}()
	select {
	case <-done:
		t.Log("no deadlock detected (bug is fixed)")
	case <-time.After(3 * time.Second):
		t.Fatal("DEADLOCK CONFIRMED (H2): OnBanned hook calling g.Snapshot() deadlocks because RecordFailure holds g.mu.Lock()")
	}
}

func TestBug_H3_HookDeadlock_Cleanup(t *testing.T) {
	done := make(chan struct{})
	go func() {
		var g *Guard
		g, _ = New(Config{
			MaxRetry: 2, FindTime: 5 * time.Minute, BanTime: 1 * time.Millisecond,
		}, WithHooks(&Hooks{
			OnUnbanned: func(e UnbanEvent) {
				// This calls g.mu.RLock() while cleanup holds g.mu.Lock()
				g.IsBlocked("1.2.3.4")
			},
		}))
		defer g.Close()
		g.RecordFailure("1.2.3.4", "ssh")
		g.RecordFailure("1.2.3.4", "ssh")
		time.Sleep(50 * time.Millisecond)
		g.cleanup()
		close(done)
	}()
	select {
	case <-done:
		t.Log("no deadlock detected (bug is fixed)")
	case <-time.After(3 * time.Second):
		t.Fatal("DEADLOCK CONFIRMED (H3): OnUnbanned hook calling g.IsBlocked() deadlocks because cleanup holds g.mu.Lock()")
	}
}

func TestBug_H4_WhitelistReturnsEmptyReason(t *testing.T) {
	g := newTestGuard(t, Config{
		Whitelist: []string{"10.0.0.0/8"},
		Blacklist: []string{"10.0.0.1"},
	})
	blocked, reason := g.IsBlocked("10.0.0.1")
	if blocked {
		t.Fatal("whitelisted IP should not be blocked")
	}
	if reason != "" {
		t.Errorf("whitelisted IPs should return empty reason, got %q", reason)
	}
}

// --- Permanent ban / recidivism tests ---

func triggerBan(g *Guard, ip string) {
	max := g.cfg.MaxRetry
	for i := 0; i < max; i++ {
		g.RecordFailure(ip, "ssh")
	}
}

func TestPermaBan_AutoEscalation(t *testing.T) {
	now := time.Now()
	g := newTestGuard(t, Config{
		MaxRetry:      2,
		FindTime:      5 * time.Minute,
		BanTime:       50 * time.Millisecond,
		PermaBanAfter: 3,
	}, WithClock(func() time.Time { return now }))

	var permaBanEvents []PermaBanEvent
	var banEvents []BanEvent
	g.hooks = &Hooks{
		OnBanned:      func(e BanEvent) { banEvents = append(banEvents, e) },
		OnPermaBanned: func(e PermaBanEvent) { permaBanEvents = append(permaBanEvents, e) },
	}

	for cycle := 1; cycle <= 3; cycle++ {
		triggerBan(g, "1.2.3.4")
		if cycle < 3 {
			now = now.Add(time.Second)
			g.cleanup()
			now = now.Add(time.Second)
		}
	}

	if len(banEvents) != 2 {
		t.Errorf("expected 2 temp ban events, got %d", len(banEvents))
	}
	if len(permaBanEvents) != 1 {
		t.Fatalf("expected 1 permaban event, got %d", len(permaBanEvents))
	}
	if permaBanEvents[0].IP != "1.2.3.4" {
		t.Errorf("permaban event IP: %s", permaBanEvents[0].IP)
	}
	if permaBanEvents[0].BanCount != 3 {
		t.Errorf("permaban event BanCount: %d, want 3", permaBanEvents[0].BanCount)
	}

	blocked, reason := g.IsBlocked("1.2.3.4")
	if !blocked || reason != ReasonPermaBan {
		t.Errorf("expected permanent_ban, got blocked=%v reason=%s", blocked, reason)
	}
}

func TestPermaBan_SkipsExpiry(t *testing.T) {
	now := time.Now()
	g := newTestGuard(t, Config{
		MaxRetry:      2,
		FindTime:      5 * time.Minute,
		BanTime:       50 * time.Millisecond,
		PermaBanAfter: 1,
	}, WithClock(func() time.Time { return now }))

	triggerBan(g, "1.2.3.4")

	now = now.Add(time.Hour)
	g.cleanup()

	blocked, reason := g.IsBlocked("1.2.3.4")
	if !blocked || reason != ReasonPermaBan {
		t.Errorf("permanent ban should survive cleanup+expiry, got blocked=%v reason=%s", blocked, reason)
	}
}

func TestPermaBan_WorksWithoutAutoBan(t *testing.T) {
	g := newTestGuard(t, Config{},
		WithPermaBans([]string{"10.0.0.1", "10.0.0.2"}))

	blocked, reason := g.IsBlocked("10.0.0.1")
	if !blocked || reason != ReasonPermaBan {
		t.Errorf("WithPermaBans IP should be blocked, got blocked=%v reason=%s", blocked, reason)
	}

	blocked, _ = g.IsBlocked("10.0.0.3")
	if blocked {
		t.Error("non-permabanned IP should not be blocked")
	}
}

func TestPermaBan_ManualPromotion(t *testing.T) {
	var events []PermaBanEvent
	g := newTestGuard(t, Config{}, WithHooks(&Hooks{
		OnPermaBanned: func(e PermaBanEvent) { events = append(events, e) },
	}))

	result := g.PermaBan("5.5.5.5")
	if !result {
		t.Error("PermaBan should return true")
	}

	blocked, reason := g.IsBlocked("5.5.5.5")
	if !blocked || reason != ReasonPermaBan {
		t.Errorf("manually permabanned IP should be blocked, got blocked=%v reason=%s", blocked, reason)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 permaban event, got %d", len(events))
	}
	if events[0].IP != "5.5.5.5" {
		t.Errorf("permaban event IP: %s", events[0].IP)
	}
}

func TestPermaBan_ManualOnActiveBan(t *testing.T) {
	g := newTestGuard(t, Config{
		MaxRetry: 2, FindTime: 5 * time.Minute, BanTime: 1 * time.Hour,
	})
	triggerBan(g, "1.2.3.4")

	blocked, reason := g.IsBlocked("1.2.3.4")
	if !blocked || reason != ReasonAutoBan {
		t.Fatalf("should be temp banned first, got reason=%s", reason)
	}

	g.PermaBan("1.2.3.4")

	blocked, reason = g.IsBlocked("1.2.3.4")
	if !blocked || reason != ReasonPermaBan {
		t.Errorf("should now be permanently banned, got reason=%s", reason)
	}
}

func TestPermaBan_Idempotent(t *testing.T) {
	var events []PermaBanEvent
	g := newTestGuard(t, Config{}, WithHooks(&Hooks{
		OnPermaBanned: func(e PermaBanEvent) { events = append(events, e) },
	}))

	g.PermaBan("1.2.3.4")
	g.PermaBan("1.2.3.4")

	if len(events) != 1 {
		t.Errorf("expected 1 permaban event (idempotent), got %d", len(events))
	}
}

func TestPermaBan_IPNormalization(t *testing.T) {
	g := newTestGuard(t, Config{})

	g.PermaBan("::ffff:1.2.3.4")

	blocked, reason := g.IsBlocked("1.2.3.4")
	if !blocked || reason != ReasonPermaBan {
		t.Errorf("IPv4-mapped IPv6 permaban should match IPv4 lookup, got blocked=%v reason=%s", blocked, reason)
	}
}

func TestUnban_Permanent(t *testing.T) {
	var unbanEvents []UnbanEvent
	g := newTestGuard(t, Config{}, WithHooks(&Hooks{
		OnUnbanned: func(e UnbanEvent) { unbanEvents = append(unbanEvents, e) },
	}))

	g.PermaBan("1.2.3.4")

	blocked, _ := g.IsBlocked("1.2.3.4")
	if !blocked {
		t.Fatal("should be permabanned")
	}

	result := g.Unban("1.2.3.4")
	if !result {
		t.Error("Unban should return true for permabanned IP")
	}

	blocked, _ = g.IsBlocked("1.2.3.4")
	if blocked {
		t.Error("should be unbanned after Unban")
	}

	if len(unbanEvents) != 1 || unbanEvents[0].Reason != "manual" {
		t.Errorf("unexpected unban events: %v", unbanEvents)
	}

	g.mu.RLock()
	_, historyExists := g.banHistory["1.2.3.4"]
	g.mu.RUnlock()
	if historyExists {
		t.Error("Unban should also clear banHistory")
	}
}

func TestUnban_IPNormalization(t *testing.T) {
	g := newTestGuard(t, Config{
		MaxRetry: 2, FindTime: 5 * time.Minute, BanTime: 1 * time.Hour,
	})
	triggerBan(g, "1.2.3.4")

	result := g.Unban("::ffff:1.2.3.4")
	if !result {
		t.Error("Unban with IPv4-mapped IPv6 should find the record")
	}

	blocked, _ := g.IsBlocked("1.2.3.4")
	if blocked {
		t.Error("should be unbanned")
	}
}

func TestWithPermaBans_Startup(t *testing.T) {
	g := newTestGuard(t, Config{},
		WithPermaBans([]string{"1.1.1.1", "::ffff:2.2.2.2"}))

	blocked, reason := g.IsBlocked("1.1.1.1")
	if !blocked || reason != ReasonPermaBan {
		t.Errorf("1.1.1.1 should be permabanned, got blocked=%v reason=%s", blocked, reason)
	}

	blocked, reason = g.IsBlocked("2.2.2.2")
	if !blocked || reason != ReasonPermaBan {
		t.Errorf("2.2.2.2 (via normalized ::ffff:) should be permabanned, got blocked=%v reason=%s", blocked, reason)
	}
}

func TestWithPermaBans_NoHooksFired(t *testing.T) {
	hookCalled := false
	g := newTestGuard(t, Config{},
		WithHooks(&Hooks{
			OnPermaBanned: func(e PermaBanEvent) { hookCalled = true },
		}),
		WithPermaBans([]string{"1.1.1.1"}))

	_ = g
	if hookCalled {
		t.Error("WithPermaBans should not fire OnPermaBanned hooks")
	}
}

func TestRecidivismWindow(t *testing.T) {
	now := time.Now()
	g := newTestGuard(t, Config{
		MaxRetry:         2,
		FindTime:         5 * time.Minute,
		BanTime:          50 * time.Millisecond,
		PermaBanAfter:    3,
		RecidivismWindow: time.Hour,
	}, WithClock(func() time.Time { return now }))

	triggerBan(g, "1.2.3.4")
	now = now.Add(time.Second)
	g.cleanup()

	g.mu.RLock()
	memo := g.banHistory["1.2.3.4"]
	g.mu.RUnlock()
	if memo == nil || memo.count != 1 {
		t.Fatal("banHistory should have count=1 after first ban")
	}

	now = now.Add(2 * time.Hour)
	g.cleanup()

	g.mu.RLock()
	memo = g.banHistory["1.2.3.4"]
	g.mu.RUnlock()
	if memo != nil {
		t.Error("banHistory should be pruned after RecidivismWindow")
	}

	now = now.Add(time.Second)
	triggerBan(g, "1.2.3.4")

	g.mu.RLock()
	memo = g.banHistory["1.2.3.4"]
	g.mu.RUnlock()
	if memo == nil || memo.count != 1 {
		t.Errorf("IP should start fresh after history expired, got count=%v", memo)
	}
}

func TestPermaBanAfter_Disabled(t *testing.T) {
	g := newTestGuard(t, Config{
		MaxRetry: 2, FindTime: 5 * time.Minute, BanTime: 1 * time.Hour,
	})

	triggerBan(g, "1.2.3.4")

	g.mu.RLock()
	histLen := len(g.banHistory)
	g.mu.RUnlock()
	if histLen != 0 {
		t.Errorf("banHistory should be empty when PermaBanAfter=0, got %d entries", histLen)
	}

	blocked, reason := g.IsBlocked("1.2.3.4")
	if !blocked || reason != ReasonAutoBan {
		t.Errorf("should be temp banned, got blocked=%v reason=%s", blocked, reason)
	}
}

func TestBanHistory_SurvivesRecordDeletion(t *testing.T) {
	now := time.Now()
	g := newTestGuard(t, Config{
		MaxRetry:      2,
		FindTime:      5 * time.Minute,
		BanTime:       50 * time.Millisecond,
		PermaBanAfter: 3,
	}, WithClock(func() time.Time { return now }))

	triggerBan(g, "1.2.3.4")
	now = now.Add(time.Second)
	g.cleanup()

	g.mu.RLock()
	_, recordExists := g.records["1.2.3.4"]
	memo := g.banHistory["1.2.3.4"]
	g.mu.RUnlock()

	if recordExists {
		t.Error("record should be deleted after ban expiry")
	}
	if memo == nil || memo.count != 1 {
		t.Error("banHistory should survive record deletion")
	}

	now = now.Add(time.Second)
	triggerBan(g, "1.2.3.4")

	g.mu.RLock()
	memo = g.banHistory["1.2.3.4"]
	g.mu.RUnlock()
	if memo == nil || memo.count != 2 {
		t.Errorf("banHistory count should be 2, got %v", memo)
	}
}

func TestReconfigure_PreservesPermaBans(t *testing.T) {
	g := newTestGuard(t, Config{
		MaxRetry: 2, FindTime: 5 * time.Minute, BanTime: 1 * time.Hour,
	}, WithPermaBans([]string{"1.2.3.4"}))

	err := g.Reconfigure(Config{
		Blacklist: []string{"5.6.7.8"},
		MaxRetry:  3, FindTime: 5 * time.Minute, BanTime: 2 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	blocked, reason := g.IsBlocked("1.2.3.4")
	if !blocked || reason != ReasonPermaBan {
		t.Errorf("permaban should survive reconfigure, got blocked=%v reason=%s", blocked, reason)
	}
}

func TestReconfigure_PermaBanAfterLowered(t *testing.T) {
	now := time.Now()
	g := newTestGuard(t, Config{
		MaxRetry:      2,
		FindTime:      5 * time.Minute,
		BanTime:       50 * time.Millisecond,
		PermaBanAfter: 5,
	}, WithClock(func() time.Time { return now }))

	for i := 0; i < 3; i++ {
		triggerBan(g, "1.2.3.4")
		now = now.Add(time.Second)
		g.cleanup()
		now = now.Add(time.Second)
	}

	err := g.Reconfigure(Config{
		MaxRetry:      2,
		FindTime:      5 * time.Minute,
		BanTime:       50 * time.Millisecond,
		PermaBanAfter: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	triggerBan(g, "1.2.3.4")

	blocked, reason := g.IsBlocked("1.2.3.4")
	if !blocked || reason != ReasonPermaBan {
		t.Errorf("lowered threshold should promote on next ban, got blocked=%v reason=%s", blocked, reason)
	}
}

func TestReconfigure_PermaBanAfterDisabled(t *testing.T) {
	now := time.Now()
	g := newTestGuard(t, Config{
		MaxRetry:      2,
		FindTime:      5 * time.Minute,
		BanTime:       50 * time.Millisecond,
		PermaBanAfter: 1,
	}, WithClock(func() time.Time { return now }))

	triggerBan(g, "1.2.3.4")

	blocked, reason := g.IsBlocked("1.2.3.4")
	if !blocked || reason != ReasonPermaBan {
		t.Fatalf("should be permabanned, got blocked=%v reason=%s", blocked, reason)
	}

	err := g.Reconfigure(Config{
		MaxRetry: 2,
		FindTime: 5 * time.Minute,
		BanTime:  50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	blocked, reason = g.IsBlocked("1.2.3.4")
	if !blocked || reason != ReasonPermaBan {
		t.Errorf("existing permaban should survive PermaBanAfter being disabled, got blocked=%v reason=%s", blocked, reason)
	}
}

func TestSnapshot_PermaBanFields(t *testing.T) {
	g := newTestGuard(t, Config{
		MaxRetry:      2,
		FindTime:      5 * time.Minute,
		BanTime:       1 * time.Hour,
		PermaBanAfter: 1,
	}, WithGeo(newTestGeoLookup()))

	triggerBan(g, "1.0.0.1")

	snap := g.Snapshot()
	if len(snap.Bans) != 1 {
		t.Fatalf("expected 1 ban, got %d", len(snap.Bans))
	}
	br := snap.Bans[0]
	if !br.Permanent {
		t.Error("BanRecord should be permanent")
	}
	if br.BanCount != 1 {
		t.Errorf("BanCount: %d, want 1", br.BanCount)
	}
	if !br.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt should be zero for permanent bans, got %v", br.ExpiresAt)
	}
	if br.Country != "US" {
		t.Errorf("Country: %q, want US", br.Country)
	}
	if snap.Stats.PermanentBans != 1 {
		t.Errorf("PermanentBans: %d, want 1", snap.Stats.PermanentBans)
	}
	if snap.Stats.BanHistorySize != 1 {
		t.Errorf("BanHistorySize: %d, want 1", snap.Stats.BanHistorySize)
	}
}

func TestSnapshot_GeoHotSwap(t *testing.T) {
	g := newTestGuard(t, Config{}, WithPermaBans([]string{"2.0.0.1"}))

	tableA := &testGeoTable{
		entries:   []uint32{0x02000000},
		countries: []uint16{0},
		codes:     []string{"US"},
	}
	g.SetGeoLookup(tableA)

	snap := g.Snapshot()
	if len(snap.Bans) != 1 || snap.Bans[0].Country != "US" {
		t.Errorf("expected Country=US, got %q", snap.Bans[0].Country)
	}

	tableB := &testGeoTable{
		entries:   []uint32{0x02000000},
		countries: []uint16{0},
		codes:     []string{"CN"},
	}
	g.SetGeoLookup(tableB)

	snap = g.Snapshot()
	if snap.Bans[0].Country != "CN" {
		t.Errorf("after hot-swap, expected Country=CN, got %q", snap.Bans[0].Country)
	}
}

func TestGeoEnrichment_BanEvent(t *testing.T) {
	var events []BanEvent
	g := newTestGuard(t, Config{
		MaxRetry: 2, FindTime: 5 * time.Minute, BanTime: 1 * time.Hour,
	}, WithGeo(newTestGeoLookup()), WithHooks(&Hooks{
		OnBanned: func(e BanEvent) { events = append(events, e) },
	}))

	triggerBan(g, "1.0.0.1")

	if len(events) != 1 {
		t.Fatalf("expected 1 ban event, got %d", len(events))
	}
	if events[0].Country != "US" {
		t.Errorf("BanEvent.Country: %q, want US", events[0].Country)
	}
}

func TestGeoEnrichment_BanEventNoGeo(t *testing.T) {
	var events []BanEvent
	g := newTestGuard(t, Config{
		MaxRetry: 2, FindTime: 5 * time.Minute, BanTime: 1 * time.Hour,
	}, WithHooks(&Hooks{
		OnBanned: func(e BanEvent) { events = append(events, e) },
	}))

	triggerBan(g, "1.0.0.1")

	if len(events) != 1 {
		t.Fatalf("expected 1 ban event, got %d", len(events))
	}
	if events[0].Country != "" {
		t.Errorf("BanEvent.Country should be empty without geo, got %q", events[0].Country)
	}
}

func TestGeoEnrichment_PermaBanEvent(t *testing.T) {
	var events []PermaBanEvent
	g := newTestGuard(t, Config{
		MaxRetry:      2,
		FindTime:      5 * time.Minute,
		BanTime:       1 * time.Hour,
		PermaBanAfter: 1,
	}, WithGeo(newTestGeoLookup()), WithHooks(&Hooks{
		OnPermaBanned: func(e PermaBanEvent) { events = append(events, e) },
	}))

	triggerBan(g, "2.0.0.1")

	if len(events) != 1 {
		t.Fatalf("expected 1 permaban event, got %d", len(events))
	}
	if events[0].Country != "CN" {
		t.Errorf("PermaBanEvent.Country: %q, want CN", events[0].Country)
	}
}

func TestHighPermaBanWarning(t *testing.T) {
	now := time.Now()
	g := newTestGuard(t, Config{}, WithClock(func() time.Time { return now }))

	var warnings []map[string]string
	g.hooks = &Hooks{
		OnWarning: func(msg string, data map[string]string) {
			warnings = append(warnings, data)
		},
	}

	for i := 0; i < 10_001; i++ {
		ip := net.IPv4(byte(10+i/(256*256)), byte((i/(256))%256), byte(i%256), 1).String()
		bannedAt := now
		g.records[ip] = &ipRecord{bannedAt: &bannedAt, permanent: true}
	}

	g.cleanup()

	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(warnings))
	}
	if warnings[0]["count"] != "10001" {
		t.Errorf("warning count: %s", warnings[0]["count"])
	}

	g.cleanup()
	if len(warnings) != 1 {
		t.Error("warning should be rate-limited to once per hour")
	}

	now = now.Add(2 * time.Hour)
	g.cleanup()
	if len(warnings) != 2 {
		t.Error("warning should fire again after rate limit window")
	}
}

func TestPermaBan_StatsTracking(t *testing.T) {
	g := newTestGuard(t, Config{}, WithPermaBans([]string{"1.2.3.4"}))

	g.IsBlocked("1.2.3.4")
	g.logBlocked("1.2.3.4", ReasonPermaBan, "test")

	g.summaryMu.Lock()
	count := g.stats.permaBan
	g.summaryMu.Unlock()
	if count != 1 {
		t.Errorf("permaBan stat: %d, want 1", count)
	}
}

func TestPermaBan_NilReceiver(t *testing.T) {
	var g *Guard
	result := g.PermaBan("1.2.3.4")
	if result {
		t.Error("nil guard PermaBan should return false")
	}
}

func TestCleanup_BackwardsCompat(t *testing.T) {
	g := newTestGuard(t, Config{
		MaxRetry: 2, FindTime: 50 * time.Millisecond, BanTime: 50 * time.Millisecond,
	})
	for i := 0; i < 100; i++ {
		ip := net.IPv4(10, 0, 0, byte(i)).String()
		g.RecordFailure(ip, "ssh")
		g.RecordFailure(ip, "ssh")
	}
	time.Sleep(100 * time.Millisecond)
	g.cleanup()
	g.mu.RLock()
	remaining := len(g.records)
	histSize := len(g.banHistory)
	g.mu.RUnlock()
	if remaining != 0 {
		t.Errorf("expected 0 records after cleanup (PermaBanAfter=0), got %d", remaining)
	}
	if histSize != 0 {
		t.Errorf("expected 0 banHistory entries (PermaBanAfter=0), got %d", histSize)
	}
}

func TestBanEvent_BanCount(t *testing.T) {
	now := time.Now()
	var events []BanEvent
	g := newTestGuard(t, Config{
		MaxRetry:      2,
		FindTime:      5 * time.Minute,
		BanTime:       50 * time.Millisecond,
		PermaBanAfter: 5,
	}, WithClock(func() time.Time { return now }), WithHooks(&Hooks{
		OnBanned: func(e BanEvent) { events = append(events, e) },
	}))

	triggerBan(g, "1.2.3.4")
	now = now.Add(time.Second)
	g.cleanup()
	now = now.Add(time.Second)
	triggerBan(g, "1.2.3.4")

	if len(events) != 2 {
		t.Fatalf("expected 2 ban events, got %d", len(events))
	}
	if events[0].BanCount != 1 {
		t.Errorf("first ban BanCount: %d, want 1", events[0].BanCount)
	}
	if events[1].BanCount != 2 {
		t.Errorf("second ban BanCount: %d, want 2", events[1].BanCount)
	}
}
