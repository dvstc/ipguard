package ipguard

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// --- Construction validation ---

func TestWrapHandler_IPHeaderWithoutTrustedProxies(t *testing.T) {
	g := newTestGuard(t, Config{})
	_, err := g.WrapHandler(http.NotFoundHandler(), WithIPHeader("X-Forwarded-For"))
	if err == nil {
		t.Fatal("expected error for WithIPHeader without WithTrustedProxies")
	}
}

func TestWrapHandler_InvalidTrustedProxy(t *testing.T) {
	g := newTestGuard(t, Config{})
	_, err := g.WrapHandler(http.NotFoundHandler(),
		WithTrustedProxies("not-a-cidr"),
		WithIPHeader("X-Forwarded-For"),
	)
	if err == nil {
		t.Fatal("expected error for invalid CIDR in WithTrustedProxies")
	}
}

func TestWrapHandler_ExtractorAloneValid(t *testing.T) {
	g := newTestGuard(t, Config{})
	_, err := g.WrapHandler(http.NotFoundHandler(),
		WithIPExtractor(func(r *http.Request) string { return "1.2.3.4" }),
	)
	if err != nil {
		t.Fatalf("WithIPExtractor alone should be valid: %v", err)
	}
}

func TestWrapHandler_NoOptionsValid(t *testing.T) {
	g := newTestGuard(t, Config{})
	_, err := g.WrapHandler(http.NotFoundHandler())
	if err != nil {
		t.Fatalf("no options should be valid: %v", err)
	}
}

func TestWrapHandler_NilGuard(t *testing.T) {
	var g *Guard
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	h, err := g.WrapHandler(inner)
	if err != nil {
		t.Fatalf("nil guard should not error: %v", err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Code != 200 {
		t.Errorf("nil guard should pass through, got %d", rr.Code)
	}
}

// --- IP extraction ---

func TestWrapHandler_DefaultRemoteAddr(t *testing.T) {
	var gotIP string
	g := newTestGuard(t, Config{Blacklist: []string{"9.9.9.9"}},
		WithHooks(&Hooks{OnBlocked: func(e BlockEvent) { gotIP = e.IP }}))

	h, _ := g.WrapHandler(http.NotFoundHandler())
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "9.9.9.9:12345"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if rr.Code != 403 {
		t.Errorf("expected 403, got %d", rr.Code)
	}
	if gotIP != "9.9.9.9" {
		t.Errorf("expected IP 9.9.9.9, got %s", gotIP)
	}
}

func TestWrapHandler_RemoteAddrWithoutPort(t *testing.T) {
	g := newTestGuard(t, Config{Blacklist: []string{"9.9.9.9"}})
	h, _ := g.WrapHandler(http.NotFoundHandler())
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "9.9.9.9"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != 403 {
		t.Errorf("expected 403 for bare IP RemoteAddr, got %d", rr.Code)
	}
}

func TestWrapHandler_XFFRightToLeftWalk(t *testing.T) {
	var gotIP string
	g := newTestGuard(t, Config{Blacklist: []string{"203.0.113.50"}},
		WithHooks(&Hooks{OnBlocked: func(e BlockEvent) { gotIP = e.IP }}))

	h, _ := g.WrapHandler(http.NotFoundHandler(),
		WithTrustedProxies("10.0.0.0/8"),
		WithIPHeader("X-Forwarded-For"),
	)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "spoofed.garbage, 203.0.113.50, 10.0.0.5")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if rr.Code != 403 {
		t.Errorf("expected 403, got %d", rr.Code)
	}
	if gotIP != "203.0.113.50" {
		t.Errorf("expected 203.0.113.50 from XFF walk, got %s", gotIP)
	}
}

func TestWrapHandler_XFFSpoofRejected(t *testing.T) {
	g := newTestGuard(t, Config{Blacklist: []string{"1.1.1.1"}})
	h, _ := g.WrapHandler(http.NotFoundHandler(),
		WithTrustedProxies("10.0.0.0/8"),
		WithIPHeader("X-Forwarded-For"),
	)

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "5.5.5.5:9999"
	r.Header.Set("X-Forwarded-For", "1.1.1.1")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if rr.Code == 403 {
		t.Error("untrusted RemoteAddr should not trust XFF; should use 5.5.5.5 instead")
	}
}

func TestWrapHandler_XFFAllTrusted_FallbackToRemoteAddr(t *testing.T) {
	g := newTestGuard(t, Config{Blacklist: []string{"10.0.0.1"}})
	h, _ := g.WrapHandler(http.NotFoundHandler(),
		WithTrustedProxies("10.0.0.0/8"),
		WithIPHeader("X-Forwarded-For"),
	)

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "10.0.0.5, 10.0.0.6")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if rr.Code != 403 {
		t.Error("all XFF entries trusted, should fall back to RemoteAddr 10.0.0.1 which is blacklisted")
	}
}

func TestWrapHandler_SingleValueHeader_Trusted(t *testing.T) {
	var gotIP string
	g := newTestGuard(t, Config{Blacklist: []string{"203.0.113.1"}},
		WithHooks(&Hooks{OnBlocked: func(e BlockEvent) { gotIP = e.IP }}))

	h, _ := g.WrapHandler(http.NotFoundHandler(),
		WithTrustedProxies("10.0.0.0/8"),
		WithIPHeader("CF-Connecting-IP"),
	)

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("CF-Connecting-IP", "203.0.113.1")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if rr.Code != 403 || gotIP != "203.0.113.1" {
		t.Errorf("expected blocked by 203.0.113.1, got code=%d ip=%s", rr.Code, gotIP)
	}
}

func TestWrapHandler_SingleValueHeader_NotTrusted(t *testing.T) {
	g := newTestGuard(t, Config{Blacklist: []string{"203.0.113.1"}})
	h, _ := g.WrapHandler(http.NotFoundHandler(),
		WithTrustedProxies("10.0.0.0/8"),
		WithIPHeader("CF-Connecting-IP"),
	)

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "5.5.5.5:1234"
	r.Header.Set("CF-Connecting-IP", "203.0.113.1")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if rr.Code == 403 {
		t.Error("non-trusted RemoteAddr should ignore CF-Connecting-IP; 5.5.5.5 is not blacklisted")
	}
}

func TestWrapHandler_CustomExtractor(t *testing.T) {
	g := newTestGuard(t, Config{Blacklist: []string{"99.99.99.99"}})
	h, _ := g.WrapHandler(http.NotFoundHandler(),
		WithIPExtractor(func(r *http.Request) string { return "99.99.99.99" }),
	)

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if rr.Code != 403 {
		t.Error("custom extractor should return 99.99.99.99 which is blacklisted")
	}
}

// --- Blocking and hooks ---

func TestWrapHandler_BlockedResponse(t *testing.T) {
	g := newTestGuard(t, Config{Blacklist: []string{"9.9.9.9"}})
	h, _ := g.WrapHandler(http.NotFoundHandler())
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "9.9.9.9:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if rr.Code != 403 {
		t.Errorf("expected 403, got %d", rr.Code)
	}
	if reason := rr.Header().Get("X-Blocked-Reason"); reason != ReasonBlacklist {
		t.Errorf("expected X-Blocked-Reason=%s, got %s", ReasonBlacklist, reason)
	}
}

func TestWrapHandler_AllowedPassesThrough(t *testing.T) {
	g := newTestGuard(t, Config{})
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	h, _ := g.WrapHandler(inner)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if rr.Body.String() != "ok" {
		t.Errorf("expected body 'ok', got %q", rr.Body.String())
	}
}

func TestWrapHandler_OnBlockedHookFires(t *testing.T) {
	var events []BlockEvent
	g := newTestGuard(t, Config{Blacklist: []string{"9.9.9.9"}},
		WithHooks(&Hooks{OnBlocked: func(e BlockEvent) { events = append(events, e) }}))

	h, _ := g.WrapHandler(http.NotFoundHandler())
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "9.9.9.9:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if len(events) != 1 {
		t.Fatalf("expected 1 block event, got %d", len(events))
	}
	if events[0].IP != "9.9.9.9" || events[0].Reason != ReasonBlacklist {
		t.Errorf("unexpected event: %+v", events[0])
	}
}

func TestWrapHandler_BlockEventCountry(t *testing.T) {
	var events []BlockEvent
	g := newTestGuard(t, Config{
		GeoMode: GeoBlock, GeoCountries: []string{"CN"},
	}, WithGeo(newTestGeoLookup()),
		WithHooks(&Hooks{OnBlocked: func(e BlockEvent) { events = append(events, e) }}))

	h, _ := g.WrapHandler(http.NotFoundHandler())
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "2.0.0.1:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if rr.Code != 403 {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
	if len(events) != 1 || events[0].Country != "CN" {
		t.Errorf("expected Country=CN, got %+v", events)
	}
}

// --- Failure recording ---

func TestWrapHandler_FailureCodes_Records(t *testing.T) {
	g := newTestGuard(t, Config{
		MaxRetry: 2, FindTime: 5 * 60e9, BanTime: 3600e9,
	})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	})
	h, _ := g.WrapHandler(inner, WithFailureCodes(401, 404))

	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "5.5.5.5:1234"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		if rr.Code != 401 {
			t.Errorf("request %d: expected 401, got %d", i, rr.Code)
		}
	}

	blocked, reason := g.IsBlocked("5.5.5.5")
	if !blocked || reason != ReasonAutoBan {
		t.Errorf("expected auto_ban after 2 failures, got blocked=%v reason=%s", blocked, reason)
	}
}

func TestWrapHandler_FailureCodes_200NoRecord(t *testing.T) {
	g := newTestGuard(t, Config{
		MaxRetry: 1, FindTime: 5 * 60e9, BanTime: 3600e9,
	})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	h, _ := g.WrapHandler(inner, WithFailureCodes(401, 404))

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "5.5.5.5:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	blocked, _ := g.IsBlocked("5.5.5.5")
	if blocked {
		t.Error("200 response should not trigger RecordFailure")
	}
}

func TestWrapHandler_FailureCodes_BlockedSkipsHandler(t *testing.T) {
	handlerCalled := false
	g := newTestGuard(t, Config{Blacklist: []string{"9.9.9.9"}})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(404)
	})
	h, _ := g.WrapHandler(inner, WithFailureCodes(404))

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "9.9.9.9:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if rr.Code != 403 {
		t.Errorf("expected 403, got %d", rr.Code)
	}
	if handlerCalled {
		t.Error("handler should not be called for blocked IP")
	}
}

func TestWrapHandler_NoFailureCodes_NoOverhead(t *testing.T) {
	g := newTestGuard(t, Config{})
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := w.(*statusRecorder); ok {
			panic("should not wrap with statusRecorder when no failure codes")
		}
		w.WriteHeader(200)
	})
	h, _ := g.WrapHandler(inner)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
}

// --- Transport ---

func TestWrapHandler_TransportAutoDetect_HTTP(t *testing.T) {
	var events []BlockEvent
	g := newTestGuard(t, Config{Blacklist: []string{"9.9.9.9"}},
		WithHooks(&Hooks{OnBlocked: func(e BlockEvent) { events = append(events, e) }}))
	h, _ := g.WrapHandler(http.NotFoundHandler())

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "9.9.9.9:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if len(events) != 1 || events[0].Transport != "http" {
		t.Errorf("expected transport=http, got %+v", events)
	}
}

func TestWrapHandler_TransportAutoDetect_HTTPS(t *testing.T) {
	var events []BlockEvent
	g := newTestGuard(t, Config{Blacklist: []string{"9.9.9.9"}},
		WithHooks(&Hooks{OnBlocked: func(e BlockEvent) { events = append(events, e) }}))
	h, _ := g.WrapHandler(http.NotFoundHandler())

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "9.9.9.9:1234"
	r.TLS = &tls.ConnectionState{}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if len(events) != 1 || events[0].Transport != "https" {
		t.Errorf("expected transport=https, got %+v", events)
	}
}

func TestWrapHandler_TransportOverride(t *testing.T) {
	var events []BlockEvent
	g := newTestGuard(t, Config{Blacklist: []string{"9.9.9.9"}},
		WithHooks(&Hooks{OnBlocked: func(e BlockEvent) { events = append(events, e) }}))
	h, _ := g.WrapHandler(http.NotFoundHandler(), WithTransport("grpc"))

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "9.9.9.9:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if len(events) != 1 || events[0].Transport != "grpc" {
		t.Errorf("expected transport=grpc, got %+v", events)
	}
}

// --- Edge cases ---

func TestWrapHandler_StatusRecorder_Hijacker(t *testing.T) {
	sr := &statusRecorder{ResponseWriter: httptest.NewRecorder(), status: 200}
	_, _, err := sr.Hijack()
	if err == nil {
		t.Error("httptest.ResponseRecorder does not support Hijack, should error")
	}
}

func TestWrapHandler_StatusRecorder_Flusher(t *testing.T) {
	sr := &statusRecorder{ResponseWriter: httptest.NewRecorder(), status: 200}
	sr.Flush()
}

func TestWrapHandler_StatusRecorder_ImplicitWriteHeader(t *testing.T) {
	g := newTestGuard(t, Config{
		MaxRetry: 1, FindTime: 5 * 60e9, BanTime: 3600e9,
	})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("no explicit WriteHeader"))
	})
	h, _ := g.WrapHandler(inner, WithFailureCodes(200))

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "5.5.5.5:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	blocked, _ := g.IsBlocked("5.5.5.5")
	if !blocked {
		t.Error("implicit 200 with WithFailureCodes(200) should trigger RecordFailure")
	}
}

// --- Helpers for proxy tests with real listener ---

type hijackableRecorder struct {
	*httptest.ResponseRecorder
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, fmt.Errorf("not a real connection")
}
