package sources

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func defaultTestLogger() *slog.Logger { return slog.Default() }

func TestMemoryCache_GetPut(t *testing.T) {
	c := NewMemoryCache()

	entry, err := c.Get("https://example.com/data")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if entry != nil {
		t.Fatal("expected nil for missing entry")
	}

	want := &CacheEntry{
		URL:          "https://example.com/data",
		Data:         []byte("hello"),
		ETag:         `"abc123"`,
		LastModified: "Thu, 01 Jan 2026 00:00:00 GMT",
	}
	if err := c.Put(want); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := c.Get("https://example.com/data")
	if err != nil {
		t.Fatalf("Get after Put: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil entry after Put")
	}
	if string(got.Data) != "hello" {
		t.Errorf("Data = %q, want %q", got.Data, "hello")
	}
	if got.ETag != `"abc123"` {
		t.Errorf("ETag = %q, want %q", got.ETag, `"abc123"`)
	}
}

func TestMemoryCache_ConcurrentAccess(t *testing.T) {
	c := NewMemoryCache()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = c.Put(&CacheEntry{URL: "u", Data: []byte("x")})
			_, _ = c.Get("u")
		}()
	}
	wg.Wait()
}

func TestConditionalRequest_304(t *testing.T) {
	etag := `"v1"`
	body := []byte("original-data")

	reqCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount++
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Write(body)
	}))
	defer ts.Close()

	cache := NewMemoryCache()
	ctx := context.Background()

	// First request: 200 with data.
	data, err := httpGet(ctx, ts.Client(), ts.URL+"/data", cache, defaultTestLogger())
	if err != nil {
		t.Fatalf("first httpGet: %v", err)
	}
	if string(data) != "original-data" {
		t.Errorf("first fetch: got %q, want %q", data, "original-data")
	}

	// Second request: should send If-None-Match and get 304.
	data2, err := httpGet(ctx, ts.Client(), ts.URL+"/data", cache, defaultTestLogger())
	if err != nil {
		t.Fatalf("second httpGet: %v", err)
	}
	if string(data2) != "original-data" {
		t.Errorf("cached fetch: got %q, want %q", data2, "original-data")
	}
	if reqCount != 2 {
		t.Errorf("expected 2 requests, got %d", reqCount)
	}
}

func TestConditionalRequest_200UpdatesCache(t *testing.T) {
	version := 1
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		etag := `"v` + string(rune('0'+version)) + `"`
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Write([]byte("data-v" + string(rune('0'+version))))
	}))
	defer ts.Close()

	cache := NewMemoryCache()
	ctx := context.Background()

	data, _ := httpGet(ctx, ts.Client(), ts.URL, cache, defaultTestLogger())
	if string(data) != "data-v1" {
		t.Fatalf("v1: got %q", data)
	}

	// Upstream changes.
	version = 2
	data, _ = httpGet(ctx, ts.Client(), ts.URL, cache, defaultTestLogger())
	if string(data) != "data-v2" {
		t.Fatalf("v2: got %q", data)
	}

	// Confirm cached v2 is returned on 304.
	data, _ = httpGet(ctx, ts.Client(), ts.URL, cache, defaultTestLogger())
	if string(data) != "data-v2" {
		t.Fatalf("v2 cached: got %q", data)
	}
}

func TestConditionalRequest_NilCache(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
			t.Error("conditional headers sent with nil cache")
		}
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	data, err := httpGet(context.Background(), ts.Client(), ts.URL, nil, defaultTestLogger())
	if err != nil {
		t.Fatalf("httpGet: %v", err)
	}
	if string(data) != "ok" {
		t.Errorf("got %q, want %q", data, "ok")
	}
}

func TestConditionalRequest_EmptyETagNotSent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "" {
			t.Error("If-None-Match sent for empty ETag")
		}
		if r.Header.Get("If-Modified-Since") != "" {
			t.Error("If-Modified-Since sent for empty LastModified")
		}
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	cache := NewMemoryCache()
	// Pre-populate cache with empty ETag/LastModified.
	_ = cache.Put(&CacheEntry{URL: ts.URL, Data: []byte("cached"), ETag: "", LastModified: ""})

	ctx := context.Background()
	data, err := httpGet(ctx, ts.Client(), ts.URL, cache, defaultTestLogger())
	if err != nil {
		t.Fatalf("httpGet: %v", err)
	}
	// Should get fresh data since no conditional headers were sent.
	if string(data) != "ok" {
		t.Errorf("got %q, want %q", data, "ok")
	}
}
