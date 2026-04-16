package sources

import (
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const syntheticDBIPCSV = `1.0.0.0,1.0.0.255,AU
1.0.1.0,1.0.3.255,CN
2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,JP
10.0.0.0,10.255.255.255,ZZ
`

func serveGzipCSV(csv string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gz := gzip.NewWriter(w)
		gz.Write([]byte(csv))
		gz.Close()
	}))
}

func TestDBIPParseCSV(t *testing.T) {
	ranges, err := parseDBIPCSV([]byte(syntheticDBIPCSV))
	if err != nil {
		t.Fatalf("parseDBIPCSV: %v", err)
	}

	if len(ranges) != 3 {
		t.Fatalf("expected 3 ranges, got %d", len(ranges))
	}

	if ranges[0].Country != "AU" || ranges[0].Start.String() != "1.0.0.0" {
		t.Errorf("range 0: %+v", ranges[0])
	}
	if ranges[1].Country != "CN" {
		t.Errorf("range 1: %+v", ranges[1])
	}
}

func TestDBIPFetchFromServer(t *testing.T) {
	ts := serveGzipCSV(syntheticDBIPCSV)
	defer ts.Close()

	src := &DBIP{Client: ts.Client(), URL: ts.URL}
	ranges, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(ranges) != 3 {
		t.Fatalf("expected 3 ranges, got %d", len(ranges))
	}
}

func TestDBIPMonthFallback(t *testing.T) {
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if strings.Contains(r.URL.Path, "current") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gz := gzip.NewWriter(w)
		gz.Write([]byte("1.0.0.0,1.0.0.255,AU\n"))
		gz.Close()
	}))
	defer ts.Close()

	src := &DBIP{Client: ts.Client(), URL: ts.URL}
	ranges, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(ranges))
	}
}

func TestDBIPGracefulFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	src := &DBIP{Client: ts.Client(), URL: ts.URL}
	_, err := src.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error on 503")
	}
}

func TestDBIPFilterIPv6(t *testing.T) {
	csv := "2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,JP\n"
	ranges, err := parseDBIPCSV([]byte(csv))
	if err != nil {
		t.Fatalf("parseDBIPCSV: %v", err)
	}
	if len(ranges) != 0 {
		t.Errorf("expected 0 ranges after IPv6 filter, got %d", len(ranges))
	}
}
