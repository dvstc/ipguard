package sources

import (
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func gzipString(s string) []byte {
	var b strings.Builder
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return []byte(b.String())
}

func TestBGPParsePfx2AS(t *testing.T) {
	pfxData := "1.0.0.0\t24\t13335\n" +
		"10.0.0.0\t8\t15169\n" +
		"# comment\n" +
		"192.168.0.0\t16\t99999\n"

	asnMap := ASNCountryMap{
		13335: "AU",
		15169: "US",
	}

	bgp := &BGP{ASNMap: asnMap}
	ranges, err := bgp.parsePfx2AS([]byte(pfxData))
	if err != nil {
		t.Fatalf("parsePfx2AS: %v", err)
	}

	if len(ranges) != 2 {
		t.Fatalf("expected 2 ranges, got %d", len(ranges))
	}

	if ranges[0].Start.String() != "1.0.0.0" || ranges[0].End.String() != "1.0.0.255" {
		t.Errorf("range 0: %s - %s", ranges[0].Start, ranges[0].End)
	}
	if ranges[0].Country != "AU" {
		t.Errorf("range 0 country: %s", ranges[0].Country)
	}

	if ranges[1].Start.String() != "10.0.0.0" || ranges[1].End.String() != "10.255.255.255" {
		t.Errorf("range 1: %s - %s", ranges[1].Start, ranges[1].End)
	}
}

func TestBGPMultiOriginAS(t *testing.T) {
	pfxData := "1.0.0.0\t24\t13335_15169\n"
	asnMap := ASNCountryMap{
		13335: "AU",
		15169: "US",
	}

	bgp := &BGP{ASNMap: asnMap}
	ranges, err := bgp.parsePfx2AS([]byte(pfxData))
	if err != nil {
		t.Fatalf("parsePfx2AS: %v", err)
	}

	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(ranges))
	}
	if ranges[0].Country != "AU" {
		t.Errorf("expected first AS (AU), got %s", ranges[0].Country)
	}
}

func TestBGPCreationLogDiscovery(t *testing.T) {
	pfxData := "1.0.0.0\t24\t13335\n"
	var pfxPath string

	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	defer ts.Close()

	pfxPath = "/data/pfx2as-latest.gz"
	mux.HandleFunc("/pfx2as-creation.log", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("some log line\n" + pfxPath + "\n"))
	})
	mux.HandleFunc(pfxPath, func(w http.ResponseWriter, r *http.Request) {
		gz := gzip.NewWriter(w)
		gz.Write([]byte(pfxData))
		gz.Close()
	})

	bgp := &BGP{
		Client:         ts.Client(),
		ASNMap:         ASNCountryMap{13335: "AU"},
		CreationLogURL: ts.URL + "/pfx2as-creation.log",
		BaseURL:        ts.URL,
	}

	ranges, err := bgp.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(ranges))
	}
}

func TestBGPMissingASNMap(t *testing.T) {
	bgp := &BGP{}
	_, err := bgp.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error when ASNMap is nil")
	}
}
