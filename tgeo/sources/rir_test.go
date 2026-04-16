package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const syntheticNROData = `2|nro|20260401|1234|19900101|20260401|+0000
nro|*|ipv4|*|0|summary
nro|*|ipv6|*|0|summary
nro|*|asn|*|0|summary
# comment line
ripencc|US|ipv4|1.0.0.0|256|20100101|allocated
ripencc|CN|ipv4|1.0.1.0|256|20100101|assigned
ripencc|AU|asn|13335|1|20100101|allocated
ripencc|GB|ipv4|5.0.0.0|1|20110101|allocated
ripencc|ZZ|ipv4|10.0.0.0|256|20100101|reserved
ripencc|XX|ipv6|2001:db8::|32|20100101|allocated
`

func TestRIRParseIPv4Ranges(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(syntheticNROData))
	}))
	defer ts.Close()

	src := &RIR{Client: ts.Client(), URL: ts.URL}
	ranges, asnMap, err := src.FetchWithASN(context.Background())
	if err != nil {
		t.Fatalf("FetchWithASN: %v", err)
	}

	if len(ranges) != 3 {
		t.Fatalf("expected 3 ranges, got %d", len(ranges))
	}

	us := ranges[0]
	if us.Start.String() != "1.0.0.0" || us.End.String() != "1.0.0.255" {
		t.Errorf("US range: %s - %s", us.Start, us.End)
	}
	if us.Country != "US" {
		t.Errorf("US country: %s", us.Country)
	}

	gb := ranges[2]
	if gb.Start.String() != "5.0.0.0" || gb.End.String() != "5.0.0.0" {
		t.Errorf("GB range: %s - %s", gb.Start, gb.End)
	}

	if len(asnMap) != 1 {
		t.Fatalf("expected 1 ASN entry, got %d", len(asnMap))
	}
	if asnMap[13335] != "AU" {
		t.Errorf("ASN 13335: got %s, want AU", asnMap[13335])
	}
}

func TestRIRFilterReserved(t *testing.T) {
	ranges, _, err := parseRIRData([]byte(syntheticNROData))
	if err != nil {
		t.Fatalf("parseRIRData: %v", err)
	}

	for _, r := range ranges {
		if r.Start.String() == "10.0.0.0" {
			t.Error("reserved range 10.0.0.0 should have been filtered")
		}
	}
}

func TestRIRFilterIPv6(t *testing.T) {
	ranges, _, err := parseRIRData([]byte(syntheticNROData))
	if err != nil {
		t.Fatalf("parseRIRData: %v", err)
	}

	for _, r := range ranges {
		if r.Start.Is6() {
			t.Error("IPv6 range should have been filtered")
		}
	}
}

func TestRIRFallback(t *testing.T) {
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ripencc|DE|ipv4|1.0.0.0|256|20100101|allocated\n"))
	}))
	defer ts.Close()

	src := &RIR{Client: ts.Client(), URL: ts.URL}
	_, _, err := src.FetchWithASN(context.Background())
	if err == nil {
		t.Fatal("expected error with overridden URL returning 503")
	}
}

func TestRIRHostCountEdgeCases(t *testing.T) {
	tests := []struct {
		name, start, value, wantEnd string
	}{
		{"single host (/32)", "1.0.0.0", "1", "1.0.0.0"},
		{"class C (/24)", "1.0.0.0", "256", "1.0.0.255"},
		{"class A (/8)", "10.0.0.0", "16777216", "10.255.255.255"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := parseIPv4Record(tt.start, tt.value, "US")
			if err != nil {
				t.Fatalf("parseIPv4Record: %v", err)
			}
			if r.End.String() != tt.wantEnd {
				t.Errorf("end: got %s, want %s", r.End, tt.wantEnd)
			}
		})
	}
}
