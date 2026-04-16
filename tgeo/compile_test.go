package tgeo

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"testing"
)

func ip(s string) netip.Addr {
	return netip.MustParseAddr(s)
}

func TestCompileProducesValidBinary(t *testing.T) {
	ranges := []IPRange{
		{Start: ip("0.0.0.0"), End: ip("0.255.255.255"), Country: "ZZ"},
		{Start: ip("1.0.0.0"), End: ip("1.0.0.255"), Country: "US"},
		{Start: ip("1.0.1.0"), End: ip("255.255.255.255"), Country: "ZZ"},
	}

	result, err := Compile(ranges)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	if result.EntryCount != 3 {
		t.Errorf("entry count: got %d, want 3", result.EntryCount)
	}
	if result.Countries != 2 {
		t.Errorf("country count: got %d, want 2", result.Countries)
	}

	hash := sha256.Sum256(result.GzipData)
	expected := fmt.Sprintf("sha256:%x", hash)
	if result.Checksum != expected {
		t.Errorf("checksum mismatch")
	}

	raw, err := DecompressGzip(result.GzipData)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}

	data, err := Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(data.Entries) != 3 {
		t.Errorf("decoded entries: got %d, want 3", len(data.Entries))
	}
}

func TestCompileEmptyRanges(t *testing.T) {
	_, err := Compile(nil)
	if err == nil {
		t.Fatal("expected error for empty ranges")
	}
}

func TestCompileSortOrder(t *testing.T) {
	ranges := []IPRange{
		{Start: ip("10.0.0.0"), End: ip("10.0.0.255"), Country: "US"},
		{Start: ip("1.0.0.0"), End: ip("1.0.0.255"), Country: "AU"},
	}

	result, err := Compile(ranges)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	raw, _ := DecompressGzip(result.GzipData)
	data, _ := Decode(raw)

	if data.Entries[0].IPStart > data.Entries[1].IPStart {
		t.Error("entries not sorted by IP start")
	}
}
