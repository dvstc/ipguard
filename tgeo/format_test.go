package tgeo

import (
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	data := &GeoIPData{
		Entries: []IPv4Entry{
			{IPStart: 0x01000000, CountryIdx: 0},
			{IPStart: 0x0A000000, CountryIdx: 1},
			{IPStart: 0xC0A80000, CountryIdx: 2},
		},
		Countries: []string{"US", "CN", "ZZ"},
	}

	raw, err := Encode(data)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	decoded, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if len(decoded.Entries) != len(data.Entries) {
		t.Fatalf("entry count: got %d, want %d", len(decoded.Entries), len(data.Entries))
	}
	for i := range data.Entries {
		if decoded.Entries[i] != data.Entries[i] {
			t.Errorf("entry %d: got %+v, want %+v", i, decoded.Entries[i], data.Entries[i])
		}
	}
	if len(decoded.Countries) != len(data.Countries) {
		t.Fatalf("country count: got %d, want %d", len(decoded.Countries), len(data.Countries))
	}
	for i := range data.Countries {
		if decoded.Countries[i] != data.Countries[i] {
			t.Errorf("country %d: got %q, want %q", i, decoded.Countries[i], data.Countries[i])
		}
	}
}

func TestHeaderMagicValidation(t *testing.T) {
	_, err := Decode([]byte("XGEO\x00\x00\x00\x01\x00\x00\x00\x00"))
	if err == nil {
		t.Fatal("expected error for invalid magic")
	}
}

func TestHeaderVersionValidation(t *testing.T) {
	_, err := Decode([]byte("TGEO\x00\x00\x00\x02\x00\x00\x00\x00"))
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestEmptyTable(t *testing.T) {
	data := &GeoIPData{
		Entries:   nil,
		Countries: nil,
	}
	raw, err := Encode(data)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(decoded.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(decoded.Entries))
	}
	if len(decoded.Countries) != 0 {
		t.Errorf("expected 0 countries, got %d", len(decoded.Countries))
	}
}

func TestSingleEntry(t *testing.T) {
	data := &GeoIPData{
		Entries:   []IPv4Entry{{IPStart: 0, CountryIdx: 0}},
		Countries: []string{"ZZ"},
	}
	raw, err := Encode(data)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(decoded.Entries) != 1 || decoded.Entries[0].IPStart != 0 {
		t.Errorf("unexpected entry: %+v", decoded.Entries)
	}
}

func TestMaxIPv4Entry(t *testing.T) {
	data := &GeoIPData{
		Entries:   []IPv4Entry{{IPStart: 0xFFFFFFFF, CountryIdx: 0}},
		Countries: []string{"US"},
	}
	raw, err := Encode(data)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.Entries[0].IPStart != 0xFFFFFFFF {
		t.Errorf("got IP %x, want FFFFFFFF", decoded.Entries[0].IPStart)
	}
}

func TestCompressDecompressRoundTrip(t *testing.T) {
	data := &GeoIPData{
		Entries:   []IPv4Entry{{IPStart: 0x01000000, CountryIdx: 0}},
		Countries: []string{"US"},
	}
	raw, err := Encode(data)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	compressed, err := CompressGzip(raw)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}
	decompressed, err := DecompressGzip(compressed)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if len(decompressed) != len(raw) {
		t.Fatalf("length mismatch: %d vs %d", len(decompressed), len(raw))
	}
	for i := range raw {
		if decompressed[i] != raw[i] {
			t.Fatalf("byte %d: got %x, want %x", i, decompressed[i], raw[i])
		}
	}
}

func TestDataTooShort(t *testing.T) {
	_, err := Decode([]byte("TGEO"))
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestInvalidCountryCodeLength(t *testing.T) {
	data := &GeoIPData{
		Entries:   []IPv4Entry{{IPStart: 0, CountryIdx: 0}},
		Countries: []string{"USA"},
	}
	_, err := Encode(data)
	if err == nil {
		t.Fatal("expected error for 3-char country code")
	}
}
