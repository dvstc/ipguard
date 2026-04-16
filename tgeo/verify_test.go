package tgeo

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyAndWrite_Valid(t *testing.T) {
	data := &GeoIPData{
		Entries:   []IPv4Entry{{IPStart: 0x01000000, CountryIdx: 0}},
		Countries: []string{"US"},
	}
	raw, err := Encode(data)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := CompressGzip(raw)
	if err != nil {
		t.Fatal(err)
	}

	hash := sha256.Sum256(compressed)
	checksum := fmt.Sprintf("sha256:%x", hash)

	dir := t.TempDir()
	dest := filepath.Join(dir, "geo", "iploc.bin")

	if err := VerifyAndWrite(compressed, checksum, dest); err != nil {
		t.Fatalf("VerifyAndWrite: %v", err)
	}

	written, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != len(raw) {
		t.Errorf("written file size: got %d, want %d", len(written), len(raw))
	}
	for i := range raw {
		if written[i] != raw[i] {
			t.Fatalf("byte %d: got %x, want %x", i, written[i], raw[i])
		}
	}
}

func TestVerifyAndWrite_ChecksumMismatch(t *testing.T) {
	compressed, _ := CompressGzip([]byte("test data"))
	err := VerifyAndWrite(compressed, "sha256:0000000000000000000000000000000000000000000000000000000000000000", t.TempDir()+"/out.bin")
	if err == nil {
		t.Fatal("expected error for checksum mismatch")
	}
}

func TestVerifyAndWrite_CreatesDirectories(t *testing.T) {
	data := &GeoIPData{
		Entries:   []IPv4Entry{{IPStart: 0, CountryIdx: 0}},
		Countries: []string{"ZZ"},
	}
	raw, _ := Encode(data)
	compressed, _ := CompressGzip(raw)
	hash := sha256.Sum256(compressed)
	checksum := fmt.Sprintf("sha256:%x", hash)

	dir := t.TempDir()
	dest := filepath.Join(dir, "a", "b", "c", "geo.bin")

	if err := VerifyAndWrite(compressed, checksum, dest); err != nil {
		t.Fatalf("VerifyAndWrite: %v", err)
	}

	if _, err := os.Stat(dest); os.IsNotExist(err) {
		t.Error("expected file to be created")
	}
}

func TestVerifyAndWrite_LoadableResult(t *testing.T) {
	data := &GeoIPData{
		Entries: []IPv4Entry{
			{IPStart: 0x01000000, CountryIdx: 0},
			{IPStart: 0x02000000, CountryIdx: 1},
		},
		Countries: []string{"US", "CN"},
	}
	raw, _ := Encode(data)
	compressed, _ := CompressGzip(raw)
	hash := sha256.Sum256(compressed)
	checksum := fmt.Sprintf("sha256:%x", hash)

	dir := t.TempDir()
	dest := filepath.Join(dir, "iploc.bin")
	if err := VerifyAndWrite(compressed, checksum, dest); err != nil {
		t.Fatal(err)
	}

	table, err := LoadTable(dest)
	if err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	if table.EntryCount() != 2 {
		t.Errorf("expected 2 entries, got %d", table.EntryCount())
	}
}
