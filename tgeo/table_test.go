package tgeo

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tgeoTestEntry struct {
	ipStart    uint32
	countryIdx uint16
}

func buildTestTGEO(t *testing.T, entries []tgeoTestEntry, codes []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.Write([]byte("TGEO"))
	binary.Write(&buf, binary.BigEndian, uint32(1))
	binary.Write(&buf, binary.BigEndian, uint32(len(entries)))
	for _, e := range entries {
		binary.Write(&buf, binary.BigEndian, e.ipStart)
		binary.Write(&buf, binary.BigEndian, e.countryIdx)
	}
	binary.Write(&buf, binary.BigEndian, uint16(len(codes)))
	for _, c := range codes {
		if len(c) < 2 {
			c = c + " "
		}
		buf.WriteString(c[:2])
	}
	return buf.Bytes()
}

func writeTestTGEO(t *testing.T, dir string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, "test.tgeo")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadTable_Valid(t *testing.T) {
	dir := t.TempDir()
	data := buildTestTGEO(t, []tgeoTestEntry{
		{0x01000000, 0},
		{0x02000000, 1},
		{0x03000000, 2},
	}, []string{"US", "CN", "CA"})
	path := writeTestTGEO(t, dir, data)

	table, err := LoadTable(path)
	if err != nil {
		t.Fatal(err)
	}
	if table.EntryCount() != 3 {
		t.Errorf("expected 3 entries, got %d", table.EntryCount())
	}
	if table.CodeCount() != 3 {
		t.Errorf("expected 3 codes, got %d", table.CodeCount())
	}
}

func TestLoadTable_BadMagic(t *testing.T) {
	dir := t.TempDir()
	data := []byte("XGEO\x00\x00\x00\x01\x00\x00\x00\x00")
	path := writeTestTGEO(t, dir, data)

	_, err := LoadTable(path)
	if err == nil {
		t.Fatal("expected error for bad magic")
	}
	if !strings.Contains(err.Error(), "invalid TGEO") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadTable_UnsupportedVersion(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	buf.Write([]byte("TGEO"))
	binary.Write(&buf, binary.BigEndian, uint32(99))
	binary.Write(&buf, binary.BigEndian, uint32(0))
	path := writeTestTGEO(t, dir, buf.Bytes())

	_, err := LoadTable(path)
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
	if !strings.Contains(err.Error(), "unsupported TGEO version") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadTable_Truncated(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	buf.Write([]byte("TGEO"))
	binary.Write(&buf, binary.BigEndian, uint32(1))
	binary.Write(&buf, binary.BigEndian, uint32(5))
	binary.Write(&buf, binary.BigEndian, uint32(0x01000000))
	path := writeTestTGEO(t, dir, buf.Bytes())

	_, err := LoadTable(path)
	if err == nil {
		t.Fatal("expected error for truncated file")
	}
}

func TestLoadTable_EmptyTable(t *testing.T) {
	dir := t.TempDir()
	data := buildTestTGEO(t, nil, nil)
	path := writeTestTGEO(t, dir, data)

	table, err := LoadTable(path)
	if err != nil {
		t.Fatal(err)
	}
	if table.EntryCount() != 0 {
		t.Errorf("expected 0 entries, got %d", table.EntryCount())
	}

	result := table.LookupCountry(netip.MustParseAddr("1.2.3.4"))
	if result != "ZZ" {
		t.Errorf("empty table lookup should return ZZ, got %s", result)
	}
}

func TestLoadTable_FileNotFound(t *testing.T) {
	_, err := LoadTable("/nonexistent/path/geo.tgeo")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadTable_TooSmall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tiny.tgeo")
	if err := os.WriteFile(path, []byte("TGEO\x00"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadTable(path)
	if err == nil {
		t.Fatal("expected error for too-small file")
	}
}

func TestLookupCountry(t *testing.T) {
	data := buildTestTGEO(t, []tgeoTestEntry{
		{0x01000000, 0},
		{0x02000000, 1},
		{0x03000000, 2},
		{0x04000000, 3},
		{0x05000000, 4},
	}, []string{"US", "CN", "CA", "ZZ", "GB"})

	dir := t.TempDir()
	path := writeTestTGEO(t, dir, data)
	table, err := LoadTable(path)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{"FirstEntry", "1.0.0.1", "US"},
		{"MiddleEntry", "2.128.0.0", "CN"},
		{"LastEntry", "5.0.0.1", "GB"},
		{"BetweenRanges", "1.255.255.255", "US"},
		{"ExactBoundary", "3.0.0.0", "CA"},
		{"BeforeAllRanges", "0.0.0.1", "ZZ"},
		{"AfterAllRanges", "255.255.255.255", "GB"},
		{"ZZRange", "4.0.0.1", "ZZ"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.ip)
			result := table.LookupCountry(addr)
			if result != tt.expected {
				t.Errorf("LookupCountry(%s) = %q, want %q", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestLookupCountry_IPv6(t *testing.T) {
	dir := t.TempDir()
	data := buildTestTGEO(t, []tgeoTestEntry{
		{0x01000000, 0},
	}, []string{"US"})
	path := writeTestTGEO(t, dir, data)
	table, err := LoadTable(path)
	if err != nil {
		t.Fatal(err)
	}

	addr := netip.MustParseAddr("::1")
	result := table.LookupCountry(addr)
	if result != "ZZ" {
		t.Errorf("IPv6 lookup should return ZZ, got %s", result)
	}
}

func TestLoadTable_AtomicSwapDirect(t *testing.T) {
	dir := t.TempDir()

	dataA := buildTestTGEO(t, []tgeoTestEntry{{0x02000000, 0}}, []string{"US"})
	pathA := filepath.Join(dir, "a.tgeo")
	os.WriteFile(pathA, dataA, 0644)

	tableA, err := LoadTable(pathA)
	if err != nil {
		t.Fatal(err)
	}
	result := tableA.LookupCountry(netip.MustParseAddr("2.0.0.1"))
	if result != "US" {
		t.Errorf("table A lookup should be US, got %s", result)
	}

	dataB := buildTestTGEO(t, []tgeoTestEntry{{0x02000000, 0}}, []string{"CN"})
	pathB := filepath.Join(dir, "b.tgeo")
	os.WriteFile(pathB, dataB, 0644)

	tableB, err := LoadTable(pathB)
	if err != nil {
		t.Fatal(err)
	}
	result = tableB.LookupCountry(netip.MustParseAddr("2.0.0.1"))
	if result != "CN" {
		t.Errorf("table B lookup should be CN, got %s", result)
	}
}

func TestLoadTableFromBytes_Parity(t *testing.T) {
	data := buildTestTGEO(t, []tgeoTestEntry{
		{0x01000000, 0},
		{0x02000000, 1},
	}, []string{"US", "CN"})

	tableFile, err := func() (*Table, error) {
		dir := t.TempDir()
		path := writeTestTGEO(t, dir, data)
		return LoadTable(path)
	}()
	if err != nil {
		t.Fatalf("LoadTable: %v", err)
	}

	tableBytes, err := LoadTableFromBytes(data)
	if err != nil {
		t.Fatalf("LoadTableFromBytes: %v", err)
	}

	if tableFile.EntryCount() != tableBytes.EntryCount() {
		t.Errorf("entry count mismatch: file=%d bytes=%d", tableFile.EntryCount(), tableBytes.EntryCount())
	}
	if tableFile.CodeCount() != tableBytes.CodeCount() {
		t.Errorf("code count mismatch: file=%d bytes=%d", tableFile.CodeCount(), tableBytes.CodeCount())
	}

	ip := netip.MustParseAddr("1.0.0.1")
	if tableFile.LookupCountry(ip) != tableBytes.LookupCountry(ip) {
		t.Errorf("lookup mismatch for %s: file=%s bytes=%s", ip, tableFile.LookupCountry(ip), tableBytes.LookupCountry(ip))
	}
}

func TestLoadTableFromBytes_BadData(t *testing.T) {
	_, err := LoadTableFromBytes([]byte("not tgeo data"))
	if err == nil {
		t.Fatal("expected error for bad data")
	}
}

func TestLoadTable_TruncatedCodes(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	buf.Write([]byte("TGEO"))
	binary.Write(&buf, binary.BigEndian, uint32(1))
	binary.Write(&buf, binary.BigEndian, uint32(1))
	binary.Write(&buf, binary.BigEndian, uint32(0x01000000))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	binary.Write(&buf, binary.BigEndian, uint16(3))
	path := writeTestTGEO(t, dir, buf.Bytes())

	_, err := LoadTable(path)
	if err == nil {
		t.Fatal("expected error for truncated code table")
	}
}
