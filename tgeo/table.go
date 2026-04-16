package tgeo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
)

// Table is a read-optimized lookup structure loaded from a TGEO binary file.
// It uses parallel arrays and binary search for ~14ns IPv4 lookups.
type Table struct {
	entries   []uint32 // ip_start values, sorted ascending
	countries []uint16 // country_idx for each entry (parallel array)
	codes     []string // country code table (index -> "US", "CN", etc.)
}

// LoadTable reads a TGEO binary file from disk and returns a Table ready for lookups.
func LoadTable(path string) (*Table, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) < HeaderSize || !bytes.Equal(raw[:4], Magic[:]) {
		return nil, fmt.Errorf("invalid TGEO file")
	}
	version := binary.BigEndian.Uint32(raw[4:8])
	if version != FormatVersion {
		return nil, fmt.Errorf("unsupported TGEO version: %d", version)
	}

	entryCount := binary.BigEndian.Uint32(raw[8:12])

	maxEntries := (len(raw) - HeaderSize) / IPv4EntrySize
	if int64(entryCount) > int64(maxEntries) {
		return nil, fmt.Errorf("invalid TGEO file: entryCount %d exceeds file capacity of %d entries", entryCount, maxEntries)
	}

	t := &Table{
		entries:   make([]uint32, entryCount),
		countries: make([]uint16, entryCount),
	}

	off := HeaderSize
	for i := uint32(0); i < entryCount; i++ {
		if off+IPv4EntrySize > len(raw) {
			return nil, fmt.Errorf("invalid TGEO file: truncated entries at index %d", i)
		}
		t.entries[i] = binary.BigEndian.Uint32(raw[off : off+4])
		t.countries[i] = binary.BigEndian.Uint16(raw[off+4 : off+6])
		off += IPv4EntrySize
	}

	if off+2 > len(raw) {
		return nil, fmt.Errorf("invalid TGEO file: truncated code count")
	}
	codeCount := binary.BigEndian.Uint16(raw[off : off+2])
	off += 2
	t.codes = make([]string, codeCount)
	for i := uint16(0); i < codeCount; i++ {
		if off+CountryCodeLen > len(raw) {
			return nil, fmt.Errorf("invalid TGEO file: truncated country codes at index %d", i)
		}
		t.codes[i] = string(raw[off : off+CountryCodeLen])
		off += CountryCodeLen
	}

	for i, idx := range t.countries {
		if int(idx) >= len(t.codes) {
			return nil, fmt.Errorf("invalid TGEO file: entry %d references country index %d, but only %d codes exist", i, idx, len(t.codes))
		}
	}

	return t, nil
}

// LookupCountry returns the ISO 3166-1 alpha-2 country code for an IPv4 address.
// Returns "ZZ" for unallocated/reserved space or non-IPv4 addresses.
func (t *Table) LookupCountry(ip netip.Addr) string {
	if !ip.Is4() {
		return "ZZ"
	}
	b := ip.As4()
	target := binary.BigEndian.Uint32(b[:])

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

// EntryCount returns the number of IPv4 range entries in the table.
func (t *Table) EntryCount() int {
	return len(t.entries)
}

// CodeCount returns the number of distinct country codes in the table.
func (t *Table) CodeCount() int {
	return len(t.codes)
}
