package tgeo

import (
	"crypto/sha256"
	"fmt"
	"sort"
)

// CompileResult holds the output of the compilation step.
type CompileResult struct {
	GzipData   []byte
	Checksum   string // "sha256:hex..."
	EntryCount int
	Countries  int
}

// Compile takes merged IPv4 ranges and produces a gzip-compressed
// TGEO binary along with its SHA-256 checksum. Ranges are sorted
// by start IP before encoding.
func Compile(ranges []IPRange) (*CompileResult, error) {
	if len(ranges) == 0 {
		return nil, fmt.Errorf("no ranges to compile")
	}

	sort.Slice(ranges, func(i, j int) bool {
		return AddrToUint32(ranges[i].Start) < AddrToUint32(ranges[j].Start)
	})

	countryIdx := make(map[string]uint16)
	var countries []string
	for _, r := range ranges {
		if _, ok := countryIdx[r.Country]; !ok {
			countryIdx[r.Country] = uint16(len(countries))
			countries = append(countries, r.Country)
		}
	}

	entries := make([]IPv4Entry, len(ranges))
	for i, r := range ranges {
		entries[i] = IPv4Entry{
			IPStart:    AddrToUint32(r.Start),
			CountryIdx: countryIdx[r.Country],
		}
	}

	data := &GeoIPData{
		Entries:   entries,
		Countries: countries,
	}

	raw, err := Encode(data)
	if err != nil {
		return nil, fmt.Errorf("encode binary: %w", err)
	}

	compressed, err := CompressGzip(raw)
	if err != nil {
		return nil, fmt.Errorf("compress: %w", err)
	}

	hash := sha256.Sum256(compressed)
	checksum := fmt.Sprintf("sha256:%x", hash)

	return &CompileResult{
		GzipData:   compressed,
		Checksum:   checksum,
		EntryCount: len(entries),
		Countries:  len(countries),
	}, nil
}
