package tgeo

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
)

// Magic is the four-byte file signature for the TGEO binary format.
var Magic = [4]byte{'T', 'G', 'E', 'O'}

const (
	FormatVersion  = 1
	HeaderSize     = 12 // magic(4) + version(4) + entry_count(4)
	IPv4EntrySize  = 6  // ip_start(4) + country_idx(2)
	CountryCodeLen = 2  // ISO 3166-1 alpha-2
)

// GeoIPData is the in-memory representation of the TGEO binary format.
type GeoIPData struct {
	Entries   []IPv4Entry
	Countries []string // 2-char country codes, index matches CountryIdx
}

// IPv4Entry is a single row in the IPv4 lookup table.
type IPv4Entry struct {
	IPStart    uint32
	CountryIdx uint16
}

// Encode serializes GeoIPData to the TGEO binary format (uncompressed).
func Encode(data *GeoIPData) ([]byte, error) {
	if len(data.Countries) > 65535 {
		return nil, fmt.Errorf("too many country codes: %d", len(data.Countries))
	}
	if len(data.Entries) > int(^uint32(0)) {
		return nil, fmt.Errorf("too many entries: %d", len(data.Entries))
	}

	tableSize := len(data.Entries) * IPv4EntrySize
	countryTableSize := 2 + len(data.Countries)*CountryCodeLen
	buf := make([]byte, 0, HeaderSize+tableSize+countryTableSize)

	buf = append(buf, Magic[:]...)
	buf = binary.BigEndian.AppendUint32(buf, FormatVersion)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(data.Entries)))

	for _, e := range data.Entries {
		buf = binary.BigEndian.AppendUint32(buf, e.IPStart)
		buf = binary.BigEndian.AppendUint16(buf, e.CountryIdx)
	}

	buf = binary.BigEndian.AppendUint16(buf, uint16(len(data.Countries)))
	for _, cc := range data.Countries {
		if len(cc) != CountryCodeLen {
			return nil, fmt.Errorf("invalid country code length: %q", cc)
		}
		buf = append(buf, cc[0], cc[1])
	}

	return buf, nil
}

// Decode deserializes the TGEO binary format (uncompressed) into GeoIPData.
func Decode(raw []byte) (*GeoIPData, error) {
	if len(raw) < HeaderSize {
		return nil, fmt.Errorf("data too short for header: %d bytes", len(raw))
	}

	if !bytes.Equal(raw[:4], Magic[:]) {
		return nil, fmt.Errorf("invalid magic: %q", raw[:4])
	}

	version := binary.BigEndian.Uint32(raw[4:8])
	if version != FormatVersion {
		return nil, fmt.Errorf("unsupported format version: %d", version)
	}

	entryCount := binary.BigEndian.Uint32(raw[8:12])

	maxEntries := int64(len(raw)-HeaderSize) / int64(IPv4EntrySize)
	if int64(entryCount) > maxEntries {
		return nil, fmt.Errorf("entryCount %d exceeds data capacity of %d entries", entryCount, maxEntries)
	}

	tableEnd := HeaderSize + int(entryCount)*IPv4EntrySize
	if len(raw) < tableEnd+2 {
		return nil, fmt.Errorf("data too short for %d entries", entryCount)
	}

	entries := make([]IPv4Entry, entryCount)
	for i := range entries {
		off := HeaderSize + i*IPv4EntrySize
		entries[i] = IPv4Entry{
			IPStart:    binary.BigEndian.Uint32(raw[off : off+4]),
			CountryIdx: binary.BigEndian.Uint16(raw[off+4 : off+6]),
		}
	}

	countryCount := int(binary.BigEndian.Uint16(raw[tableEnd : tableEnd+2]))
	countriesStart := tableEnd + 2
	if len(raw) < countriesStart+countryCount*CountryCodeLen {
		return nil, fmt.Errorf("data too short for %d countries", countryCount)
	}

	countries := make([]string, countryCount)
	for i := range countries {
		off := countriesStart + i*CountryCodeLen
		countries[i] = string(raw[off : off+CountryCodeLen])
	}

	for i, e := range entries {
		if int(e.CountryIdx) >= len(countries) {
			return nil, fmt.Errorf("entry %d references country index %d, but only %d codes exist", i, e.CountryIdx, len(countries))
		}
	}

	return &GeoIPData{Entries: entries, Countries: countries}, nil
}

// CompressGzip compresses data with gzip at default compression level.
func CompressGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, gzip.DefaultCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const maxDecompressedBytes = 256 << 20 // 256 MB

// DecompressGzip decompresses gzip data. Returns an error if the
// decompressed output exceeds 256 MB to prevent decompression bombs.
func DecompressGzip(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, maxDecompressedBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > maxDecompressedBytes {
		return nil, fmt.Errorf("decompressed data exceeds %d byte limit", maxDecompressedBytes)
	}
	return out, nil
}
