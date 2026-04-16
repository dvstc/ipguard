package sources

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/dvstc/ipguard/tgeo"
)

const (
	nroURL = "https://ftp.ripe.net/pub/stats/ripencc/nro-stats/latest/nro-delegated-stats"
)

var rirFallbackURLs = []string{
	"https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
	"https://ftp.apnic.net/pub/apnic/stats/apnic/delegated-apnic-extended-latest",
	"https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
	"https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
	"https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}

// RIR implements RIRSource by fetching NRO combined delegation files
// (or individual RIR files as fallback) and parsing IPv4 allocations
// and ASN-to-country mappings.
type RIR struct {
	Client *http.Client
	Logger *slog.Logger
	URL    string // override for testing; empty = nroURL
}

func (r *RIR) Name() string  { return "rir-nro" }
func (r *RIR) Priority() int { return 1 }

func (r *RIR) Fetch(ctx context.Context) ([]tgeo.IPRange, error) {
	ranges, _, err := r.FetchWithASN(ctx)
	return ranges, err
}

func (r *RIR) FetchWithASN(ctx context.Context) ([]tgeo.IPRange, ASNCountryMap, error) {
	logger := r.logger()

	bodies, err := r.downloadAll(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("download RIR data: %w", err)
	}

	var ranges []tgeo.IPRange
	asnMap := make(ASNCountryMap)

	for _, body := range bodies {
		r, a, err := parseRIRData(body)
		if err != nil {
			logger.Warn("error parsing RIR data segment", "error", err)
			continue
		}
		ranges = append(ranges, r...)
		for k, v := range a {
			asnMap[k] = v
		}
	}

	logger.Info("parsed RIR delegation data", "ipv4_ranges", len(ranges), "asn_entries", len(asnMap))
	return ranges, asnMap, nil
}

func (r *RIR) downloadAll(ctx context.Context) ([][]byte, error) {
	client := r.Client
	if client == nil {
		client = http.DefaultClient
	}

	url := r.URL
	if url == "" {
		url = nroURL
	}

	body, err := httpGet(ctx, client, url)
	if err == nil {
		return [][]byte{body}, nil
	}

	if r.URL != "" {
		return nil, err
	}

	r.logger().Warn("NRO combined file unavailable, falling back to individual RIRs", "error", err)

	var bodies [][]byte
	for _, furl := range rirFallbackURLs {
		b, ferr := httpGet(ctx, client, furl)
		if ferr != nil {
			r.logger().Warn("RIR fallback download failed", "url", furl, "error", ferr)
			continue
		}
		bodies = append(bodies, b)
	}
	if len(bodies) == 0 {
		return nil, fmt.Errorf("all RIR downloads failed")
	}
	return bodies, nil
}

func (r *RIR) logger() *slog.Logger {
	if r.Logger != nil {
		return r.Logger
	}
	return slog.Default()
}

func parseRIRData(data []byte) ([]tgeo.IPRange, ASNCountryMap, error) {
	var ranges []tgeo.IPRange
	asnMap := make(ASNCountryMap)

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		fields := strings.Split(line, "|")
		if len(fields) < 7 {
			continue
		}

		cc := fields[1]
		recType := fields[2]
		start := fields[3]
		value := fields[4]
		status := fields[6]

		if cc == "*" {
			continue
		}

		if status != "allocated" && status != "assigned" {
			continue
		}

		switch recType {
		case "ipv4":
			r, err := parseIPv4Record(start, value, cc)
			if err != nil {
				continue
			}
			ranges = append(ranges, r)

		case "asn":
			asn, err := strconv.ParseUint(start, 10, 32)
			if err != nil {
				continue
			}
			asnMap[uint32(asn)] = cc
		}
	}

	return ranges, asnMap, scanner.Err()
}

func parseIPv4Record(startStr, valueStr, cc string) (tgeo.IPRange, error) {
	startAddr, err := netip.ParseAddr(startStr)
	if err != nil {
		return tgeo.IPRange{}, err
	}
	if !startAddr.Is4() {
		return tgeo.IPRange{}, fmt.Errorf("not IPv4: %s", startStr)
	}

	count, err := strconv.ParseUint(valueStr, 10, 32)
	if err != nil {
		return tgeo.IPRange{}, err
	}
	if count == 0 {
		return tgeo.IPRange{}, fmt.Errorf("zero count")
	}

	startU32 := tgeo.AddrToUint32(startAddr)
	end64 := uint64(startU32) + uint64(count) - 1
	if end64 > uint64(^uint32(0)) {
		return tgeo.IPRange{}, fmt.Errorf("range overflow: %s + %d exceeds IPv4 address space", startStr, count)
	}
	endU32 := uint32(end64)
	endAddr := tgeo.Uint32ToAddr(endU32)

	return tgeo.IPRange{
		Start:   startAddr,
		End:     endAddr,
		Country: cc,
	}, nil
}
