package sources

import (
	"bufio"
	"bytes"
	"compress/gzip"
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
	caidaCreationLogURL = "https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/pfx2as-creation.log"
	caidaBaseURL        = "https://publicdata.caida.org/datasets/routing/routeviews-prefix2as"
)

// BGP implements Source by fetching CAIDA's RouteViews prefix-to-AS mapping
// and joining it with an ASN-to-country map from the RIR source.
type BGP struct {
	Client         *http.Client
	Logger         *slog.Logger
	ASNMap         ASNCountryMap
	CreationLogURL string // override for testing
	BaseURL        string // override for testing
}

func (b *BGP) Name() string  { return "bgp-caida" }
func (b *BGP) Priority() int { return 2 }

func (b *BGP) Fetch(ctx context.Context) ([]tgeo.IPRange, error) {
	logger := b.logger()
	client := b.Client
	if client == nil {
		client = http.DefaultClient
	}
	if b.ASNMap == nil {
		return nil, fmt.Errorf("ASNMap not set; RIR source must run first")
	}

	fileURL, err := b.discoverLatestFile(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("discover pfx2as file: %w", err)
	}

	logger.Info("downloading BGP pfx2as data", "url", fileURL)
	data, err := b.downloadGzip(ctx, client, fileURL)
	if err != nil {
		return nil, fmt.Errorf("download pfx2as: %w", err)
	}

	ranges, err := b.parsePfx2AS(data)
	if err != nil {
		return nil, fmt.Errorf("parse pfx2as: %w", err)
	}

	logger.Info("parsed BGP pfx2as data", "ipv4_ranges", len(ranges))
	return ranges, nil
}

func (b *BGP) discoverLatestFile(ctx context.Context, client *http.Client) (string, error) {
	logURL := b.CreationLogURL
	if logURL == "" {
		logURL = caidaCreationLogURL
	}

	body, err := httpGet(ctx, client, logURL)
	if err != nil {
		return "", fmt.Errorf("fetch creation log: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) == 0 {
		return "", fmt.Errorf("empty creation log")
	}

	lastLine := strings.TrimSpace(lines[len(lines)-1])
	parts := strings.Fields(lastLine)
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid creation log last line: %q", lastLine)
	}

	filePath := parts[len(parts)-1]

	base := b.BaseURL
	if base == "" {
		base = caidaBaseURL
	}

	if strings.HasPrefix(filePath, "http") {
		if !strings.HasPrefix(filePath, base+"/") {
			return "", fmt.Errorf("creation log references unexpected URL: %q", filePath)
		}
		return filePath, nil
	}

	cleaned := strings.TrimPrefix(filePath, "/")
	if strings.Contains(cleaned, "..") {
		return "", fmt.Errorf("creation log contains path traversal: %q", filePath)
	}
	return base + "/" + cleaned, nil
}

func (b *BGP) downloadGzip(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	body, err := readLimited(resp.Body, maxResponseBytes)
	if err != nil {
		return nil, err
	}

	gr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return body, nil
	}
	defer gr.Close()
	return readLimited(gr, maxResponseBytes)
}

func (b *BGP) parsePfx2AS(data []byte) ([]tgeo.IPRange, error) {
	var ranges []tgeo.IPRange
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}

		prefixStr := fields[0]
		bitsStr := fields[1]
		asnField := fields[2]

		addr, err := netip.ParseAddr(prefixStr)
		if err != nil || !addr.Is4() {
			continue
		}

		bits, err := strconv.Atoi(bitsStr)
		if err != nil || bits < 0 || bits > 32 {
			continue
		}

		prefix, err := addr.Prefix(bits)
		if err != nil {
			continue
		}

		asnStr := asnField
		if idx := strings.IndexByte(asnField, '_'); idx > 0 {
			asnStr = asnField[:idx]
		}

		asn, err := strconv.ParseUint(asnStr, 10, 32)
		if err != nil {
			continue
		}

		cc, ok := b.ASNMap[uint32(asn)]
		if !ok {
			continue
		}

		startAddr := prefix.Addr()
		endAddr := prefixLastAddr(prefix)

		ranges = append(ranges, tgeo.IPRange{
			Start:   startAddr,
			End:     endAddr,
			Country: cc,
		})
	}

	return ranges, scanner.Err()
}

func prefixLastAddr(p netip.Prefix) netip.Addr {
	addr := p.Addr()
	bits := p.Bits()
	hostBits := 32 - bits
	mask := uint32((1 << hostBits) - 1)
	v := tgeo.AddrToUint32(addr) | mask
	var out [4]byte
	out[0] = byte(v >> 24)
	out[1] = byte(v >> 16)
	out[2] = byte(v >> 8)
	out[3] = byte(v)
	return netip.AddrFrom4(out)
}

func (b *BGP) logger() *slog.Logger {
	if b.Logger != nil {
		return b.Logger
	}
	return slog.Default()
}
