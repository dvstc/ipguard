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
	"strings"
	"sync"
	"time"

	"github.com/dvstc/ipguard/tgeo"
)

const dbipURLTemplate = "https://download.db-ip.com/free/dbip-country-lite-%d-%02d.csv.gz"

// DBIP implements Source by fetching the DB-IP Lite country CSV.
type DBIP struct {
	Client *http.Client
	Logger *slog.Logger
	URL    string // override for testing; empty = constructed from date
	Cache  Cache  // optional; nil = auto-created MemoryCache

	initCache    sync.Once
	defaultCache Cache
}

func (d *DBIP) Name() string  { return "dbip-lite" }
func (d *DBIP) Priority() int { return 3 }

func (d *DBIP) Fetch(ctx context.Context) ([]tgeo.IPRange, error) {
	logger := d.logger()
	client := d.Client
	if client == nil {
		client = http.DefaultClient
	}

	data, err := d.download(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("download DB-IP data: %w", err)
	}

	ranges, err := parseDBIPCSV(data)
	if err != nil {
		return nil, fmt.Errorf("parse DB-IP CSV: %w", err)
	}

	logger.Info("parsed DB-IP data", "ipv4_ranges", len(ranges))
	return ranges, nil
}

func (d *DBIP) download(ctx context.Context, client *http.Client) ([]byte, error) {
	if d.URL != "" {
		return d.downloadGzip(ctx, client, d.URL)
	}

	now := time.Now().UTC()
	url := fmt.Sprintf(dbipURLTemplate, now.Year(), now.Month())
	data, err := d.downloadGzip(ctx, client, url)
	if err == nil {
		return data, nil
	}

	prev := now.AddDate(0, -1, 0)
	prevURL := fmt.Sprintf(dbipURLTemplate, prev.Year(), prev.Month())
	d.logger().Warn("current month DB-IP unavailable, trying previous month",
		"current_url", url, "fallback_url", prevURL, "error", err)
	return d.downloadGzip(ctx, client, prevURL)
}

func (d *DBIP) downloadGzip(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	c := d.cache()
	logger := d.logger()

	resp, body, err := httpDoConditional(ctx, client, url, c, logger)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return body, nil
	}

	gr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gr.Close()

	decompressed, err := readLimited(gr, maxResponseBytes)
	if err != nil {
		return nil, err
	}

	if c != nil {
		_ = c.Put(&CacheEntry{
			URL:          url,
			Data:         decompressed,
			ETag:         resp.Header.Get("ETag"),
			LastModified: resp.Header.Get("Last-Modified"),
		})
	}
	return decompressed, nil
}

func parseDBIPCSV(data []byte) ([]tgeo.IPRange, error) {
	var ranges []tgeo.IPRange
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.SplitN(line, ",", 4)
		if len(fields) < 3 {
			continue
		}

		startStr := strings.Trim(fields[0], "\"")
		endStr := strings.Trim(fields[1], "\"")
		cc := strings.Trim(fields[2], "\"")

		startAddr, err := netip.ParseAddr(startStr)
		if err != nil {
			continue
		}
		if startAddr.Is6() && !startAddr.Is4In6() {
			continue
		}
		startAddr = startAddr.Unmap()

		endAddr, err := netip.ParseAddr(endStr)
		if err != nil {
			continue
		}
		endAddr = endAddr.Unmap()

		if !startAddr.Is4() || !endAddr.Is4() {
			continue
		}

		if len(cc) != 2 {
			continue
		}

		ranges = append(ranges, tgeo.IPRange{
			Start:   startAddr,
			End:     endAddr,
			Country: cc,
		})
	}

	return ranges, scanner.Err()
}

func (d *DBIP) cache() Cache {
	if d.Cache != nil {
		return d.Cache
	}
	d.initCache.Do(func() { d.defaultCache = NewMemoryCache() })
	return d.defaultCache
}

func (d *DBIP) logger() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.Default()
}
