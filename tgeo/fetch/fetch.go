// Package fetch provides a single-call way to download a pre-compiled TGEO
// table from a remote URL. Use WithURL to specify the feed URL.
//
// Usage:
//
//	table, err := fetch.Table(ctx, fetch.WithURL("https://feed.example.com/latest.tgeo.gz"))
//	guard.SetGeoLookup(table)
package fetch

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/dvstc/ipguard/tgeo"
	"github.com/dvstc/ipguard/tgeo/sources"
)

// DefaultURL is a placeholder. Consumers should always provide their
// own feed URL via WithURL.
const DefaultURL = "https://your-r2-domain.example.com/latest.tgeo.gz"

// Option configures a call to Table.
type Option func(*options)

type options struct {
	url    string
	client *http.Client
	logger *slog.Logger
}

// WithURL overrides the default TGEO download URL.
func WithURL(url string) Option {
	return func(o *options) { o.url = url }
}

// WithClient sets the HTTP client used for the download.
func WithClient(c *http.Client) Option {
	return func(o *options) { o.client = c }
}

// WithLogger sets the logger for download status messages.
func WithLogger(l *slog.Logger) Option {
	return func(o *options) { o.logger = l }
}

var (
	defaultCache     sources.Cache
	defaultCacheOnce sync.Once
)

func getDefaultCache() sources.Cache {
	defaultCacheOnce.Do(func() { defaultCache = sources.NewMemoryCache() })
	return defaultCache
}

// Table downloads a pre-compiled TGEO gzip file, decompresses it, and returns
// a *tgeo.Table ready for lookups. Subsequent calls use HTTP conditional
// requests (ETag / If-Modified-Since) so the full payload is only downloaded
// when the upstream file has changed.
func Table(ctx context.Context, opts ...Option) (*tgeo.Table, error) {
	o := &options{
		url:    DefaultURL,
		client: &http.Client{},
		logger: slog.Default(),
	}
	for _, fn := range opts {
		fn(o)
	}

	cache := getDefaultCache()

	data, err := sources.HTTPGetCached(ctx, o.client, o.url, cache, o.logger)
	if err != nil {
		return nil, fmt.Errorf("fetch TGEO data: %w", err)
	}

	raw, err := tgeo.DecompressGzip(data)
	if err != nil {
		return nil, fmt.Errorf("decompress TGEO data: %w", err)
	}

	table, err := tgeo.LoadTableFromBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("load TGEO table: %w", err)
	}

	return table, nil
}
