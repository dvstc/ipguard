package sources

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

const maxResponseBytes = 512 << 20 // 512 MB

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds %d byte limit", limit)
	}
	return data, nil
}

// httpDoConditional performs a GET with conditional request headers when a
// cached entry exists. On 304 it returns (nil, cachedData, nil). On 200 it
// returns (resp, body, nil) — the caller owns post-processing and cache update.
func httpDoConditional(ctx context.Context, client *http.Client, url string, cache Cache, logger *slog.Logger) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}

	var cached *CacheEntry
	if cache != nil {
		cached, _ = cache.Get(url)
		if cached != nil {
			if cached.ETag != "" {
				req.Header.Set("If-None-Match", cached.ETag)
			}
			if cached.LastModified != "" {
				req.Header.Set("If-Modified-Since", cached.LastModified)
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}

	if resp.StatusCode == http.StatusNotModified {
		resp.Body.Close()
		if cached != nil {
			logger.Info("upstream unchanged (304), using cached data", "url", url)
			return nil, cached.Data, nil
		}
		return nil, nil, fmt.Errorf("HTTP 304 from %s but no cached data", url)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	body, err := readLimited(resp.Body, maxResponseBytes)
	resp.Body.Close()
	if err != nil {
		return nil, nil, err
	}

	logger.Debug("downloaded fresh data", "url", url, "bytes", len(body))
	return resp, body, nil
}

// HTTPGetCached fetches url and returns the response body. When cache is non-nil,
// conditional request headers are sent and the result is cached for future calls.
// Exported for use by the tgeo/fetch package; most callers should use the
// Source types directly.
func HTTPGetCached(ctx context.Context, client *http.Client, url string, cache Cache, logger *slog.Logger) ([]byte, error) {
	return httpGet(ctx, client, url, cache, logger)
}

func httpGet(ctx context.Context, client *http.Client, url string, cache Cache, logger *slog.Logger) ([]byte, error) {
	resp, data, err := httpDoConditional(ctx, client, url, cache, logger)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return data, nil
	}

	if cache != nil {
		_ = cache.Put(&CacheEntry{
			URL:          url,
			Data:         data,
			ETag:         resp.Header.Get("ETag"),
			LastModified: resp.Header.Get("Last-Modified"),
		})
	}
	return data, nil
}
