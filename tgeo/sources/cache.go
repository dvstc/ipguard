package sources

import "sync"

// CacheEntry stores a fetched response alongside its HTTP freshness headers.
// Data holds the caller's final processed output (e.g. decompressed bytes),
// not necessarily the raw HTTP body.
type CacheEntry struct {
	URL          string
	Data         []byte
	ETag         string
	LastModified string
}

// Cache allows source fetchers to skip re-downloading unchanged upstream data
// by storing responses and their ETag/Last-Modified headers for conditional requests.
type Cache interface {
	Get(url string) (*CacheEntry, error)
	Put(entry *CacheEntry) error
}

// MemoryCache is a process-lifetime in-memory Cache.
type MemoryCache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
}

// NewMemoryCache returns a ready-to-use in-memory cache.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{entries: make(map[string]*CacheEntry)}
}

func (m *MemoryCache) Get(url string) (*CacheEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry, ok := m.entries[url]
	if !ok {
		return nil, nil
	}
	return entry, nil
}

func (m *MemoryCache) Put(entry *CacheEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[entry.URL] = entry
	return nil
}
