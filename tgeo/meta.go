package tgeo

// Meta is the canonical metadata type for TGEO data feeds.
// Both the producing service (API responses) and consuming clients
// (API requests) should use this type to avoid drift.
type Meta struct {
	Version     string   `json:"version"`
	PublishedAt string   `json:"published_at"`
	Checksum    string   `json:"checksum"`
	ChecksumRaw string   `json:"checksum_raw"`
	Size        int64    `json:"size"`
	DownloadURL string   `json:"download_url"`
	Sources     []string `json:"sources"`
	License     string   `json:"license"`
}
