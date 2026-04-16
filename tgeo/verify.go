package tgeo

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
)

// VerifyAndWrite validates a compressed TGEO payload against its expected
// checksum, decompresses it, and atomically writes the result to destPath.
//
// The checksum must be in the format "sha256:<hex>". The SHA-256 is computed
// over the compressed bytes (what was downloaded), not the decompressed content.
// The write is atomic: data is written to a temporary file then renamed.
func VerifyAndWrite(compressed []byte, expectedChecksum string, destPath string) error {
	hash := sha256.Sum256(compressed)
	got := fmt.Sprintf("sha256:%x", hash)
	if got != expectedChecksum {
		return fmt.Errorf("checksum mismatch: got %s, want %s", got, expectedChecksum)
	}

	raw, err := DecompressGzip(compressed)
	if err != nil {
		return fmt.Errorf("decompress: %w", err)
	}

	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	tmp := destPath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmp, destPath); err != nil {
		os.Remove(destPath)
		if rerr := os.Rename(tmp, destPath); rerr != nil {
			os.Remove(tmp)
			return fmt.Errorf("rename: %w", err)
		}
	}

	return nil
}
