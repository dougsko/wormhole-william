package cmd

import (
	"errors"
	"path/filepath"
	"strings"
)

// safeBaseName normalizes a filename that arrived inside a transfer offer.
// Offered names are attacker-controlled input, so we always reduce them to
// their final path element; names that contain path separators, are absolute,
// or resolve to "." / ".." are rejected. The result is guaranteed to be a
// single relative path element safe to create inside a working directory.
func safeBaseName(name string) (string, error) {
	if name == "" {
		return "", errors.New("empty filename in offer")
	}
	// Normalize windows-style separators too: this runs wherever the CLI
	// is built, but offers may have been crafted on any OS.
	normalized := strings.ReplaceAll(name, "\\", "/")
	base := filepath.Base(normalized)
	if base == "." || base == ".." || base == "/" || base == "" {
		return "", errors.New("unsafe filename in offer")
	}
	return base, nil
}

// zipPathContained reports whether p (an absolute path) is inside dirName
// (also absolute). Unlike a bare strings.HasPrefix check this does not treat
// /tmp/out-evil as being inside /tmp/out.
func zipPathContained(dirName, p string) bool {
	rel, err := filepath.Rel(dirName, p)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
