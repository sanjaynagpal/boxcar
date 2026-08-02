// Package assets holds the static files embedded into the boxcar binary at
// compile time via go:embed. This filesystem is read-only and fixed at
// build time — injected, runtime-mutable data lives in package vault
// instead.
package assets

import (
	"embed"
	"io/fs"
)

//go:embed assets
var FS embed.FS

// List returns the path of every embedded file (not directories), in
// walk order.
func List() ([]string, error) {
	var out []string
	err := fs.WalkDir(FS, "assets", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
