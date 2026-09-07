// SPDX-License-Identifier: AGPL-3.0-only

// Package webui contains the browser application and its static file handler.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
)

//go:embed assets
var embedded embed.FS

var assets, _ = fs.Sub(embedded, "assets")

// Handler serves an external public directory, or the embedded bundle when empty.
func Handler(directory string) http.Handler {
	files := assets
	if directory != "" {
		files = os.DirFS(directory)
	}
	handler := http.FileServerFS(files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method != "GET" && r.Method != "HEAD" {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", 405)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

// Export writes the complete bundle, including assets added by future UI builds.
func Export(directory string) error {
	return fs.WalkDir(assets, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(directory, filepath.FromSlash(path))
		if entry.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		data, err := fs.ReadFile(assets, path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0644)
	})
}
