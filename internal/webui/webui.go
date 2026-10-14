// SPDX-License-Identifier: AGPL-3.0-only

// Package webui serves built Web assets embedded in dae or supplied externally.
package webui

import (
	"embed"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
)

// Build assets with make web-assets from the repository root.
//
//go:embed all:assets
var embedded embed.FS

var assets, _ = fs.Sub(embedded, "assets")

// Handler serves an external public directory, or the embedded bundle when empty.
func Handler(directory string, testTargets ...netip.AddrPort) http.Handler {
	embeddedHandler := http.FileServerFS(assets)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		connect := "'self'"
		if local, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr); ok && len(testTargets) != 0 {
			targets := append([]netip.AddrPort{local.AddrPort()}, testTargets...)
			for _, target := range targets {
				ip, port := target.Addr().Unmap(), target.Port()
				address := netip.AddrPortFrom(ip, port).String()
				// Chromium rejects IPv6 literals in CSP host sources. Constrain
				// these to HTTPS + test port + path; the browser request helper
				// and challenge server additionally require an advertised endpoint.
				if ip.Is6() {
					address = "*:" + strconv.Itoa(int(port))
				}
				connect += " https://" + address + "/test/"
			}
		}
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src "+connect+"; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method != "GET" && r.Method != "HEAD" {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", 405)
			return
		}
		var files fs.FS = assets
		handler := embeddedHandler
		if directory != "" {
			// Reopen for each request so replacing the bundle directory takes
			// effect immediately. Root also confines sidecars and directory
			// listings, including symlink resolution during concurrent edits.
			root, err := os.OpenRoot(directory)
			if err != nil {
				http.Error(w, "Web assets unavailable", http.StatusServiceUnavailable)
				return
			}
			defer root.Close()
			files = root.FS()
			handler = http.FileServerFS(files)
		}
		if !serveAsset(files, w, r) {
			handler.ServeHTTP(w, r)
		}
	})
}
