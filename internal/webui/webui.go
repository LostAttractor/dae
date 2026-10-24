// SPDX-License-Identifier: AGPL-3.0-only

// Package webui serves built Web assets embedded in dae or supplied externally.
//go:build !no_webui

package webui

import (
	"embed"
	"encoding/json/v2"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/api"
)

// Build assets with make web-assets from the repository root.
//
//go:embed all:assets
var embedded embed.FS

var assets, _ = fs.Sub(embedded, "assets")

// Read from the same root as the bundle, never from daemon configuration.
func apiConnectSource(files fs.FS) (string, error) {
	file, err := files.Open("dae-web.json")
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return "", err
	}
	var metadata map[string]*string
	if len(data) > 4096 || json.Unmarshal(data, &metadata) != nil || len(metadata) != 1 {
		return "", fmt.Errorf("invalid Web metadata")
	}
	value := metadata["api_origin"]
	if value == nil {
		return "", fmt.Errorf("missing Web API origin")
	}
	origin := *value
	if origin == "" {
		return "", nil
	}
	canonical, err := api.NormalizeOrigin(origin)
	if err != nil || canonical != origin || !strings.HasPrefix(canonical, "https://") {
		return "", fmt.Errorf("invalid Web API origin")
	}
	if strings.HasPrefix(origin, "https://[") {
		port := "443"
		if _, p, err := net.SplitHostPort(strings.TrimPrefix(origin, "https://")); err == nil {
			port = p
		}
		return "https://*:" + port + "/api/", nil
	}
	return origin + "/api/", nil
}

// Handler serves an external public directory, or the embedded bundle when empty.
func Handler(directory string, testTargets ...netip.AddrPort) http.Handler {
	embeddedHandler := http.FileServerFS(assets)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
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
		apiSource, err := apiConnectSource(files)
		if err != nil {
			http.Error(w, "Web build metadata unavailable or invalid", http.StatusServiceUnavailable)
			return
		}
		connect := "'self'"
		if apiSource != "" {
			connect += " " + apiSource
		}
		if local, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr); ok {
			targets := append([]netip.AddrPort{local.AddrPort()}, testTargets...)
			for i, target := range targets {
				ip, port := target.Addr().Unmap(), target.Port()
				address := netip.AddrPortFrom(ip, port).String()
				// Chromium rejects IPv6 literals in CSP host sources. Constrain
				// these to HTTPS + test port + path; the browser request helper
				// and challenge server additionally require an advertised endpoint.
				if ip.Is6() {
					address = "*:" + strconv.Itoa(int(port))
				}
				path := "/test/"
				if i == 0 {
					path = "/api/"
				}
				connect += " https://" + address + path
			}
		}
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src "+connect+"; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		if !serveAsset(files, w, r) {
			handler.ServeHTTP(w, r)
		}
	})
}
