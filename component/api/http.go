// SPDX-License-Identifier: AGPL-3.0-only
package api

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/daeuniverse/dae/component/api/internal/webui"
)

type Certificates struct {
	Fingerprint string
	Handler     http.Handler
}

// Options captures one plane's configuration. Publish a new handler when
// configuration changes; stores continue to provide live runtime state.
type Options struct {
	Selectors     SelectorStore
	Devices       DeviceStore
	ResolveClient func(netip.Addr) ([6]byte, error)
	Certificates  *Certificates
	Token         string
}

type server struct{ options Options }

// NewHandler serves one plane's management API. The owner drains requests before
// closing that plane and publishing its replacement.
func NewHandler(options Options) http.Handler {
	s := &server{options: options}
	resolve := options.ResolveClient
	mux := http.NewServeMux()
	page := webui.Handler()
	for _, path := range []string{"/{$}", "/style.css", "/app.js"} {
		mux.Handle("GET "+path, page)
	}
	if options.Certificates != nil {
		certificates := options.Certificates.Handler
		for _, path := range []string{"/api/certificate", "/ca.pem", "/ca.cer", "/ca.mobileconfig"} {
			mux.Handle("GET "+path, certificates)
		}
	}
	mux.HandleFunc("GET /api/selectors", s.serveSelectors)
	mux.HandleFunc("PUT /api/selectors/{group}", s.serveSelector)
	mux.HandleFunc("DELETE /api/selectors/{group}", s.serveSelector)
	mux.HandleFunc("GET /api/device", func(w http.ResponseWriter, r *http.Request) { s.serveDevice(w, r, resolve) })
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		mux.HandleFunc(method+" /api/device/sets/{name}", func(w http.ResponseWriter, r *http.Request) { s.serveClientSet(w, r, resolve) })
		mux.HandleFunc(method+" /api/device/mitm", func(w http.ResponseWriter, r *http.Request) { s.serveMITM(w, r, resolve) })
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if !localIPHost(r) || !sameOrigin(r) {
				apiError(w, 403, "open the API directly using the router IP address and port; cross-origin access is not allowed")
				return
			}
			if r.URL.RawQuery != "" {
				apiError(w, 400, "API requests do not accept query parameters")
				return
			}
			if (r.Method == http.MethodPut || r.Method == http.MethodDelete) && r.Header.Get("X-Dae-API") != "1" {
				apiError(w, 403, "changes require X-Dae-API: 1")
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
