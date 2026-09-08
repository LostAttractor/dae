// SPDX-License-Identifier: AGPL-3.0-only
package apiserver

import (
	"net/http"
	"net/netip"
	"strings"

	contract "github.com/daeuniverse/dae/api"
)

type Certificates struct {
	Identity contract.Certificate
	Handler  http.Handler
}

// ClientResolver receives the actual TCP endpoints, including IPv6 zones.
type ClientResolver func(source, destination netip.AddrPort) ([6]byte, error)

// Options captures one plane's configuration. Publish a new handler when
// configuration changes; stores continue to provide live runtime state.
type Options struct {
	Status        func() *contract.StatusSnapshot
	Selectors     SelectorStore
	Devices       DeviceStore
	ResolveClient ClientResolver
	Certificates  *Certificates
	Token         string
}

type handler struct{ options Options }

// NewHandler serves one plane's management API. The owner drains requests before
// closing that plane and publishing its replacement.
func NewHandler(options Options) http.Handler {
	s := &handler{options: options}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		if s.requireAdmin(w, r) && apiBody(w, r, nil) {
			writeAPI(w, options.Status())
		}
	})
	if options.Certificates != nil {
		certificates := options.Certificates.Handler
		mux.HandleFunc("GET /api/certificate", func(w http.ResponseWriter, r *http.Request) {
			if apiBody(w, r, nil) {
				writeAPI(w, options.Certificates.Identity)
			}
		})
		for _, path := range []string{"/ca.pem", "/ca.cer", "/ca.mobileconfig"} {
			mux.Handle("GET "+path, certificates)
		}
	}
	mux.HandleFunc("GET /api/selectors", s.serveSelectors)
	mux.HandleFunc("PUT /api/selectors/{group}", s.serveSelector)
	mux.HandleFunc("DELETE /api/selectors/{group}", s.serveSelector)
	mux.HandleFunc("GET /api/device", s.serveDevice)
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		mux.HandleFunc(method+" /api/device/sets/{name}", s.serveClientSet)
		mux.HandleFunc(method+" /api/device/mitm", s.serveMITM)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if (!localAPISocket(r) && !localIPHost(r)) || !sameOrigin(r) {
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
