// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/webui"
)

// APIHandler belongs to the current plane. The daemon drains HTTP requests
// before retiring it, then publishes the replacement on the same listener.
func (c *ControlPlane) APIHandler() http.Handler {
	return c.apiHandler(func(ip netip.Addr) ([6]byte, error) {
		return netutils.ResolveClientMAC(ip, c.lanInterface)
	})
}

func (c *ControlPlane) apiHandler(resolve func(netip.Addr) ([6]byte, error)) http.Handler {
	mux := http.NewServeMux()
	page := webui.Handler()
	for _, path := range []string{"/{$}", "/style.css", "/app.js"} {
		mux.Handle("GET "+path, page)
	}
	if c.surge != nil && c.surge.Authority() != nil {
		certificates := c.surge.Authority().Handler()
		for _, path := range []string{"/api/certificate", "/ca.pem", "/ca.cer", "/ca.mobileconfig"} {
			mux.Handle("GET "+path, certificates)
		}
	}
	mux.HandleFunc("GET /api/selectors", c.serveSelectors)
	mux.HandleFunc("PUT /api/selectors/{group}", c.serveSelector)
	mux.HandleFunc("DELETE /api/selectors/{group}", c.serveSelector)
	mux.HandleFunc("GET /api/device", func(w http.ResponseWriter, r *http.Request) { c.serveDevice(w, r, resolve) })
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		mux.HandleFunc(method+" /api/device/sets/{name}", func(w http.ResponseWriter, r *http.Request) { c.serveClientSet(w, r, resolve) })
		mux.HandleFunc(method+" /api/device/mitm", func(w http.ResponseWriter, r *http.Request) { c.serveMITM(w, r, resolve) })
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
